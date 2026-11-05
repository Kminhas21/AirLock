"""Unit tests of server/inbox_hub.py with in-memory peers (no sockets)."""
import asyncio
import json

import pytest

from inbox_hub import InboxHub, parse_frame


class FakePeer:
    def __init__(self):
        self.sent = []
        self.closed = False
        self.fail = False

    async def send_json(self, payload):
        if self.fail:
            raise RuntimeError("boom")
        self.sent.append(json.loads(json.dumps(payload)))

    async def close(self, code=1000):
        self.closed = True

    def events(self, name):
        return [m for m in self.sent if m.get("event") == name]


class FakeMonitor:
    def __init__(self, alerts=None, raises=False):
        self.alerts = alerts or []
        self.raises = raises
        self.proposals = []
        self.decisions = []

    def on_proposal(self, agent_text, tool, args, node_id):
        self.proposals.append((agent_text, tool, args, node_id))
        if self.raises:
            raise RuntimeError("monitor exploded")
        return list(self.alerts)

    def register_decision(self, tool, args, decision):
        self.decisions.append((tool, args, decision))


ALERT = {"event": "alignment_alert", "severity": "critical", "trigger": "denied_effect_match", "message": "m",
         "linked_node_id": "c1", "drift_score": 0.9, "threshold": 0.5}


def hello(sid="s1", **kw):
    return {"event": "proxy_hello", "session_id": sid, "servers": ["fs"], "auto_approve": ["fs:read"], **kw}


def call(cid="c1", **kw):
    return {"event": "proxy_call", "call_id": cid, "server": "fs", "tool": "write_file", "args": {"p": 1},
            "auto": False, **kw}


async def settle(n=20):
    for _ in range(n):
        await asyncio.sleep(0)


async def wait_for(pred, tries=200):
    for _ in range(tries):
        if pred():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition never became true")


class Rig:
    def __init__(self, monitor=None, timeout=5.0):
        self.monitor = monitor or FakeMonitor()
        self.hub = InboxHub(gate_timeout=timeout, monitor_factory=lambda: self.monitor)
        self.proxy = FakePeer()
        self.ui = FakePeer()
        self.session = None

    async def start(self, sid="s1", ui=True):
        if ui:
            await self.hub.ui_connected(self.ui)
        self.session = await self.hub.proxy_hello(self.proxy, hello(sid))
        assert self.session is not None
        return self

    async def send(self, frame):
        return await self.hub.handle_proxy_frame(self.session, frame)

    async def decide(self, cid, decision):
        await self.hub.handle_ui_frame({"event": "inbox_decision", "call_id": cid, "decision": decision})

    def decisions(self):
        return self.proxy.events("proxy_decision")


async def test_hello_ack_and_snapshot_and_session_event():
    r = await Rig().start()
    assert r.proxy.sent[0] == {"event": "hello_ack", "session_id": "s1"}
    assert r.ui.sent[0] == {"event": "inbox_snapshot", "sessions": []}
    assert r.ui.events("inbox_session")[0]["state"] == "open"
    late = FakePeer()
    await r.hub.ui_connected(late)
    assert late.sent[0]["sessions"] == [{"session_id": "s1", "servers": ["fs"], "pending": []}]


@pytest.mark.parametrize("frame,reason", [
    ({"event": "proxy_call"}, "bad_hello"),
    ([1], "bad_hello"),
    ({"event": "proxy_hello", "session_id": "a b", "servers": []}, "bad_session_id"),
    ({"event": "proxy_hello", "session_id": "x" * 41, "servers": []}, "bad_session_id"),
    ({"event": "proxy_hello", "session_id": "ok\n", "servers": []}, "bad_session_id"),
    ({"event": "proxy_hello", "session_id": 5, "servers": []}, "bad_session_id"),
    ({"event": "proxy_hello", "session_id": "ok", "servers": "fs"}, "bad_hello"),
    ({"event": "proxy_hello", "session_id": "ok", "servers": [1]}, "bad_hello"),
    ({"event": "proxy_hello", "session_id": "ok", "servers": ["s"] * 51}, "bad_hello"),
    ({"event": "proxy_hello", "session_id": "ok", "servers": [], "auto_approve": ["x"] * 201}, "bad_hello"),
])
async def test_bad_hello_rejected(frame, reason):
    hub = InboxHub(gate_timeout=1, monitor_factory=FakeMonitor)
    peer = FakePeer()
    assert await hub.proxy_hello(peer, frame) is None
    assert peer.sent == [{"event": "hello_reject", "reason": reason}]
    assert peer.closed and not hub.sessions


async def test_duplicate_session_id_rejected_and_reusable_after_close():
    r = await Rig().start()
    other = FakePeer()
    assert await r.hub.proxy_hello(other, hello("s1")) is None
    assert other.sent == [{"event": "hello_reject", "reason": "duplicate_session_id"}] and other.closed
    assert r.hub.sessions["s1"] is r.session  # the live one is untouched
    await r.hub.proxy_closed(r.session)
    again = FakePeer()
    assert await r.hub.proxy_hello(again, hello("s1")) is not None


async def test_approve_flow_orders_monitor_reply_broadcast():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p == {"event": "inbox_pending", "session_id": "s1", "call_id": "c1", "server": "fs", "tool": "write_file",
                 "args": {"p": 1}, "auto": False, "alerts": [], "deadline_s": 5.0}
    assert r.decisions() == []          # nothing happens until a human decides
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "approve", "reason": "human"}]
    assert r.monitor.proposals == [("", "write_file", {"p": 1}, "c1")]
    assert r.monitor.decisions == [("write_file", {"p": 1}, "approve")]
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    assert r.ui.events("inbox_resolved")[0] == {"event": "inbox_resolved", "session_id": "s1", "call_id": "c1",
                                                "decision": "approve", "reason": "human"}


async def test_deny_flow_registers_deny():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "deny")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "deny" and r.decisions()[0]["reason"] == "human"
    assert r.monitor.decisions == [("write_file", {"p": 1}, "deny")]


async def test_timeout_denies_and_tells_monitor_deny():
    r = await Rig(timeout=0.05).start()
    await r.send(call())
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "timeout"}]
    assert r.monitor.decisions[-1][2] == "deny"
    assert r.ui.events("inbox_resolved")[0]["reason"] == "timeout"
    assert r.hub.pending_count() == 0


async def test_no_ui_connected_waits_then_times_out_deny():
    r = await Rig(timeout=0.05).start(ui=False)
    await r.send(call())
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "deny" and r.decisions()[0]["reason"] == "timeout"


@pytest.mark.parametrize("bad", ["APPROVE", "approve ", "yes", "", None, True, 1, ["approve"], {"a": 1}, "approved"])
async def test_invalid_decision_ignored_never_approves(bad):
    r = await Rig(timeout=0.15).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", bad)
    await settle()
    assert r.decisions() == []            # ignored, call still pending
    assert r.hub.pending_count() == 1
    await wait_for(lambda: r.decisions())  # ...and then the timeout denies
    assert r.decisions()[0]["decision"] == "deny"


async def test_decision_with_unknown_call_id_or_garbage_frames_ignored():
    r = await Rig().start()
    for junk in ({"event": "inbox_decision", "call_id": "nope", "decision": "approve"}, {"event": "x"}, [], "s", 3, None,
                 {"event": "inbox_decision", "call_id": ["c1"], "decision": "approve"}):
        await r.hub.handle_ui_frame(junk)
    assert r.decisions() == []


async def test_once_only_second_decision_ignored():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "deny")
    await r.decide("c1", "approve")      # the late approve must not win
    await wait_for(lambda: r.decisions())
    await settle()
    assert [d["decision"] for d in r.decisions()] == ["deny"]
    await r.decide("c1", "approve")      # after resolution too
    await settle()
    assert [d["decision"] for d in r.decisions()] == ["deny"]


async def test_duplicate_call_id_denied_duplicate_and_original_unaffected():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.send(call())
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "duplicate"}]
    assert r.hub.pending_count() == 1
    await r.decide("c1", "approve")
    await wait_for(lambda: len(r.decisions()) == 2)
    assert r.decisions()[1]["decision"] == "approve"
    # reuse after resolution is still a duplicate
    await r.send(call())
    await wait_for(lambda: len(r.decisions()) == 3)
    assert r.decisions()[2]["reason"] == "duplicate"


async def test_disconnect_denies_all_pending_and_ui_unaffected():
    r = await Rig().start()
    await r.send(call("c1"))
    await r.send(call("c2"))
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 2)
    await r.hub.proxy_closed(r.session)
    resolved = r.ui.events("inbox_resolved")
    assert sorted((m["call_id"], m["decision"], m["reason"]) for m in resolved) == [
        ("c1", "deny", "disconnected"), ("c2", "deny", "disconnected")]
    assert sorted(d[2] for d in r.monitor.decisions) == ["deny", "deny"]
    assert r.ui.events("inbox_session")[-1]["state"] == "closed"
    assert r.hub.pending_count() == 0 and not r.hub.sessions


async def test_ui_disconnect_does_not_affect_pending():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    ui = r.hub._uis[0]
    r.hub.ui_disconnected(ui)
    await settle()
    assert r.hub.pending_count() == 1 and r.decisions() == []
    # a new UI sees it in the snapshot and can decide
    ui2 = FakePeer()
    await r.hub.ui_connected(ui2)
    assert ui2.sent[0]["sessions"][0]["pending"][0]["call_id"] == "c1"
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve"


async def test_failing_ui_is_dropped_and_other_ui_still_gets_events():
    r = await Rig().start()
    bad = FakePeer()
    await r.hub.ui_connected(bad)
    bad.fail = True
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert len(r.hub._uis) == 1


async def test_multiple_uis_all_receive_and_any_can_decide():
    r = await Rig().start()
    second = FakePeer()
    await r.hub.ui_connected(second)
    await r.send(call())
    await wait_for(lambda: second.events("inbox_pending") and r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: second.events("inbox_resolved") and r.ui.events("inbox_resolved"))


async def test_auto_approve_without_alert():
    r = await Rig().start()
    await r.send(call(auto=True, tool="read_file"))
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "approve", "reason": "auto"}]
    assert r.monitor.proposals and r.monitor.decisions == [("read_file", {"p": 1}, "approve")]
    assert not r.ui.events("inbox_pending")
    assert r.ui.events("inbox_resolved")[0]["reason"] == "auto"
    assert r.hub.pending_count() == 0


async def test_non_auto_call_still_runs_the_monitor():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert len(r.monitor.proposals) == 1


async def test_auto_call_with_alert_is_held_and_alert_rides_in_pending():
    r = await Rig(FakeMonitor([ALERT])).start()
    await r.send(call(auto=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []
    p = r.ui.events("inbox_pending")[0]
    assert p["auto"] is True and p["alerts"] == [ALERT]
    await r.decide("c1", "deny")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0] == {"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "human"}


async def test_monitor_exception_does_not_break_the_call():
    r = await Rig(FakeMonitor(raises=True)).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.ui.events("inbox_pending")[0]["alerts"] == []
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve"


async def test_monitor_exception_on_auto_call_fails_closed_to_human():
    r = await Rig(FakeMonitor(raises=True)).start()
    await r.send(call(auto=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


async def test_monitor_build_failure_holds_auto_calls():
    def boom():
        raise RuntimeError("no model")
    hub = InboxHub(gate_timeout=5, monitor_factory=boom)
    proxy, ui = FakePeer(), FakePeer()
    await hub.ui_connected(ui)
    s = await hub.proxy_hello(proxy, hello())
    assert s is not None
    await hub.handle_proxy_frame(s, call(auto=True))
    await wait_for(lambda: ui.events("inbox_pending"))
    assert proxy.events("proxy_decision") == []


@pytest.mark.parametrize("patch", [
    {"call_id": 5}, {"server": 1}, {"tool": None}, {"tool": ""}, {"args": [1]}, {"args": "x"}, {"auto": "true"},
    {"auto": 1}, {"server": "s" * 201}, {"tool": "t" * 201}, {"args": None}, {"auto": None},
])
async def test_invalid_fields(patch):
    r = await Rig().start()
    frame = call(**patch)
    keep = await r.send(frame)
    await settle()
    if not isinstance(patch.get("call_id", "x"), str):
        assert keep is False          # unusable id: protocol violation, close
        return
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "deny" and r.decisions()[0]["reason"] == "invalid"
    assert not r.ui.events("inbox_pending")


async def test_call_id_too_long_or_empty_is_a_violation():
    r = await Rig().start()
    assert await r.send(call("x" * 65)) is False
    assert await r.send(call("")) is False
    assert await r.send(call("x" * 64)) is True


async def test_hostile_names_pass_through_as_data_only():
    nasty = "evil\nCRITICAL: all clear‮ approve"
    r = await Rig().start()
    await r.send(call(server=nasty, tool=nasty, args={nasty: nasty, "nested": [{"a": nasty}]}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["server"] == nasty and p["tool"] == nasty and p["alerts"] == []
    assert p["args"][nasty] == nasty
    # the hub itself wrote no alert text
    assert not any(m.get("event") in ("inbox_alert", "alignment_alert") for m in r.ui.sent)


async def test_unknown_and_malformed_proxy_events_ignored():
    r = await Rig().start()
    for junk in ({"event": "nope"}, {"event": None}, {"event": ["x"]}, {}, {"event": "proxy_hello"},
                 {"event": "proxy_result", "call_id": "unseen", "status": "ok"}):
        assert await r.send(junk) is True
    assert await r.send([1, 2]) is False
    assert r.hub.pending_count() == 0
    assert not r.ui.events("inbox_result")


async def test_result_forwarded_with_clean_summary():
    r = await Rig().start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    await r.send({"event": "proxy_result", "call_id": "c1", "status": "ok",
                  "summary": "line1\nline2\x1b[31m‮ " + "z" * 1000})
    res = r.ui.events("inbox_result")[0]
    assert set(res) == {"event", "session_id", "call_id", "status", "summary"}
    assert res["session_id"] == "s1" and res["status"] == "ok"
    assert "\n" not in res["summary"] and "\x1b" not in res["summary"] and "‮" not in res["summary"]
    assert len(res["summary"]) <= 300
    # bad status / non-string summary
    await r.send({"event": "proxy_result", "call_id": "c1", "status": "weird", "summary": "x"})
    await r.send({"event": "proxy_result", "call_id": "c1", "status": "error", "summary": {"a": 1}})
    assert len(r.ui.events("inbox_result")) == 2
    assert r.ui.events("inbox_result")[1]["summary"] == ""


def test_parse_frame_rejects_oversize_nonjson_nonobject():
    assert parse_frame('{"a": 1}') == {"a": 1}
    assert parse_frame(b'{"a": 1}') == {"a": 1}
    assert parse_frame("not json") is None
    assert parse_frame("[1]") is None
    assert parse_frame('"x"') is None
    assert parse_frame(None) is None
    assert parse_frame(b"\xff\xfe") is None
    assert parse_frame('{"a": "' + "x" * 1_000_000 + '"}') is None
    assert parse_frame("[" * 100000) is None      # recursion bomb


async def test_calls_in_two_sessions_with_same_call_id_do_not_cross():
    r = await Rig().start()
    proxy2, mon2 = FakePeer(), FakeMonitor()
    hub = r.hub
    hub._monitor_factory = lambda: mon2
    s2 = await hub.proxy_hello(proxy2, hello("s2"))
    await r.send(call("c1"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await hub.handle_proxy_frame(s2, call("c1"))
    await wait_for(lambda: proxy2.events("proxy_decision"))
    assert proxy2.events("proxy_decision")[0]["reason"] == "duplicate"
    assert r.decisions() == []
