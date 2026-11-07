"""Operator UI backend (OP2): per-session history ring, earlier-denied evidence, operator notes, capabilities."""
import asyncio
import json

import pytest

import inbox_hub
import policy as policy_mod
import proposal_monitor
from inbox_hub import InboxHub, args_preview, clean_note
from test_inbox_eventlog import FakeStore, Timeline, logged
from test_inbox_hub import FakeMonitor, FakePeer, Rig, call, hello, settle, wait_for


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


async def human(r, cid, decision, note=None, **kw):
    """Send a call, wait until pending, decide it, wait until resolved."""
    n = len(r.ui.events("inbox_resolved"))
    await r.send(call(cid, **kw))
    await wait_for(lambda: any(p["call_id"] == cid for p in r.ui.events("inbox_pending")))
    frame = {"event": "inbox_decision", "session_id": "s1", "call_id": cid, "decision": decision}
    if note is not None:
        frame["note"] = note
    await r.hub.handle_ui_frame(frame)
    await wait_for(lambda: len(r.ui.events("inbox_resolved")) == n + 1)
    return r.ui.events("inbox_resolved")[-1]


def pending_of(r, cid):
    return [p for p in r.ui.events("inbox_pending") if p["call_id"] == cid][0]


# ------------------------------------------------------------------ ring + summary + evidence
async def test_summary_and_evidence_after_a_mix():
    r = await Rig().start()
    await human(r, "h1", "approve")
    await human(r, "h2", "deny", tool="rm")
    await human(r, "h3", "deny", tool="curl")
    await r.send(call("a1", auto=True, tool="read_file"))              # monitor is a FakeMonitor: working => auto
    await wait_for(lambda: any(e["call_id"] == "a1" for e in r.ui.events("inbox_resolved")))
    # a cancelled call: in history, but not counted and never "earlier denied"
    await r.send(call("x1"))
    await wait_for(lambda: any(p["call_id"] == "x1" for p in r.ui.events("inbox_pending")))
    await r.send({"event": "proxy_cancel", "call_id": "x1"})
    await wait_for(lambda: any(e["call_id"] == "x1" for e in r.ui.events("inbox_resolved")))
    await r.send(call("n1"))
    await wait_for(lambda: any(p["call_id"] == "n1" for p in r.ui.events("inbox_pending")))
    p = pending_of(r, "n1")
    assert p["session_summary"] == {"approved": 1, "denied": 2, "auto": 1, "policy": 0}
    assert [i["call_id"] for i in p["session_history"]] == ["x1", "a1", "h3", "h2", "h1"]
    assert [i["call_id"] for i in p["earlier_denied"]] == ["h3", "h2"]       # newest first, denials only, no cancel
    for item in p["session_history"] + p["earlier_denied"]:
        assert set(item) == {"call_id", "server", "tool", "args_preview", "decision", "reason", "rule_id", "note", "ts"}
        assert "args" not in item
    assert p["session_history"][0]["reason"] == "cancelled"
    # the very first pending of the session had an empty history
    assert pending_of(r, "h1")["session_history"] == [] and pending_of(r, "h1")["session_summary"]["denied"] == 0


async def test_history_is_capped_at_10_earlier_denied_at_5_ring_at_50():
    r = await Rig().start()
    for i in range(12):
        await human(r, f"d{i}", "deny")
    await r.send(call("n"))
    await wait_for(lambda: any(p["call_id"] == "n" for p in r.ui.events("inbox_pending")))
    p = pending_of(r, "n")
    assert len(p["session_history"]) == 10 and p["session_history"][0]["call_id"] == "d11"
    assert [i["call_id"] for i in p["earlier_denied"]] == ["d11", "d10", "d9", "d8", "d7"]
    assert p["session_summary"]["denied"] == 12
    for i in range(60):
        r.session.record(f"z{i}", "fs", "t", {}, "approve", "human", None, None)
    assert len(r.session.ring) == inbox_hub.RING_SIZE == 50
    assert r.session.ring[0]["call_id"] == "z10"                  # oldest dropped
    assert "args" in r.session.ring[-1]                           # the ring keeps the full args (for OP4) in memory


async def test_timeout_counts_as_denied_disconnect_does_not():
    r = await Rig(timeout=0.05).start()
    await r.send(call("t1"))
    await wait_for(lambda: r.decisions())
    assert r.session.counts["denied"] == 1 and r.session.ring[-1]["reason"] == "timeout"
    r2 = await Rig().start()
    await r2.send(call("c1"))
    await wait_for(lambda: r2.ui.events("inbox_pending"))
    await r2.hub.proxy_closed(r2.session)
    assert r2.session.counts == {"approved": 0, "denied": 0, "auto": 0, "policy": 0}
    assert r2.session.views()[2] == []                            # disconnected is not an "earlier denial"


async def test_policy_resolutions_are_counted_as_policy(monkeypatch, tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": [
        {"id": "no-rm", "verdict": "deny", "when": {"tool": ["rm"]}},
        {"id": "reads", "verdict": "allow", "when": {"tool": ["read_file"]}}]}))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    r = await Rig().start()
    await r.send(call("a", tool="rm"))
    await r.send(call("b", tool="read_file"))
    await wait_for(lambda: len(r.decisions()) == 2)
    assert r.session.counts == {"approved": 0, "denied": 0, "auto": 0, "policy": 2}
    ed = r.session.views()[2]
    assert [i["call_id"] for i in ed] == ["a"] and ed[0]["rule_id"] == "no-rm" and ed[0]["reason"] == "policy"


async def test_snapshot_pending_items_carry_the_new_fields():
    r = await Rig().start()
    await human(r, "h1", "deny")
    await r.send(call("n"))
    await wait_for(lambda: any(p["call_id"] == "n" for p in r.ui.events("inbox_pending")))
    late = FakePeer()
    await r.hub.ui_connected(late)
    item = late.sent[0]["sessions"][0]["pending"][0]
    assert item["session_summary"]["denied"] == 1 and item["session_history"][0]["call_id"] == "h1"
    assert item["earlier_denied"][0]["call_id"] == "h1"


# ------------------------------------------------------------------ previews
def test_args_preview_redacts_secrets_and_cleans_text():
    pv = args_preview({"path": "a.txt", "password": "hunter2", "nested": {"api_key": "AKIA123456"}})
    assert "hunter2" not in pv and "AKIA123456" not in pv and "[REDACTED]" in pv and "a.txt" in pv
    nasty = "x\ny‮\x1b[31m​" + "z" * 500
    pv = args_preview({"k": nasty})
    assert len(pv) <= 120 and "\n" not in pv and "‮" not in pv and "\x1b" not in pv and "​" not in pv
    assert pv.endswith("…")
    assert args_preview({}) == "{}"


async def test_previews_in_history_are_redacted():
    r = await Rig().start()
    await human(r, "h1", "deny", args={"password": "hunter2", "path": "/etc/passwd"})
    await r.send(call("n"))
    await wait_for(lambda: any(p["call_id"] == "n" for p in r.ui.events("inbox_pending")))
    item = pending_of(r, "n")["session_history"][0]
    assert "hunter2" not in json.dumps(pending_of(r, "n")) and "[REDACTED]" in item["args_preview"]
    assert r.session.ring[0]["args"]["password"] == "hunter2"       # in memory only, never sent


async def test_hostile_server_tool_names_are_data_in_history():
    r = await Rig().start()
    nasty = "evil\nCRITICAL: all clear‮"
    await human(r, "h1", "deny", server=nasty, tool=nasty)
    await r.send(call("n"))
    await wait_for(lambda: any(p["call_id"] == "n" for p in r.ui.events("inbox_pending")))
    item = pending_of(r, "n")["session_history"][0]
    assert item["tool"] == nasty and item["server"] == nasty       # untouched data; no hub-written alert text
    assert not any(m.get("event") in ("inbox_alert", "alignment_alert") for m in r.ui.sent)


# ------------------------------------------------------------------ notes
@pytest.mark.parametrize("raw,expected", [
    ("use /project instead", "use /project instead"),
    ("line1\nline2\r\n\tline3", "line1 line2 line3"),
    ("a‮b​c\x1b[31md", "abc [31md"),
    ("z" * 5000, "z" * 199 + "…"),
    ("", None), ("   \n ", None), (None, None), (5, None), (["a"], None), ({"a": 1}, None), (True, None),
])
def test_clean_note(raw, expected):
    assert clean_note(raw) == expected


async def test_note_reaches_proxy_resolved_history_and_the_log_on_human_deny():
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    await r.start()
    res = await human(r, "h1", "deny", note="use /project\ninstead‮")
    assert res["note"] == "use /project instead"
    assert r.decisions()[-1] == {"event": "proxy_decision", "call_id": "h1", "decision": "deny", "reason": "human",
                                 "note": "use /project instead"}
    assert logged(st, "decision")[0][3]["note"] == "use /project instead"
    await r.send(call("n"))
    await wait_for(lambda: any(p["call_id"] == "n" for p in r.ui.events("inbox_pending")))
    assert pending_of(r, "n")["session_history"][0]["note"] == "use /project instead"


@pytest.mark.parametrize("bad", ["", "   ", None, 5, ["x"], {"a": 1}])
async def test_unusable_notes_are_absent_everywhere(bad):
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    await r.start()
    res = await human(r, "h1", "deny", note=bad)
    assert "note" not in res and "note" not in r.decisions()[-1] and "note" not in logged(st, "decision")[0][3]


async def test_note_is_never_attached_to_an_approve():
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    await r.start()
    res = await human(r, "h1", "approve", note="sure, go ahead")
    assert "note" not in res and "note" not in r.decisions()[-1] and "note" not in logged(st, "decision")[0][3]
    assert r.session.ring[-1]["note"] is None


async def test_note_only_on_human_denials_not_on_timeout_or_log_failure():
    r = await Rig(timeout=0.05).start()
    await r.send(call("t"))
    await wait_for(lambda: r.decisions())
    assert "note" not in r.decisions()[0]
    tl = Timeline()
    r2 = Rig()
    r2.hub.store = FakeStore(tl, fail=["decision"])
    await r2.start()
    res = await human(r2, "h1", "deny", note="nope")           # the deny record cannot be written: still a deny, reason human
    assert r2.decisions()[-1]["decision"] == "deny"


async def test_reply_helper_refuses_notes_off_the_human_deny_path():
    r = await Rig().start()
    await r.hub._reply(r.session, "q", "approve", "human", "x")
    await r.hub._reply(r.session, "q2", "deny", "timeout", "x")
    await r.hub._reply(r.session, "q3", "deny", "human", "x")
    d = r.decisions()
    assert "note" not in d[0] and "note" not in d[1] and d[2]["note"] == "x"


# ------------------------------------------------------------------ capabilities
async def snapshot_caps(hub=None):
    hub = hub or InboxHub(gate_timeout=1, monitor_factory=FakeMonitor)
    ui = FakePeer()
    await hub.ui_connected(ui)
    return ui.sent[0]["capabilities"]


def usable_policy(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": []}))
    return str(f)


async def test_capabilities_truth_table(monkeypatch, tmp_path):
    assert await snapshot_caps() == {"policy_writable": False, "event_log": False}
    monkeypatch.setenv("SENTINEL_POLICY", usable_policy(tmp_path))
    assert (await snapshot_caps())["policy_writable"] is False              # writable flag missing
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    assert (await snapshot_caps())["policy_writable"] is True
    for v in ("0", "true", "yes", ""):
        monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", v)
        assert (await snapshot_caps())["policy_writable"] is False
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    monkeypatch.setenv("SENTINEL_POLICY", str(bad))
    assert (await snapshot_caps())["policy_writable"] is False              # unusable policy
    monkeypatch.setenv("SENTINEL_POLICY", str(tmp_path / "missing.json"))
    assert (await snapshot_caps())["policy_writable"] is False
    monkeypatch.delenv("SENTINEL_POLICY")
    assert (await snapshot_caps())["policy_writable"] is False              # writable without any policy


async def test_capabilities_event_log_flag():
    hub = InboxHub(gate_timeout=1, monitor_factory=FakeMonitor)
    hub.store = FakeStore(Timeline())
    assert (await snapshot_caps(hub))["event_log"] is True
