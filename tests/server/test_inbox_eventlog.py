"""Durable event log in the InboxHub (EL3): docs/plans/EVENT-LOG.md "Hub integration"."""
import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from starlette.testclient import TestClient

import eventlog
import health_view
import inbox_hub
import live_drift
import main
import policy as policy_mod
import proposal_monitor
from inbox_hub import InboxHub
from test_inbox_hub import ALERT, FakeMonitor, FakePeer, Rig, call, hello, settle, wait_for

TOKEN = "t0ken"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG", "SENTINEL_LOG_KEY", "SENTINEL_LOG_ANCHOR"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


class Timeline(list):
    pass


class TLPeer(FakePeer):
    def __init__(self, name, tl):
        super().__init__()
        self.name, self.tl = name, tl

    async def send_json(self, payload):
        await super().send_json(payload)
        self.tl.append(("send", self.name, payload.get("event"), payload.get("decision"), payload.get("reason")))


class FakeStore:
    def __init__(self, tl, fail=(), dup=(), recent=None):
        self.tl, self.fail, self.dup, self.recent = tl, set(fail), set(dup), recent or []
        self.events = []
        self.attempts = []

    def append(self, kind, *, session_id=None, call_id=None, payload=None):
        self.attempts.append((kind, call_id, payload))
        if kind in self.fail:
            raise eventlog.EventLogError("disk on fire /secret/path")
        if kind in self.dup:
            raise eventlog.DuplicateEvent("dup")
        self.tl.append(("log", kind, (payload or {}).get("decision"), (payload or {}).get("reason")))
        self.events.append((kind, session_id, call_id, payload))
        return SimpleNamespace(seq=len(self.events))

    def recent_resolved(self, n=50):
        return self.recent[:n]

    def close(self):
        pass


def logged(store, kind):
    return [e for e in store.events if e[0] == kind]


def make(tl, store=None, monitor=None, timeout=5.0):
    r = Rig(monitor, timeout)
    r.proxy, r.ui = TLPeer("proxy", tl), TLPeer("ui", tl)
    r.hub.store = store
    return r


def idx(tl, pred):
    return next(i for i, e in enumerate(tl) if pred(e))


async def test_hello_is_logged_before_the_ack():
    tl = Timeline()
    st = FakeStore(tl)
    r = make(tl, st)
    await r.start()
    assert idx(tl, lambda e: e[:2] == ("log", "proxy_hello")) < idx(tl, lambda e: e[:3] == ("send", "proxy", "hello_ack"))
    p = logged(st, "proxy_hello")[0][3]
    assert p["session_id"] == "s1" and p["servers"] == ["fs"] and p["auto_approve"] == ["fs:read"]
    assert set(p) >= {"monitor_mode", "policy_digest", "registry_digest", "frozen_model_sha256"}


async def test_hello_append_failure_rejects_log_unavailable():
    tl = Timeline()
    r = make(tl, FakeStore(tl, fail=["proxy_hello"]))
    await r.hub.ui_connected(r.ui)
    assert await r.hub.proxy_hello(r.proxy, hello()) is None
    assert r.proxy.sent == [{"event": "hello_reject", "reason": "log_unavailable"}] and r.proxy.closed
    assert not r.hub.sessions
    assert "disk on fire" not in json.dumps(r.proxy.sent + r.ui.sent)      # no exception text to peers


async def test_held_call_write_ahead_order_human_approve():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    i_prop = idx(tl, lambda e: e[:2] == ("log", "call_proposed"))
    i_pend = idx(tl, lambda e: e[:3] == ("send", "ui", "inbox_pending"))
    i_dec = idx(tl, lambda e: e[:2] == ("log", "decision"))
    i_pd = idx(tl, lambda e: e[:3] == ("send", "proxy", "proxy_decision"))
    i_res = idx(tl, lambda e: e[:3] == ("send", "ui", "inbox_resolved"))
    assert i_prop < i_pend < i_dec < i_pd and i_dec < i_res
    prop = logged(st, "call_proposed")[0][3]
    assert prop == {"server": "fs", "tool": "write_file", "args": {"p": 1}, "auto": False, "alerts": [], "policy": None}
    assert logged(st, "decision")[0][3] == {"decision": "approve", "reason": "human", "actor": "human", "rule_id": None,
                                            "policy_digest": None}


async def test_alerts_are_recorded_in_the_documented_shape():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st, FakeMonitor([ALERT])).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert logged(st, "call_proposed")[0][3]["alerts"] == [
        {"severity": "critical", "trigger": "denied_effect_match", "score": 0.9, "threshold": 0.5, "message": "m"}]


async def test_auto_approve_write_ahead_order_and_actor():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(call(auto=True, tool="read_file"))
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    i_prop = idx(tl, lambda e: e[:2] == ("log", "call_proposed"))
    i_dec = idx(tl, lambda e: e[:2] == ("log", "decision"))
    i_pd = idx(tl, lambda e: e[:3] == ("send", "proxy", "proxy_decision"))
    i_res = idx(tl, lambda e: e[:3] == ("send", "ui", "inbox_resolved"))
    assert i_prop < i_dec < i_pd and i_dec < i_res
    assert logged(st, "decision")[0][3]["actor"] == "auto" and logged(st, "decision")[0][3]["reason"] == "auto"


async def test_call_proposed_failure_denies_log_unavailable_and_broadcasts_nothing():
    tl = Timeline()
    st = FakeStore(tl, fail=["call_proposed"])
    r = await make(tl, st).start()
    await r.send(call())
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "log_unavailable"}]
    await settle()
    assert not r.ui.events("inbox_pending") and not r.ui.events("inbox_resolved") and r.hub.pending_count() == 0
    assert not logged(st, "decision")
    # auto calls too: never approved without the proposal on disk
    await r.send(call("c2", auto=True, tool="read_file"))
    await wait_for(lambda: len(r.decisions()) == 2)
    assert r.decisions()[1]["decision"] == "deny"


async def test_decision_failure_replaces_approve_with_deny_and_tries_a_second_append():
    tl = Timeline()
    st = FakeStore(tl, fail=["decision"])
    r = await make(tl, st).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0] == {"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "log_unavailable"}
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    assert r.ui.events("inbox_resolved")[0]["decision"] == "deny" and r.ui.events("inbox_resolved")[0]["reason"] == "log_unavailable"
    decs = [a for a in st.attempts if a[0] == "decision"]
    assert len(decs) == 2 and decs[0][2]["decision"] == "approve" and decs[1][2]["decision"] == "deny"
    assert r.monitor.decisions[-1][2] == "deny"


async def test_decision_failure_for_auto_approve_is_denied_too():
    tl = Timeline()
    r = await make(tl, FakeStore(tl, fail=["decision"])).start()
    await r.send(call(auto=True, tool="read_file"))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "deny" and r.decisions()[0]["reason"] == "log_unavailable"


async def test_duplicate_decision_event_means_already_resolved_ignore():
    tl = Timeline()
    r = await make(tl, FakeStore(tl, dup=["decision"])).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await settle(50)
    await asyncio.sleep(0.05)
    assert r.decisions() == [] and not r.ui.events("inbox_resolved") and r.hub.pending_count() == 0


async def test_duplicate_call_proposed_event_is_ignored():
    tl = Timeline()
    r = await make(tl, FakeStore(tl, dup=["call_proposed"])).start()
    await r.send(call())
    await settle(50)
    await asyncio.sleep(0.05)
    assert r.decisions() == [] and not r.ui.events("inbox_pending") and r.hub.pending_count() == 0


async def test_cancel_is_logged_exactly_once_as_a_system_decision():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.send({"event": "proxy_cancel", "call_id": "c1", "reason": "timeout"})
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    await r.send({"event": "proxy_cancel", "call_id": "c1"})
    await r.decide("c1", "approve")
    await settle(30)
    decs = logged(st, "decision")
    assert len(decs) == 1 and decs[0][3]["reason"] == "timeout" and decs[0][3]["actor"] == "system"
    assert decs[0][3]["decision"] == "deny" and r.decisions() == []
    assert idx(tl, lambda e: e[:2] == ("log", "decision")) < idx(tl, lambda e: e[:3] == ("send", "ui", "inbox_resolved") and e[0] == "send" and e[2] == "inbox_resolved" )


async def test_cancel_during_monitor_after_nothing_logged_before_proposal():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    r.session.cancelled_early.add("c9")
    await r.send(call("c9"))
    await settle(40)
    assert not logged(st, "call_proposed") and not logged(st, "decision")


async def test_timeout_and_disconnect_are_system_decisions_human_is_human():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st, timeout=0.05).start()
    await r.send(call("t1"))
    await wait_for(lambda: r.decisions())
    assert logged(st, "decision")[0][3]["reason"] == "timeout" and logged(st, "decision")[0][3]["actor"] == "system"
    tl2 = Timeline()
    st2 = FakeStore(tl2)
    r2 = await make(tl2, st2).start()
    await r2.send(call("d1"))
    await wait_for(lambda: r2.ui.events("inbox_pending"))
    await r2.hub.proxy_closed(r2.session)
    d = logged(st2, "decision")[0][3]
    assert d["reason"] == "disconnected" and d["actor"] == "system" and d["decision"] == "deny"
    assert logged(st2, "proxy_close")[0][3] == {"reason": "disconnected"}


async def test_call_result_logged_and_failure_never_raises():
    tl = Timeline()
    st = FakeStore(tl, fail=["call_result"])
    r = await make(tl, st).start()
    await r.send(call())
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert await r.send({"event": "proxy_result", "call_id": "c1", "status": "ok", "summary": "done"}) is True
    assert r.ui.events("inbox_result")                       # still forwarded
    st.fail.clear()
    await r.send({"event": "proxy_result", "call_id": "c1", "status": "error", "summary": "x"})
    assert logged(st, "call_result")[0][3] == {"status": "error", "summary": "x"}


async def test_policy_and_log_together(monkeypatch, tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": [
        {"id": "no-rm", "verdict": "deny", "when": {"tool": ["delete_file"]}},
        {"id": "reads", "verdict": "allow", "when": {"tool": ["read_file"]}}]}))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    pol = policy_mod.load_policy_file(str(f))[0]
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(call("a", tool="delete_file"))
    await r.send(call("b", tool="read_file"))
    await wait_for(lambda: len(r.decisions()) == 2)
    props = {e[2]: e[3] for e in logged(st, "call_proposed")}
    assert props["a"]["policy"] == {"verdict": "deny", "rule_id": "no-rm", "digest": pol.digest()}
    assert props["b"]["policy"] == {"verdict": "allow", "rule_id": "reads", "digest": pol.digest()}
    decs = {e[2]: e[3] for e in logged(st, "decision")}
    assert decs["a"] == {"decision": "deny", "reason": "policy", "actor": "policy", "rule_id": "no-rm", "policy_digest": pol.digest()}
    assert decs["b"]["actor"] == "policy" and decs["b"]["decision"] == "approve"
    assert logged(st, "proxy_hello")[0][3]["policy_digest"] == pol.digest()
    for call_id in ("a", "b"):
        assert idx(tl, lambda e: e[:2] == ("log", "call_proposed")) < idx(tl, lambda e: e[:3] == ("send", "proxy", "proxy_decision"))


async def test_snapshot_carries_recent_history():
    tl = Timeline()
    rec = [{"session_id": "s0", "call_id": "x", "server": "fs", "tool": "t", "decision": "deny", "reason": "human",
            "rule_id": None, "ts": 1.0}]
    r = make(tl, FakeStore(tl, recent=rec))
    late = FakePeer()
    await r.hub.ui_connected(late)
    assert late.sent[0]["recent"] == rec
    plain = Rig()
    ui = FakePeer()
    await plain.hub.ui_connected(ui)
    assert ui.sent[0]["recent"] == []


async def test_unset_env_is_legacy_no_store_no_log_info():
    hub = InboxHub()
    await hub.open_log_from_env({})
    assert hub.store is None and not hub.log_unusable and hub.event_log_info() is None


async def test_unusable_store_refuses_every_session_and_logs_error_once(tmp_path, caplog):
    hub = InboxHub(gate_timeout=1, monitor_factory=FakeMonitor)
    await hub.open_log_from_env({"SENTINEL_EVENT_LOG": str(tmp_path)})          # a directory: cannot be opened
    assert hub.log_unusable and hub.store is None
    assert sum(1 for r in caplog.records if r.levelname == "ERROR" and "SENTINEL_EVENT_LOG" in r.getMessage()) == 1
    for sid in ("a", "b"):
        peer = FakePeer()
        assert await hub.proxy_hello(peer, hello(sid)) is None
        assert peer.sent == [{"event": "hello_reject", "reason": "log_unavailable"}]
    assert hub.event_log_info()["ok"] is False


async def test_bad_key_makes_the_store_unusable(tmp_path):
    hub = InboxHub()
    await hub.open_log_from_env({"SENTINEL_EVENT_LOG": str(tmp_path / "e.db"), "SENTINEL_LOG_KEY": "short"})
    assert hub.log_unusable


async def test_tampered_chain_refuses_to_start(tmp_path):
    db = tmp_path / "e.db"
    hub = InboxHub()
    env = {"SENTINEL_EVENT_LOG": str(db), "SENTINEL_LOG_KEY": "k" * 20}
    await hub.open_log_from_env(env)
    assert hub.store is not None
    await hub.close_log()
    import sqlite3
    c = sqlite3.connect(db)
    c.execute("UPDATE events SET payload = '{\"keyed\": false}' WHERE seq = 1")
    c.commit()
    c.close()
    hub2 = InboxHub()
    await hub2.open_log_from_env(env)
    assert hub2.log_unusable


def test_event_log_view():
    info = {"path": "/x/e.db", "events": 7, "keyed": True, "ok": True}
    assert health_view.event_log_view(info, False) == {"events": 7, "keyed": True, "ok": True}
    assert health_view.event_log_view(info, True) == {"path": "/x/e.db", "events": 7, "keyed": True, "ok": True}


# ------------------------------------------------------------------ end to end with the REAL store
KEY = "k" * 24
P = "/proxy/ws?token=" + TOKEN
U = "/inbox/ws?token=" + TOKEN
HELLO = {"event": "proxy_hello", "session_id": "e2e", "servers": ["fs"], "auto_approve": []}


@pytest.fixture
def real(monkeypatch, tmp_path):
    db = tmp_path / "events.db"
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    monkeypatch.setenv("SENTINEL_WS_TOKEN", TOKEN)
    monkeypatch.setenv("SENTINEL_EVENT_LOG", str(db))
    monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=30))
    holder = SimpleNamespace(db=db)
    with TestClient(main.app) as c:
        holder.client = c
        yield holder
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()


def _open(ui, proxy):
    assert ui.receive_json()["event"] == "inbox_snapshot"
    proxy.send_json(HELLO)
    assert proxy.receive_json()["event"] == "hello_ack"
    assert ui.receive_json()["state"] == "open"


def test_real_store_approve_and_deny_flows_then_verify_ok(real):
    c = real.client
    with c.websocket_connect(U) as ui, c.websocket_connect(P) as proxy:
        _open(ui, proxy)
        proxy.send_json(call("a1"))
        assert ui.receive_json()["event"] == "inbox_pending"
        ui.send_json({"event": "inbox_decision", "session_id": "e2e", "call_id": "a1", "decision": "approve"})
        assert proxy.receive_json()["decision"] == "approve"
        assert ui.receive_json()["event"] == "inbox_resolved"
        proxy.send_json({"event": "proxy_result", "call_id": "a1", "status": "ok", "summary": "wrote it"})
        assert ui.receive_json()["event"] == "inbox_result"
        proxy.send_json(call("d1", args={"path": "x", "password": "hunter2"}))
        assert ui.receive_json()["event"] == "inbox_pending"
        ui.send_json({"event": "inbox_decision", "session_id": "e2e", "call_id": "d1", "decision": "deny"})
        assert proxy.receive_json()["decision"] == "deny"
        assert ui.receive_json()["event"] == "inbox_resolved"
        # /health while running: public and detail views, no verify()
        pub = c.get("/health").json()["event_log"]
        det = c.get("/health", params={"token": TOKEN}).json()["event_log"]
        assert pub == {"events": pub["events"], "keyed": True, "ok": True} and pub["events"] == 7
        assert det["path"] == str(real.db) and det["events"] == pub["events"]
    # a late UI sees the history in its snapshot
    with c.websocket_connect(U) as ui2:
        snap = ui2.receive_json()
        assert [r["call_id"] for r in snap["recent"]] == ["d1", "a1"] and snap["recent"][0]["decision"] == "deny"


def test_real_store_chain_is_valid_after_shutdown(real):
    c = real.client
    with c.websocket_connect(U) as ui, c.websocket_connect(P) as proxy:
        _open(ui, proxy)
        proxy.send_json(call("a1"))
        ui.receive_json()
        ui.send_json({"event": "inbox_decision", "session_id": "e2e", "call_id": "a1", "decision": "approve"})
        proxy.receive_json()
    c.__exit__(None, None, None)           # run the lifespan shutdown (closes the store with a final checkpoint)
    rep = eventlog.verify_file(real.db, key=KEY.encode())
    assert rep.ok and rep.keyed
    store = eventlog.EventStore.open_readonly(real.db, key=KEY.encode())
    kinds = [e.kind for e in store.events()]
    for k in ("log_open", "proxy_hello", "call_proposed", "decision", "proxy_close"):
        assert k in kinds, kinds
    assert kinds.index("proxy_hello") < kinds.index("call_proposed") < kinds.index("decision")
    dec = [e for e in store.events() if e.kind == "decision"][0]
    assert dec.payload["reason"] == "human" and dec.payload["actor"] == "human"
    store.close()
