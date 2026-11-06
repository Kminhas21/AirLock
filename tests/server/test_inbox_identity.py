"""Identity, tenancy, RBAC, audit, per-tenant settings and escalation in the hub (ID5)."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import eventlog
import health_view
import identity as identity_mod
import inbox_hub
import live_drift
import main
import policy as policy_mod
import proposal_monitor
from identity import IdentityStore, hash_token
from inbox_hub import InboxHub
from test_inbox_eventlog import FakeStore, Timeline, logged
from test_inbox_hub import ALERT, FakeMonitor, FakePeer, call, hello, settle, wait_for

TOK = {"alice": "tok-alice-admin-0001", "bob": "tok-bob-approver-0002", "carol": "tok-carol-viewer-0003",
       "dave": "tok-dave-globex-admin-04", "ci": "tok-ci-bot-agent-000005", "gbot": "tok-globex-bot-agent-6"}
URL = "https://hooks.example.com/x"


def data(acme_policy=None, gate=None):
    acme = {"name": "Acme",
            "escalation": {"levels": [{"after_s": 60, "notify": ["oncall"]}, {"after_s": 180, "notify": ["oncall", "manager"]}]},
            "channels": {"oncall": {"type": "webhook", "url": URL, "format": "json"},
                         "manager": {"type": "webhook", "url": URL, "format": "slack", "include_args": True}}}
    if acme_policy:
        acme["policy_file"] = str(acme_policy)
    if gate:
        acme["gate_timeout_s"] = gate
    return {"version": 1,
            "tenants": {"acme": acme, "globex": {"name": "Globex"}},
            "operators": [
                {"id": "alice", "tenant": "acme", "role": "admin", "token_sha256": hash_token(TOK["alice"])},
                {"id": "bob", "tenant": "acme", "role": "approver", "servers": ["fs"], "token_sha256": hash_token(TOK["bob"])},
                {"id": "carol", "tenant": "acme", "role": "viewer", "token_sha256": hash_token(TOK["carol"])},
                {"id": "dave", "tenant": "globex", "role": "admin", "token_sha256": hash_token(TOK["dave"])}],
            "agents": [{"id": "ci-bot", "tenant": "acme", "servers": ["fs", "git"], "token_sha256": hash_token(TOK["ci"])},
                       {"id": "globex-bot", "tenant": "globex", "token_sha256": hash_token(TOK["gbot"])}]}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG", "SENTINEL_IDENTITY_FILE",
              "SENTINEL_WS_TOKEN", "SENTINEL_PUBLIC_URL"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    identity_mod._reset_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    identity_mod._reset_cache()
    proposal_monitor._reset_errors()


class FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.waiters = []

    def clock(self):
        return self.now

    async def sleep(self, d):
        fut = asyncio.get_running_loop().create_future()
        self.waiters.append((self.now + d, fut))
        await fut

    def advance(self, s):
        self.now += s
        for item in list(self.waiters):
            if item[0] <= self.now and not item[1].done():
                item[1].set_result(None)
                self.waiters.remove(item)


class FakeNotifier:
    def __init__(self, mode="ok"):
        self.mode, self.sent = mode, []

    async def send(self, channel, event):
        self.sent.append((channel, dict(event)))
        if self.mode == "hang":
            await asyncio.Event().wait()
        if self.mode == "raise":
            raise RuntimeError("webhook exploded https://secret.example/hook")
        return SimpleNamespace(ok=self.mode == "ok", status=200 if self.mode == "ok" else 500, reason="x", attempts=1)


class World:
    def __init__(self, store_data=None, store=None, timeout=5.0, notifier=None):
        self.ft = FakeTime()
        self.ident = IdentityStore(store_data or data())
        self.notifier = notifier or FakeNotifier()
        self.hub = InboxHub(gate_timeout=timeout, monitor_factory=FakeMonitor, identity=self.ident, notifier=self.notifier,
                            clock=self.ft.clock, sleep=self.ft.sleep, store=store)
        self.uis, self.sessions, self.proxies = {}, {}, {}

    def principal(self, kind, name):
        p = self.ident.authenticate(kind, TOK[name])
        assert p is not None
        return p

    async def ui(self, name):
        peer = FakePeer()
        self.uis[name] = peer
        await self.hub.ui_connected(peer, self.principal("operator", name))
        await settle()
        return peer

    async def agent(self, name, sid, servers=("fs",)):
        peer = FakePeer()
        self.proxies[sid] = peer
        s = await self.hub.proxy_hello(peer, hello(sid, servers=list(servers)), self.principal("agent", name))
        self.sessions[sid] = s
        await settle()
        return s

    async def send(self, sid, cid="c1", **kw):
        await self.hub.handle_proxy_frame(self.sessions[sid], call(cid, **kw))

    async def pending(self, name, cid):
        await wait_for(lambda: any(p["call_id"] == cid for p in self.uis[name].events("inbox_pending")))
        return [p for p in self.uis[name].events("inbox_pending") if p["call_id"] == cid][0]

    async def decide(self, name, sid, cid, decision="approve"):
        ui = next(u for u in self.hub._uis if u.peer is self.uis[name])
        await self.hub.handle_ui_frame({"event": "inbox_decision", "session_id": sid, "call_id": cid, "decision": decision}, ui)

    def ui_obj(self, name):
        return next(u for u in self.hub._uis if u.peer is self.uis[name])

    def decisions(self, sid):
        return self.proxies[sid].events("proxy_decision")


# ------------------------------------------------------------------ socket auth through the loops
class FakeWS:
    def __init__(self, frames=(), headers=None, host="10.0.0.9"):
        self.headers = headers or {}
        self.client = SimpleNamespace(host=host)
        self.q = [json.dumps(f) if not isinstance(f, str) else f for f in frames]
        self.sent, self.closed_code, self.closed = [], None, False

    async def receive(self):
        if self.q:
            return {"type": "websocket.receive", "text": self.q.pop(0)}
        await asyncio.sleep(3600)

    async def send_json(self, p):
        self.sent.append(p)

    async def close(self, code=1000):
        if not self.closed:
            self.closed, self.closed_code = True, code


async def run_ui(w, ws, extra=()):
    task = asyncio.create_task(inbox_hub.serve_ui(w.hub, ws))
    await wait_for(lambda: ws.closed or len(ws.sent) >= 2, tries=100)
    return task


@pytest.mark.parametrize("how", ["header", "frame"])
async def test_operator_auth_ok_via_header_or_first_frame_auth_ok_before_snapshot(how):
    w = World()
    ws = FakeWS(headers={"authorization": "Bearer " + TOK["alice"]}) if how == "header" else FakeWS(
        [{"event": "auth", "token": TOK["alice"]}])
    task = await run_ui(w, ws)
    assert ws.sent[0] == {"event": "auth_ok", "principal": {"id": "alice", "tenant": "acme", "role": "admin"}}
    snap = ws.sent[1]
    assert snap["event"] == "inbox_snapshot" and snap["principal"] == {"id": "alice", "tenant": "acme", "role": "admin"}
    assert snap["capabilities"] == {"policy_writable": False, "can_decide": True, "event_log": False}
    task.cancel()


@pytest.mark.parametrize("headers,frames", [
    ({"authorization": "Bearer wrong"}, []), ({"authorization": "Basic abc"}, [{"event": "nope"}]),
    ({}, [{"event": "auth", "token": "wrong"}]), ({}, [{"event": "auth", "token": 5}]), ({}, [{"event": "hello"}]),
    ({}, ["not json"]), ({"authorization": "Bearer " + TOK["ci"]}, [])])         # an AGENT token is not an operator credential
async def test_operator_auth_failures(headers, frames):
    w = World()
    ws = FakeWS(frames, headers)
    await run_ui(w, ws)
    assert ws.sent == [{"event": "auth_error", "reason": "unauthorized"}] and ws.closed_code == 1008
    assert not w.hub._uis


async def test_missing_credential_times_out_with_1008(monkeypatch):
    monkeypatch.setattr(inbox_hub, "AUTH_FRAME_TIMEOUT_S", 0.05)
    w = World()
    ws = FakeWS([])
    await run_ui(w, ws)
    assert ws.closed_code == 1008 and ws.sent == []


async def test_throttle_after_five_failures_and_audit_once_per_remote_window():
    tl = Timeline()
    st = FakeStore(tl)
    w = World(store=st)
    for i in range(5):
        ws = FakeWS([{"event": "auth", "token": f"bad-{i}"}], host="1.2.3.4")
        await run_ui(w, ws)
        assert ws.sent[0]["reason"] == "unauthorized"
    ws = FakeWS([{"event": "auth", "token": TOK["alice"]}], host="1.2.3.4")          # even the right token: throttled
    await run_ui(w, ws)
    assert ws.sent == [{"event": "auth_error", "reason": "throttled"}]
    ev = logged(st, "auth_failed")
    assert len(ev) == 1                                                     # once per (remote, 60 s)
    p = ev[0][3]
    assert set(p) == {"kind", "reason", "remote_hash"} and len(p["remote_hash"]) == 12 and p["kind"] == "operator"
    assert "1.2.3.4" not in json.dumps(p) and "bad-0" not in json.dumps(ev)
    w.ft.advance(61)                                                        # window over: audited again (other remote too)
    await w.hub.audit_auth_failure("operator", "unauthorized", "1.2.3.4")
    await w.hub.audit_auth_failure("agent", "unauthorized", "5.6.7.8")
    assert len(logged(st, "auth_failed")) == 3


async def run_proxy(w, ws):
    task = asyncio.create_task(inbox_hub.serve_proxy(w.hub, ws))
    await wait_for(lambda: ws.closed or len(ws.sent) >= 1, tries=100)
    return task


async def test_agent_auth_and_forbidden_server():
    w = World()
    ws = FakeWS([hello("a1", servers=["fs"])], {"authorization": "Bearer " + TOK["ci"]})
    task = await run_proxy(w, ws)
    assert ws.sent[0] == {"event": "hello_ack", "session_id": "a1"}
    assert w.hub.sessions["a1"].agent_id == "ci-bot" and w.hub.sessions["a1"].tenant == "acme"
    task.cancel()
    ws2 = FakeWS([hello("a2", servers=["fs", "shell"])], {"authorization": "Bearer " + TOK["ci"]})
    await run_proxy(w, ws2)
    assert ws2.sent == [{"event": "hello_reject", "reason": "forbidden_server"}] and "a2" not in w.hub.sessions
    ws3 = FakeWS([{"event": "auth", "token": TOK["alice"]}, hello("a3")])           # an operator token is not an agent credential
    await run_proxy(w, ws3)
    assert ws3.sent == [{"event": "hello_reject", "reason": "unauthorized"}] and ws3.closed_code == 1008
    ws4 = FakeWS([hello("a4")])                                                       # hello without credentials
    await run_proxy(w, ws4)
    assert ws4.sent == [{"event": "hello_reject", "reason": "unauthorized"}]


async def test_unusable_identity_file_refuses_everything(tmp_path, caplog):
    f = tmp_path / "id.json"
    f.write_text("{broken")
    hub = InboxHub()
    await hub.setup_identity_from_env({"SENTINEL_IDENTITY_FILE": str(f)})
    assert hub.identity_broken and hub.identity is None and hub.identity_mode
    assert sum(1 for r in caplog.records if r.levelname == "ERROR" and "SENTINEL_IDENTITY_FILE" in r.getMessage()) == 1
    w = SimpleNamespace(hub=hub)
    ws = FakeWS(headers={"authorization": "Bearer " + TOK["alice"]})
    await run_ui(w, ws)
    assert ws.sent == [{"event": "auth_error", "reason": "unauthorized"}] and ws.closed_code == 1008
    ws2 = FakeWS([hello("a")], {"authorization": "Bearer " + TOK["ci"]})
    await run_proxy(w, ws2)
    assert ws2.sent == [{"event": "hello_reject", "reason": "unauthorized"}] and ws2.closed_code == 1008


# ------------------------------------------------------------------ tenancy
async def test_two_tenants_see_only_their_own_everything():
    w = World()
    await w.ui("alice")
    await w.ui("dave")
    await w.agent("ci", "acme-s")
    await w.agent("gbot", "globex-s")
    w.hub._monitor_factory = lambda: FakeMonitor([ALERT])
    await w.send("acme-s", "a1")
    await w.send("globex-s", "g1")
    pa, pg = await w.pending("alice", "a1"), await w.pending("dave", "g1")
    assert pa["tenant"] == "acme" and pg["tenant"] == "globex"
    assert not any(e.get("session_id") == "globex-s" for e in w.uis["alice"].sent)
    assert not any(e.get("session_id") == "acme-s" for e in w.uis["dave"].sent)
    # sessions open/closed events, resolved, result stay inside the tenant
    await w.decide("alice", "acme-s", "a1", "approve")
    await wait_for(lambda: w.uis["alice"].events("inbox_resolved"))
    await w.hub.handle_proxy_frame(w.sessions["acme-s"], {"event": "proxy_result", "call_id": "a1", "status": "ok", "summary": "x"})
    await settle()
    assert w.uis["alice"].events("inbox_result") and not w.uis["dave"].events("inbox_result")
    assert not w.uis["dave"].events("inbox_resolved")
    # a late snapshot for each tenant only has its own sessions and pending call
    late_a, late_d = FakePeer(), FakePeer()
    await w.hub.ui_connected(late_a, w.principal("operator", "alice"))
    await w.hub.ui_connected(late_d, w.principal("operator", "dave"))
    assert [s["session_id"] for s in late_a.sent[0]["sessions"]] == ["acme-s"]
    assert [s["session_id"] for s in late_d.sent[0]["sessions"]] == ["globex-s"]
    assert [p["call_id"] for p in late_d.sent[0]["sessions"][0]["pending"]] == ["g1"]
    assert late_d.sent[0]["principal"]["tenant"] == "globex"


async def test_forged_decision_for_another_tenants_call_is_ignored_silently():
    w = World()
    await w.ui("alice")
    await w.ui("dave")
    await w.agent("ci", "acme-s")
    await w.send("acme-s", "a1")
    await w.pending("alice", "a1")
    before = list(w.uis["dave"].sent)
    await w.decide("dave", "acme-s", "a1", "approve")                       # dave (globex admin) forges acme's call
    await settle(40)
    assert w.decisions("acme-s") == [] and w.hub.pending_count() == 1
    assert w.uis["dave"].sent == before                                      # not even an error frame: no information leak
    await w.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "acme-s", "call_id": "a1", "verdict": "deny",
                                 "scope": "tool", "confirm": True}, w.ui_obj("dave"))
    await settle(40)
    assert not any(e.get("reason") not in (None, "not_writable", "unknown_call") for e in w.uis["dave"].events("inbox_rule_result"))
    assert not w.uis["alice"].events("inbox_rule_result")                    # nothing leaks to the other tenant either


async def test_recent_history_is_filtered_by_tenant_with_a_real_store(tmp_path):
    st = eventlog.EventStore(tmp_path / "e.db")
    st.open()
    w = World(store=st)
    await w.ui("alice")
    await w.agent("ci", "acme-s")
    await w.agent("gbot", "globex-s")
    await w.ui("dave")
    await w.send("acme-s", "a1")
    await w.send("globex-s", "g1")
    await w.pending("alice", "a1")
    await w.pending("dave", "g1")
    await w.decide("alice", "acme-s", "a1", "approve")
    await w.decide("dave", "globex-s", "g1", "deny")
    await wait_for(lambda: w.uis["alice"].events("inbox_resolved") and w.uis["dave"].events("inbox_resolved"))
    la, ld = FakePeer(), FakePeer()
    await w.hub.ui_connected(la, w.principal("operator", "alice"))
    await w.hub.ui_connected(ld, w.principal("operator", "dave"))
    assert [r["call_id"] for r in la.sent[0]["recent"]] == ["a1"]
    assert [r["call_id"] for r in ld.sent[0]["recent"]] == ["g1"]
    assert st.recent_resolved(50, "nobody") == [] and len(st.recent_resolved(50)) == 2
    st.close()


# ------------------------------------------------------------------ RBAC
async def test_role_matrix_for_decisions():
    w = World()
    for n in ("alice", "bob", "carol"):
        await w.ui(n)
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("carol", "c1")
    await w.decide("carol", "s", "c1", "approve")                           # viewer: forbidden, to that connection only
    await settle()
    assert w.uis["carol"].events("inbox_forbidden") == [{"event": "inbox_forbidden", "action": "decide", "reason": "role"}]
    assert not w.uis["alice"].events("inbox_forbidden") and not w.uis["bob"].events("inbox_forbidden")
    assert w.decisions("s") == [] and w.hub.pending_count() == 1
    await w.decide("bob", "s", "c1", "approve")                             # approver on server 'fs': ok
    await wait_for(lambda: w.decisions("s"))
    assert w.decisions("s")[0]["decision"] == "approve"
    res = [e for e in w.uis["carol"].events("inbox_resolved")][0]
    assert res["operator"] == "bob"                                         # echoed to the whole tenant, viewers included


async def test_server_allowlist_blocks_a_decision_outside_it():
    w = World()
    await w.ui("bob")
    await w.ui("alice")
    await w.agent("ci", "s", servers=("fs", "git"))
    await w.send("s", "c1", server="git")
    await w.pending("bob", "c1")
    await w.decide("bob", "s", "c1", "approve")
    await settle()
    assert w.uis["bob"].events("inbox_forbidden") == [{"event": "inbox_forbidden", "action": "decide", "reason": "server"}]
    assert w.decisions("s") == []
    await w.decide("alice", "s", "c1", "deny")                              # admin without allowlist may
    await wait_for(lambda: w.decisions("s"))
    assert w.decisions("s")[0]["decision"] == "deny"


@pytest.fixture
def writable(monkeypatch, tmp_path):
    f = tmp_path / "acme-policy.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": []}))
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    return f


async def test_role_matrix_for_rules_and_capabilities(writable):
    w = World(store_data=data(acme_policy=writable))
    for n in ("alice", "bob", "carol"):
        await w.ui(n)
    caps = {n: w.uis[n].sent[0]["capabilities"] for n in ("alice", "bob", "carol")}
    assert caps["alice"] == {"policy_writable": True, "can_decide": True, "event_log": False}
    assert caps["bob"] == {"policy_writable": False, "can_decide": True, "event_log": False}
    assert caps["carol"] == {"policy_writable": False, "can_decide": False, "event_log": False}
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("alice", "c1")
    req = {"event": "inbox_rule_request", "session_id": "s", "call_id": "c1", "verdict": "deny", "scope": "tool", "confirm": True}
    for n in ("bob", "carol"):
        await w.hub.handle_ui_frame(dict(req), w.ui_obj(n))
        await settle()
        assert w.uis[n].events("inbox_forbidden") == [{"event": "inbox_forbidden", "action": "rules", "reason": "role"}]
    assert json.loads(writable.read_text())["rules"] == []
    await w.hub.handle_ui_frame(dict(req), w.ui_obj("alice"))
    await wait_for(lambda: w.uis["alice"].events("inbox_rule_result"))
    assert w.uis["alice"].events("inbox_rule_result")[0]["ok"] is True
    assert len(json.loads(writable.read_text())["rules"]) == 1               # wrote THE TENANT's policy file
    assert w.uis["bob"].events("inbox_rule_result")[0]["ok"] is True          # the result is shown to the tenant's UIs


async def test_rule_request_on_a_server_outside_the_admins_allowlist(writable):
    d = data(acme_policy=writable)
    d["operators"][0]["servers"] = ["fs"]
    w = World(store_data=d)
    await w.ui("alice")
    await w.agent("ci", "s", servers=("fs", "git"))
    await w.send("s", "c1", server="git")
    await w.pending("alice", "c1")
    await w.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "s", "call_id": "c1", "verdict": "deny",
                                 "scope": "tool", "confirm": True}, w.ui_obj("alice"))
    await settle()
    assert w.uis["alice"].events("inbox_forbidden") == [{"event": "inbox_forbidden", "action": "rules", "reason": "server"}]
    assert json.loads(writable.read_text())["rules"] == []


# ------------------------------------------------------------------ audit + per-tenant settings
async def test_audit_fields_in_events_and_log_payloads():
    tl = Timeline()
    st = FakeStore(tl)
    w = World(store=st)
    await w.ui("alice")
    await w.agent("ci", "s")
    assert logged(st, "proxy_hello")[0][3]["agent_id"] == "ci-bot" and logged(st, "proxy_hello")[0][3]["tenant"] == "acme"
    await w.send("s", "c1")
    p = await w.pending("alice", "c1")
    assert (p["agent_id"], p["tenant"], p["escalation_level"], p["age_s"]) == ("ci-bot", "acme", 0, 0)
    w.ft.advance(7)
    late = FakePeer()
    await w.hub.ui_connected(late, w.principal("operator", "alice"))
    assert late.sent[0]["sessions"][0]["pending"][0]["age_s"] == 7
    await w.decide("alice", "s", "c1", "approve")
    await wait_for(lambda: w.uis["alice"].events("inbox_resolved"))
    d = logged(st, "decision")[0][3]
    assert d["operator"] == "alice" and d["tenant"] == "acme" and d["actor"] == "human"
    assert w.uis["alice"].events("inbox_resolved")[0]["operator"] == "alice"
    # non-human resolutions carry operator null
    await w.send("s", "c2", tool="x")
    await w.pending("alice", "c2")
    await w.hub.handle_proxy_frame(w.sessions["s"], {"event": "proxy_cancel", "call_id": "c2"})
    await wait_for(lambda: len(w.uis["alice"].events("inbox_resolved")) == 2)
    assert w.uis["alice"].events("inbox_resolved")[1]["operator"] is None
    assert logged(st, "decision")[1][3]["operator"] is None and logged(st, "decision")[1][3]["tenant"] == "acme"


async def test_per_tenant_gate_timeout():
    w = World(store_data=data(gate=1), timeout=30.0)
    await w.ui("alice")
    await w.ui("dave")
    await w.agent("ci", "a")
    await w.agent("gbot", "g")
    await w.send("a", "c1")
    p = await w.pending("alice", "c1")
    assert p["deadline_s"] == 1.0                                            # the tenant's, not the hub's 30 s
    await wait_for(lambda: w.decisions("a"), tries=400)
    assert w.decisions("a")[0]["reason"] == "timeout"
    await w.send("g", "c1")
    assert (await w.pending("dave", "c1"))["deadline_s"] == 30.0              # the other tenant keeps the hub default


async def test_per_tenant_policy_file(tmp_path):
    f = tmp_path / "acme.json"
    f.write_text(json.dumps({"version": 1, "default": "deny", "rules": []}))
    w = World(store_data=data(acme_policy=f))
    await w.ui("dave")
    await w.agent("ci", "a")
    await w.agent("gbot", "g")
    await w.send("a", "c1")
    await wait_for(lambda: w.decisions("a"))
    assert w.decisions("a")[0] == {"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "policy"}
    await w.send("g", "c1")
    await w.pending("dave", "c1")                                            # globex has no policy file and no SENTINEL_POLICY: legacy ask


# ------------------------------------------------------------------ escalation
async def test_levels_fire_once_each_in_order_with_the_documented_event():
    tl = Timeline()
    st = FakeStore(tl)
    w = World(store=st)
    await w.ui("alice")
    await w.ui("dave")
    await w.agent("ci", "s")
    await w.send("s", "c1", args={"path": "/x", "password": "hunter2"})
    await w.pending("alice", "c1")
    await settle()
    assert w.notifier.sent == []
    w.ft.advance(61)
    await wait_for(lambda: len(w.notifier.sent) == 1)
    ch, ev = w.notifier.sent[0]
    assert ch.name == "oncall" and ev == {"tenant": "acme", "agent_id": "ci-bot", "server": "fs", "tool": "write_file",
                                           "call_id": "c1", "age_s": 61, "level": 1, "link": "/#inbox"}
    assert w.uis["alice"].events("inbox_escalated") == [{"event": "inbox_escalated", "session_id": "s", "call_id": "c1",
                                                         "level": 1, "after_s": 60}]
    assert not w.uis["dave"].events("inbox_escalated")                       # other tenants never see it
    w.ft.advance(10)
    await settle(40)
    assert len(w.notifier.sent) == 1                                          # level 1 does not fire twice
    late = FakePeer()
    await w.hub.ui_connected(late, w.principal("operator", "alice"))
    assert late.sent[0]["sessions"][0]["pending"][0]["escalation_level"] == 1
    w.ft.advance(200)
    await wait_for(lambda: len(w.notifier.sent) == 3)                         # level 2: oncall + manager 
    names = [c.name for c, _ in w.notifier.sent]
    assert names == ["oncall", "oncall", "manager"]
    mgr = w.notifier.sent[2][1]
    assert mgr["level"] == 2 and "hunter2" not in json.dumps(mgr)
    assert "[REDACTED]" in mgr["args_preview"]                                # include_args channel: redacted preview only
    assert "args_preview" not in w.notifier.sent[0][1] and "args_preview" not in w.notifier.sent[1][1]
    await wait_for(lambda: len(logged(st, "notification")) == 3)
    assert logged(st, "notification")[0][3] == {"channel": "oncall", "level": 1, "ok": True, "status": 200}


async def test_skipped_levels_fire_together_when_the_clock_jumps(monkeypatch):
    monkeypatch.setenv("SENTINEL_PUBLIC_URL", "https://sentinel.example")
    w = World()
    await w.ui("alice")
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("alice", "c1")
    await settle()
    w.ft.advance(500)
    await wait_for(lambda: len(w.notifier.sent) == 3)
    assert [e["level"] for e in w.uis["alice"].events("inbox_escalated")] == [1, 2]
    assert [ev["level"] for _, ev in w.notifier.sent] == [1, 2, 2]
    assert w.notifier.sent[0][1]["link"] == "https://sentinel.example/#inbox"


def esc_tasks():
    return [t for t in asyncio.all_tasks() if getattr(t.get_coro(), "__name__", "") == "_escalate"]


async def test_escalation_is_cancelled_when_the_call_is_resolved():
    w = World()
    await w.ui("alice")
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("alice", "c1")
    await settle()
    assert len(esc_tasks()) == 1
    await w.decide("alice", "s", "c1", "deny")
    await wait_for(lambda: w.uis["alice"].events("inbox_resolved"))
    await settle(20)
    assert esc_tasks() == []
    w.ft.advance(1000)
    await settle(40)
    assert w.notifier.sent == [] and not w.uis["alice"].events("inbox_escalated")
    # cancel and disconnect clean up too
    await w.send("s", "c2")
    await w.pending("alice", "c2")
    await w.hub.handle_proxy_frame(w.sessions["s"], {"event": "proxy_cancel", "call_id": "c2"})
    await wait_for(lambda: len(w.uis["alice"].events("inbox_resolved")) == 2)
    await w.send("s", "c3")
    await w.pending("alice", "c3")
    await w.hub.proxy_closed(w.sessions["s"])
    await settle(20)
    assert esc_tasks() == []


@pytest.mark.parametrize("mode", ["fail", "raise", "hang"])
async def test_notifier_failure_or_hang_never_blocks_decisions(monkeypatch, mode):
    monkeypatch.setattr(inbox_hub, "NOTIFY_TIMEOUT_S", 0.05)
    tl = Timeline()
    st = FakeStore(tl)
    w = World(store=st, notifier=FakeNotifier(mode))
    await w.ui("alice")
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("alice", "c1")
    await settle()
    w.ft.advance(61)
    await wait_for(lambda: w.notifier.sent)
    await w.decide("alice", "s", "c1", "approve")                            # decisions work while the notifier is broken
    await wait_for(lambda: w.decisions("s"))
    assert w.decisions("s")[0]["decision"] == "approve"
    await wait_for(lambda: logged(st, "notification"), tries=400)
    assert logged(st, "notification")[0][3]["ok"] is False
    assert "secret.example" not in json.dumps(logged(st, "notification"))     # no exception text in the log


async def test_other_sessions_are_not_blocked_by_a_hanging_notifier(monkeypatch):
    w = World(notifier=FakeNotifier("hang"))
    await w.ui("alice")
    await w.agent("ci", "s1")
    await w.send("s1", "c1")
    await w.pending("alice", "c1")
    await settle()
    w.ft.advance(61)
    await wait_for(lambda: w.notifier.sent)
    await w.send("s1", "c2", tool="read_file")                                # another call in the same session still flows
    await w.pending("alice", "c2")


# ------------------------------------------------------------------ health
def test_identity_health_views():
    store = IdentityStore(data())
    pub = health_view.identity_view(store, False)
    det = health_view.identity_view(store, True)
    assert pub == {"legacy": False}
    assert det == {"tenants": 2, "operators": 4, "agents": 2, "digest": store.digest(), "legacy": False}
    blob = json.dumps([pub, det])
    assert all(hash_token(t) not in blob and t not in blob for t in TOK.values())
    assert health_view.identity_view(IdentityStore.legacy("legacy-token-123456"), False) == {"legacy": True}


# ------------------------------------------------------------------ end to end through the app
@pytest.fixture
def app_client(monkeypatch, tmp_path):
    f = tmp_path / "identity.json"
    f.write_text(json.dumps(data()))
    monkeypatch.setenv("SENTINEL_IDENTITY_FILE", str(f))
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=30))
    with TestClient(main.app) as c:
        yield c
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()


def hdr(name):
    return {"authorization": "Bearer " + TOK[name]}


def test_app_full_flow_with_tenants_and_first_frame_auth(app_client):
    c = app_client
    with c.websocket_connect("/inbox/ws") as ui:
        ui.send_json({"event": "auth", "token": TOK["alice"]})
        assert ui.receive_json() == {"event": "auth_ok", "principal": {"id": "alice", "tenant": "acme", "role": "admin"}}
        snap = ui.receive_json()
        assert snap["event"] == "inbox_snapshot" and snap["principal"]["tenant"] == "acme"
        with c.websocket_connect("/proxy/ws", headers=hdr("ci")) as proxy:
            proxy.send_json(hello("p1"))
            assert proxy.receive_json() == {"event": "hello_ack", "session_id": "p1"}
            assert ui.receive_json()["event"] == "inbox_session"
            proxy.send_json(call("c1"))
            pend = ui.receive_json()
            assert pend["event"] == "inbox_pending" and pend["agent_id"] == "ci-bot" and pend["tenant"] == "acme"
            ui.send_json({"event": "inbox_decision", "session_id": "p1", "call_id": "c1", "decision": "approve"})
            assert proxy.receive_json()["decision"] == "approve"
            assert ui.receive_json()["operator"] == "alice"


def test_app_refuses_query_token_in_identity_mode(app_client, monkeypatch):
    monkeypatch.setattr(inbox_hub, "AUTH_FRAME_TIMEOUT_S", 0.2)
    for path in ("/inbox/ws?token=" + TOK["alice"], "/proxy/ws?token=" + TOK["ci"]):
        with pytest.raises(WebSocketDisconnect) as ei:
            with app_client.websocket_connect(path) as ws:
                ws.receive_json()
        assert ei.value.code == 1008


def test_app_origin_check_still_applies(app_client):
    with pytest.raises(WebSocketDisconnect) as ei:
        with app_client.websocket_connect("/inbox/ws", headers={**hdr("alice"), "origin": "http://evil.example"}):
            pass
    assert ei.value.code == 1008
    with app_client.websocket_connect("/inbox/ws", headers={**hdr("alice"), "origin": "http://localhost:5173"}) as ui:
        assert ui.receive_json()["event"] == "auth_ok"


def test_app_wrong_token_and_viewer_over_the_wire(app_client):
    with app_client.websocket_connect("/inbox/ws", headers={"authorization": "Bearer nope"}) as ui:
        assert ui.receive_json() == {"event": "auth_error", "reason": "unauthorized"}
        with pytest.raises(WebSocketDisconnect) as ei:
            ui.receive_json()
        assert ei.value.code == 1008
    with app_client.websocket_connect("/inbox/ws", headers=hdr("carol")) as ui:
        assert ui.receive_json()["principal"]["role"] == "viewer"
        assert ui.receive_json()["capabilities"]["can_decide"] is False
        ui.send_json({"event": "inbox_decision", "session_id": "x", "call_id": "y", "decision": "approve"})
        assert ui.receive_json() == {"event": "inbox_forbidden", "action": "decide", "reason": "role"}


def test_app_health_identity_views(app_client):
    pub = app_client.get("/health").json()["identity"]
    assert pub == {"legacy": False}
    det = app_client.get("/health", params={"token": "x"}).json()["identity"]
    assert det == {"legacy": False}                                           # detail needs SENTINEL_WS_TOKEN / opt-in


def test_app_health_detail_with_opt_in(app_client, monkeypatch):
    monkeypatch.setenv("SENTINEL_HEALTH_DETAIL", "1")
    det = app_client.get("/health").json()["identity"]
    assert det["tenants"] == 2 and det["operators"] == 4 and det["agents"] == 2 and det["legacy"] is False
    assert not any(hash_token(t) in json.dumps(det) for t in TOK.values())


def test_app_unusable_identity_file_refuses_every_connection(monkeypatch, tmp_path):
    f = tmp_path / "identity.json"
    f.write_text("{nope")
    monkeypatch.setenv("SENTINEL_IDENTITY_FILE", str(f))
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=30))
    with TestClient(main.app) as c:
        with c.websocket_connect("/inbox/ws", headers=hdr("alice")) as ui:
            assert ui.receive_json() == {"event": "auth_error", "reason": "unauthorized"}
        with c.websocket_connect("/proxy/ws", headers=hdr("ci")) as proxy:
            assert proxy.receive_json() == {"event": "hello_reject", "reason": "unauthorized"}
        h = c.get("/health").json()["identity"]
        assert h["usable"] is False


def test_legacy_mode_is_unchanged_when_no_identity_file(monkeypatch):
    monkeypatch.setenv("SENTINEL_WS_TOKEN", "legacy-token")
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=30))
    with TestClient(main.app) as c:
        assert "identity" not in c.get("/health").json()
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/inbox/ws"):
                pass
        with c.websocket_connect("/inbox/ws?token=legacy-token") as ui:
            snap = ui.receive_json()
            assert snap["event"] == "inbox_snapshot" and "principal" not in snap
            assert snap["capabilities"] == {"policy_writable": False, "event_log": False}
