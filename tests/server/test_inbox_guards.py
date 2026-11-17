"""Hub guards that decide whether a call is auto-allowed or held: they fail CLOSED (phase 1 of the "narrow write right" plan). Each one is a
branch that nothing exercised, and each guards the allow decision:

  * a policy that cannot even be resolved           -> the session is on a broken policy, every call is held   (inbox_hub ~635-637)
  * an unexpected exception while handling a call   -> the call is denied "invalid", nothing is left pending    (~758-761)
  * a verdict the engine should never return        -> ask, no rule id, no confine map                         (~817)
  * identity mode, a UI frame without a principal   -> ignored, nothing is decided                             (~1235-1236)
  * identity mode, authentication blows up          -> unauthorized, never an approval                          (~1299-1301)"""
import json
import logging
from types import SimpleNamespace

import pytest

import identity as identity_mod
import inbox_hub
import policy as policy_mod
import proposal_monitor
from inbox_hub import InboxHub
from policy import Decision as PolicyDecision
from test_inbox_hub import FakePeer, Rig, call, settle, wait_for
from test_inbox_identity import FakeWS, World, run_ui, TOK


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG", "SENTINEL_IDENTITY_FILE",
              "SENTINEL_WS_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    policy_mod._reset_policy_cache()
    identity_mod._reset_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    identity_mod._reset_cache()
    proposal_monitor._reset_errors()


def read(cid="c1", **kw):
    return call(cid, tool="read_text_file", args={"path": "/w/a.txt"}, confinable=True, **kw)


# --------------------------------------------------------------------------- policy resolution fails


async def test_a_policy_resolution_that_raises_is_a_broken_policy_and_every_call_is_held(monkeypatch, caplog):
    """Control first: with the starter resolved this very read is auto-allowed (no card)."""
    ok = await Rig().start()
    await ok.send(read())
    await wait_for(lambda: ok.decisions())
    assert ok.decisions()[0]["decision"] == "approve" and not ok.ui.events("inbox_pending")

    def boom(path=None):
        raise RuntimeError("policy resolution exploded")
    monkeypatch.setattr(inbox_hub, "_resolve_policy", boom)
    with caplog.at_level(logging.ERROR, logger="sentinel.inbox"):
        r = await Rig().start()
    assert r.session.policy_mode is True and r.session.policy is None and r.session.policy_registry is None
    await r.send(read("c1", auto=True))
    await r.send(call("c2", tool="get_current_time", args={"timezone": "UTC"}, auto=True))
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 2)
    assert r.decisions() == []                                               # nothing approved, however harmless it looks
    for p in r.ui.events("inbox_pending"):
        assert p["rule_id"] is None and p["policy_digest"] is None
    assert any("policy resolution failed" in rec.getMessage() for rec in caplog.records)
    await r.decide("c1", "approve")                                          # a human can still decide; the reason is the human's
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "human" and "confine" not in r.decisions()[0]


async def test_a_resolution_failure_in_one_session_does_not_break_the_next_one(monkeypatch):
    real = inbox_hub._resolve_policy
    calls = []

    def flaky(path=None):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("once")
        return real(path)
    monkeypatch.setattr(inbox_hub, "_resolve_policy", flaky)
    first = await Rig().start()
    second = await Rig().start()
    assert first.session.policy is None and second.session.policy is not None


# --------------------------------------------------------------------------- an unexpected exception while handling a call


async def test_an_unexpected_error_while_handling_a_call_denies_it_invalid_and_leaves_nothing_pending(monkeypatch, caplog):
    r = await Rig().start()

    async def boom(self, session, call_id, frame):
        raise RuntimeError("handler exploded")
    monkeypatch.setattr(InboxHub, "_run_call_inner", boom)
    with caplog.at_level(logging.ERROR):
        await r.send(read("c1"))
        await wait_for(lambda: r.decisions())
    assert [(d["call_id"], d["decision"], d["reason"]) for d in r.decisions()] == [("c1", "deny", "invalid")]
    assert "confine" not in r.decisions()[0] and "c1" not in r.session.pending and r.hub.pending_count() == 0
    assert not r.ui.events("inbox_pending")
    assert any("unexpected error handling call" in rec.getMessage() for rec in caplog.records)
    assert "c1" not in r.session.starting and "c1" not in r.session.cancelled_early


async def test_after_an_unexpected_error_the_session_keeps_working(monkeypatch):
    r = await Rig().start()
    real = InboxHub._run_call_inner
    n = []

    async def once(self, session, call_id, frame):
        n.append(call_id)
        if len(n) == 1:
            raise RuntimeError("first call only")
        return await real(self, session, call_id, frame)
    monkeypatch.setattr(InboxHub, "_run_call_inner", once)
    await r.send(read("c1"))
    await wait_for(lambda: len(r.decisions()) == 1)
    await r.send(read("c2"))
    await wait_for(lambda: len(r.decisions()) == 2)
    assert [(d["call_id"], d["decision"], d["reason"]) for d in r.decisions()] == [("c1", "deny", "invalid"), ("c2", "approve", "policy")]


# --------------------------------------------------------------------------- a verdict the engine must never return


@pytest.mark.parametrize("verdict", ["approve", "ALLOW", "Allow", "allow ", "", "deny\x00", "yes", None, 1, True, ["allow"]])
async def test_a_verdict_outside_allow_deny_ask_is_asked_with_no_rule_and_no_confine(monkeypatch, verdict):
    r = await Rig().start()
    bogus = PolicyDecision(verdict, "allow-read-file", ["allow-read-file"], "rule:allow-read-file", False, {"path": "read"})
    monkeypatch.setattr(type(r.session.policy), "evaluate_call", lambda self, *a, **k: bogus)
    await r.send(read("c1", auto=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []                                               # not approved, not denied: a human decides
    p = r.ui.events("inbox_pending")[0]
    assert p["rule_id"] is None
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "human" and "confine" not in r.decisions()[0]


@pytest.mark.parametrize("verdict, decision, reason", [("allow", "approve", "policy"), ("deny", "deny", "policy")])
async def test_the_three_real_verdicts_are_still_honoured(monkeypatch, verdict, decision, reason):
    r = await Rig().start()
    d = PolicyDecision(verdict, "allow-read-file", ["allow-read-file"], f"rule:allow-read-file", False, {"path": "read"} if verdict == "allow" else None)
    monkeypatch.setattr(type(r.session.policy), "evaluate_call", lambda self, *a, **k: d)
    await r.send(read("c1"))
    await wait_for(lambda: r.decisions())
    assert (r.decisions()[0]["decision"], r.decisions()[0]["reason"]) == (decision, reason)


# --------------------------------------------------------------------------- identity mode: a UI frame without a principal


async def test_a_ui_frame_without_a_principal_decides_nothing_in_identity_mode(caplog):
    w = World()
    await w.ui("bob")
    await w.agent("ci", "s")
    await w.send("s", "c1")
    await w.pending("bob", "c1")
    frame = {"event": "inbox_decision", "session_id": "s", "call_id": "c1", "decision": "approve"}
    with caplog.at_level(logging.WARNING):
        for ui in (None, FakePeer(), SimpleNamespace(principal=None)):
            await w.hub.handle_ui_frame(frame, ui)
            await w.hub.handle_ui_frame({**frame, "decision": "deny"}, ui)
    await settle()
    assert w.decisions("s") == [] and w.hub.pending_count() == 1
    assert sum("unauthenticated connection" in rec.getMessage() for rec in caplog.records) == 6
    await w.decide("bob", "s", "c1", "approve")                              # the same frame from an authenticated operator resolves it
    await wait_for(lambda: w.decisions("s"))
    assert w.decisions("s")[0]["decision"] == "approve"


async def test_a_rule_request_without_a_principal_writes_nothing_in_identity_mode(tmp_path, monkeypatch):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": []}))
    before = f.read_bytes()
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    w = World()
    await w.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "s", "call_id": "c1", "verdict": "allow", "scope": "exact",
                                 "confirm": True}, None)
    assert f.read_bytes() == before and not (tmp_path / "policy.json.bak").exists()


async def test_without_identity_mode_a_plain_ui_may_still_decide():
    r = await Rig().start()
    await r.send(call("c1"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.hub.handle_ui_frame({"event": "inbox_decision", "session_id": "s1", "call_id": "c1", "decision": "approve"}, None)
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve"


# --------------------------------------------------------------------------- identity mode: authentication fails unexpectedly


@pytest.mark.parametrize("kind", ["agent", "operator"])
async def test_an_authentication_that_blows_up_is_unauthorized_never_an_approval(monkeypatch, caplog, kind):
    w = World()

    def boom(*a, **k):
        raise RuntimeError("identity store exploded")
    monkeypatch.setattr(w.hub.identity, "authenticate_ex", boom)
    ws = FakeWS(headers={"authorization": "Bearer " + TOK["alice" if kind == "operator" else "ci"]})
    with caplog.at_level(logging.ERROR):
        assert await inbox_hub._authenticate(w.hub, ws, kind) == (None, "unauthorized")
    assert any("authentication failed unexpectedly" in rec.getMessage() for rec in caplog.records)


async def test_a_socket_whose_authentication_blows_up_is_closed_1008_and_registers_nothing(monkeypatch):
    w = World()

    async def boom(*a, **k):
        raise RuntimeError("audit exploded")
    monkeypatch.setattr(w.hub, "audit_auth_failure", boom)
    ws = FakeWS([{"event": "auth", "token": "wrong"}])
    await run_ui(w, ws)
    assert ws.sent == [{"event": "auth_error", "reason": "unauthorized"}] and ws.closed_code == 1008 and not w.hub._uis


async def test_an_unusable_identity_hub_authenticates_nobody():
    w = World()
    w.hub.identity = None
    for kind in ("agent", "operator"):
        assert await inbox_hub._authenticate(w.hub, FakeWS(headers={"authorization": "Bearer " + TOK["alice"]}), kind) == (None, "unauthorized")
