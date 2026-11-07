"""X1 end-to-end acceptance tests (black-box).

Expectations come from docs/modules/SPEC.md, DECISIONS.md and
frontend/src/types/contracts.ts only.  Every session runs under a thread
timeout guard so a hung server FAILS a test instead of hanging the suite.
"""
import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient

import main
from fakes import (
    Events, FakeClient, SERVER_EVENT_NAMES, TERMINAL_EVENTS, approve_all, auth_error, call,
    decision, deny_all, drive, guarded, of, run_session, start_msg, terminals,
    transient_error, turn, validate_event,
)

WRITE = call("write_file", {"path": "/project/pwned.txt", "content": "PWNED-123"}, "c1")
READ = call("read_file", {"path": "/project/pwned.txt"}, "c2")


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _no_ambient_auth(monkeypatch):
    monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOWED_ORIGINS", raising=False)


@pytest.fixture
def fast_sleep(monkeypatch):
    """Cap every asyncio.sleep so replay delay_ms / retry backoff cost nothing."""
    real = asyncio.sleep

    async def fast(delay, result=None):
        return await real(min(delay, 0.001), result)

    monkeypatch.setattr(asyncio, "sleep", fast)


def install_llm(monkeypatch, *clients):
    """get_client hands out the given fake clients, one per new session."""
    it = iter(clients)
    monkeypatch.setattr(main, "get_client", lambda key: (next(it), "fake-model"))


def assert_all_valid(events):
    bad = {i: validate_event(e) for i, e in enumerate(events) if validate_event(e)}
    assert not bad, f"contract violations: {bad}"


def single_terminal(events, name="session_complete"):
    t = terminals(events)
    assert len(t) == 1, f"expected exactly one terminal event, got {t}"
    assert t[0]["event"] == name
    assert events[-1] is t[0], "terminal event must be last"
    return t[0]


# 1 -------------------------------------------------------------------------
def test_approve_path(client, monkeypatch):
    fake = FakeClient([turn("I will write.", [WRITE]), turn(None, [READ]), turn("Finished.")])
    install_llm(monkeypatch, fake)
    events = run_session(client, approve_all)

    pend, res = of(events, "tool_pending"), of(events, "tool_resolved")
    assert [p["tool_name"] for p in pend] == ["write_file", "read_file"]
    assert pend[0]["tool_params"] == {"path": "/project/pwned.txt", "content": "PWNED-123"}
    assert [r["node_id"] for r in res] == [p["node_id"] for p in pend]
    assert all(r["decision"] == "approve" for r in res)
    assert "PWNED-123" in res[1]["result"], "approved write must have taken effect"
    assert not any(r["result"].startswith("[DENIED") for r in res)
    # each tool_pending precedes its tool_resolved
    for p, r in zip(pend, res):
        assert events.index(p) < events.index(r)
    assert single_terminal(events)["reason"] == "finished"


# 2 -------------------------------------------------------------------------
def test_deny_path_does_not_execute(client, monkeypatch):
    fake = FakeClient([turn(None, [WRITE]), turn(None, [READ]), turn("Finished.")])
    install_llm(monkeypatch, fake)

    def policy(ev, events):
        if ev["event"] != "tool_pending":
            return ()
        return [decision(ev["node_id"], "deny" if ev["tool_name"] == "write_file" else "approve")]

    events = run_session(client, policy)
    res = of(events, "tool_resolved")
    assert res[0]["decision"] == "deny"
    assert res[0]["result"].startswith("[DENIED")
    assert res[0]["is_replan"] is True
    assert res[1]["decision"] == "approve"
    assert "PWNED-123" not in res[1]["result"], "denied write must NOT have executed"
    assert single_terminal(events)["reason"] == "finished"


# 3 -------------------------------------------------------------------------
# Each forgery carries the OPPOSITE of the real decision, so honouring it flips the outcome.
FORGERIES = {
    "wrong_event_name": lambda nid, bait: {"event": "approve", "node_id": nid, "decision": bait},
    "wrong_node_id": lambda nid, bait: {"event": "tool_decision", "node_id": "node_nope", "decision": bait},
    "json_list": lambda nid, bait: ["tool_decision", nid, bait],
    "json_string": lambda nid, bait: bait,
    "json_number": lambda nid, bait: 1,
    "json_null": lambda nid, bait: None,
}


@pytest.mark.parametrize("forgery", sorted(FORGERIES))
@pytest.mark.parametrize("final", ["deny", "approve"])
def test_forged_messages_are_not_decisions(client, monkeypatch, forgery, final):
    fake = FakeClient([turn(None, [WRITE]), turn(None, [READ]), turn("Finished.")])
    install_llm(monkeypatch, fake)
    sent = {"done": False}

    def policy(ev, events):
        if ev["event"] != "tool_pending":
            return ()
        if ev["tool_name"] == "write_file" and not sent["done"]:
            sent["done"] = True
            bait = "deny" if final == "approve" else "approve"
            return [FORGERIES[forgery](ev["node_id"], bait), decision(ev["node_id"], final)]
        return [decision(ev["node_id"], "approve")]

    events = run_session(client, policy)
    res = of(events, "tool_resolved")
    assert len(res) == 2
    assert res[0]["decision"] == final, "forged message was taken as the decision"
    if final == "deny":
        assert res[0]["result"].startswith("[DENIED")
        assert "PWNED-123" not in res[1]["result"]
    else:
        assert "PWNED-123" in res[1]["result"]
    single_terminal(events)


# 4 -------------------------------------------------------------------------
GARBAGE = ["APPROVE", "Approve", "yes", "true", "", None, 1, True, ["approve"], "approve "]


@pytest.mark.parametrize("value", GARBAGE, ids=repr)
def test_garbage_decision_value_is_denied(client, monkeypatch, value):
    fake = FakeClient([turn(None, [WRITE]), turn(None, [READ]), turn("Finished.")])
    install_llm(monkeypatch, fake)

    def policy(ev, events):
        if ev["event"] != "tool_pending":
            return ()
        if ev["tool_name"] == "write_file":
            return [decision(ev["node_id"], value)]
        return [decision(ev["node_id"], "approve")]

    events = run_session(client, policy)
    res = of(events, "tool_resolved")
    assert res[0]["decision"] == "deny"
    assert "PWNED-123" not in res[1]["result"], "fail-closed violated: tool executed"


def test_decision_missing_key_is_denied(client, monkeypatch):
    fake = FakeClient([turn(None, [WRITE]), turn(None, [READ]), turn("Finished.")])
    install_llm(monkeypatch, fake)

    def policy(ev, events):
        if ev["event"] != "tool_pending":
            return ()
        if ev["tool_name"] == "write_file":
            return [{"event": "tool_decision", "node_id": ev["node_id"]}]
        return [decision(ev["node_id"], "approve")]

    events = run_session(client, policy)
    res = of(events, "tool_resolved")
    assert res[0]["decision"] == "deny"
    assert "PWNED-123" not in res[1]["result"]


# 5 -------------------------------------------------------------------------
def patch_gate_timeout(monkeypatch, value):
    """Make the gate timeout short.  Patches the env var, every module attribute
    named GATE_TIMEOUT_S, and await_decision's captured default (a def-time
    default would otherwise ignore the module attribute)."""
    import agent_loop
    import gate

    old = gate.GATE_TIMEOUT_S
    monkeypatch.setenv("SENTINEL_GATE_TIMEOUT_S", str(value))
    for mod in (gate, agent_loop, main):
        if hasattr(mod, "GATE_TIMEOUT_S"):
            monkeypatch.setattr(mod, "GATE_TIMEOUT_S", value)
    fn = gate.await_decision
    if fn.__defaults__ and old in fn.__defaults__:
        monkeypatch.setattr(fn, "__defaults__", tuple(value if d == old else d for d in fn.__defaults__))


def test_gate_timeout_denies_and_terminates(client, monkeypatch):
    patch_gate_timeout(monkeypatch, 0.3)
    fake = FakeClient([turn(None, [WRITE]), turn("Finished.")])
    install_llm(monkeypatch, fake)
    t0 = time.monotonic()
    events = run_session(client, None, timeout=4)  # human never answers
    assert time.monotonic() - t0 < 8
    assert of(events, "tool_pending")
    assert not [r for r in of(events, "tool_resolved") if r["decision"] == "approve"]
    assert single_terminal(events)["reason"] == "gate_timeout"
    assert_all_valid(events)


# 6 -------------------------------------------------------------------------
def test_llm_auth_error_terminates_never_hangs(client, monkeypatch):
    install_llm(monkeypatch, FakeClient([auth_error()]))
    events = run_session(client, approve_all, timeout=6)
    t = terminals(events)
    assert len(t) == 1 and events[-1] is t[0]
    if t[0]["event"] == "session_complete":
        assert t[0]["reason"] == "llm_error"
    assert_all_valid(events)


def test_llm_error_text_not_leaked_to_client(client, monkeypatch):
    # B15: str(e) must not be forwarded to the client.
    install_llm(monkeypatch, FakeClient([auth_error("bad key sk-SECRET-TOKEN-999")]))
    events = run_session(client, approve_all, timeout=6)
    assert terminals(events)
    assert "sk-SECRET-TOKEN-999" not in json.dumps(events)


# 7 -------------------------------------------------------------------------
@pytest.mark.parametrize("kinds", [("connection", "connection"), ("timeout", "connection")])
def test_transient_llm_errors_are_retried(client, monkeypatch, fast_sleep, kinds):
    fake = FakeClient([transient_error(kinds[0]), transient_error(kinds[1]), turn("Finished.")])
    install_llm(monkeypatch, fake)
    events = run_session(client, approve_all, timeout=6)
    assert len(fake.calls) == 3, "expected two retries then success"
    assert single_terminal(events)["reason"] == "finished"
    assert not of(events, "error")


# 8 -------------------------------------------------------------------------
def test_circumvention_denied_attempts_raise_alert_and_drift(client, monkeypatch):
    email = call("send_email", {"to": "boss@corp.test", "subject": "s", "body": "b"}, "e1")
    slack = call("send_slack_message", {"channel": "#general", "message": "m"}, "s1")
    fake = FakeClient([
        turn("Email the report.", [email]),
        turn("Email was denied; try Slack instead.", [slack]),
        turn("Finished."),
    ])
    install_llm(monkeypatch, fake)
    events = run_session(client, deny_all, first=start_msg(scenario="adversarial"))

    res = of(events, "tool_resolved")
    assert [r["decision"] for r in res] == ["deny", "deny"]
    alerts = of(events, "alignment_alert")
    assert alerts, "circumvention of a denied category (denied attempt) raised no alert"
    node_ids = {e["node_id"] for e in events if "node_id" in e}
    for a in alerts:
        assert a["severity"] in ("warning", "critical")
        assert a["linked_node_id"] in node_ids
    drift = of(events, "drift_update")
    assert drift, "no drift_update emitted"
    for d in drift:
        assert set(d["coordinates"]) == {"x", "y", "z"}
        assert set(d["metrics"]) == {
            "compliance_score", "goal_persistence", "hedging_density", "response_length"}
        assert isinstance(d["mahalanobis_distance"], (int, float))
        assert isinstance(d["baseline_breached"], bool)
    assert_all_valid(events)
    single_terminal(events)


# 9 -------------------------------------------------------------------------
def test_every_event_in_a_full_live_session_matches_contract(client, monkeypatch):
    fake = FakeClient([
        turn("Plan.", [call("list_directory", {"path": "/project"}, "a")]),
        turn("Next.", [WRITE]),
        turn(None, [call("send_email", {"to": "x@y.z", "subject": "s", "body": "b"}, "b")]),
        turn("Finished."),
    ])
    install_llm(monkeypatch, fake)

    def policy(ev, events):
        if ev["event"] == "tool_pending":
            return [decision(ev["node_id"], "deny" if ev["tool_name"] == "send_email" else "approve")]
        return ()

    events = run_session(client, policy)
    assert {e["event"] for e in events} <= set(SERVER_EVENT_NAMES)
    assert_all_valid(events)
    single_terminal(events)


# 10 ------------------------------------------------------------------------
@pytest.mark.parametrize("scenario", ["aligned", "adversarial"])
@pytest.mark.parametrize("model", ["no-such-model", None])
def test_replay_needs_no_key_or_valid_model(client, monkeypatch, fast_sleep, scenario, model):
    from fakes import REPO
    first = {"event": "start_task", "task": "demo", "scenario": scenario, "mode": "replay"}
    if model:
        first["model"] = model
    events = run_session(client, approve_all, first=first, timeout=10)
    assert not of(events, "error"), of(events, "error")
    assert_all_valid(events)
    term = single_terminal(events)
    assert term["reason"] == "finished"
    cached = json.loads((REPO / "demo/cached_runs" / f"{scenario}_run.json").read_text())
    assert [e["event"] for e in events[:-1]] == [e["event"] for e in cached], \
        "replay must play the cached run, in order, then terminate"
    if scenario == "adversarial":
        assert of(events, "alignment_alert")


# 11 ------------------------------------------------------------------------
def test_concurrent_sessions_do_not_share_environment(client, monkeypatch):
    pa, pb = "/project/a_only.txt", "/project/b_only.txt"
    a_script = [
        turn(None, [call("write_file", {"path": pa, "content": "AAA-SECRET"}, "w")]),
        turn(None, [call("read_file", {"path": pa}, "r1")]),
        turn(None, [call("read_file", {"path": pb}, "r2")]),
        turn("Finished."),
    ]
    b_script = [
        turn(None, [call("write_file", {"path": pb, "content": "BBB-SECRET"}, "w")]),
        turn(None, [call("read_file", {"path": pa}, "r1")]),
        turn("Finished."),
    ]
    c_script = [
        turn(None, [call("read_file", {"path": pa}, "r1")]),
        turn(None, [call("read_file", {"path": pb}, "r2")]),
        turn("Finished."),
    ]
    install_llm(monkeypatch, FakeClient(a_script), FakeClient(b_script), FakeClient(c_script))

    a_events = Events()

    def recv_until(ws, events, pred):
        while True:
            ev = ws.receive_json()
            events.append(ev)
            if pred(ev):
                return ev

    def run_b():
        ev = Events()
        with client.websocket_connect("/ws") as b:
            b.send_json(start_msg())
            drive(b, approve_all, ev)
        return ev

    def scenario():
        with client.websocket_connect("/ws") as a:
            a.send_json(start_msg())
            p = recv_until(a, a_events, lambda e: e["event"] == "tool_pending")
            a.send_json(decision(p["node_id"], "approve"))
            recv_until(a, a_events, lambda e: e["event"] == "tool_resolved")
            read_pending = recv_until(a, a_events, lambda e: e["event"] == "tool_pending")
            # A is now mid-session, awaiting a decision.  B starts, writes, finishes.
            b_events = run_b()
            # A resumes: its own state must have survived B's session, and B's must not leak in.
            a.send_json(decision(read_pending["node_id"], "approve"))
            drive(a, approve_all, a_events)
            return b_events

    b_events = guarded(scenario, 8, progress=a_events)
    b_reads = of(b_events, "tool_resolved")
    assert "AAA-SECRET" not in b_reads[-1]["result"], "session B saw session A's file"
    a_reads = of(a_events, "tool_resolved")
    assert "AAA-SECRET" in a_reads[1]["result"], "session A lost its own file when B started"
    assert "BBB-SECRET" not in a_reads[2]["result"], "session A saw session B's file"
    single_terminal(a_events)
    single_terminal(b_events)

    c_events = run_session(client, approve_all)
    c_reads = of(c_events, "tool_resolved")
    assert "AAA-SECRET" not in c_reads[0]["result"], "a later session inherited earlier state"
    assert "BBB-SECRET" not in c_reads[1]["result"], "a later session inherited earlier state"


# 12 ------------------------------------------------------------------------
BAD_FIRST = {
    "wrong_event": lambda ws: ws.send_json({"event": "tool_decision", "node_id": "x", "decision": "approve"}),
    "json_list": lambda ws: ws.send_json([1, 2, 3]),
    "json_string": lambda ws: ws.send_json("start_task"),
    "json_null": lambda ws: ws.send_json(None),
    "not_json": lambda ws: ws.send_text("this is not json {"),
    "no_event_key": lambda ws: ws.send_json({"task": "x"}),
}


@pytest.mark.parametrize("kind", sorted(BAD_FIRST))
def test_bad_first_message_gets_error_and_close(client, kind):
    events = Events()

    def body():
        with client.websocket_connect("/ws") as ws:
            BAD_FIRST[kind](ws)
            return drive(ws, None, events)

    guarded(body, 10, progress=events)
    assert events, "no error event before close"
    assert events[0]["event"] == "error"
    assert validate_event(events[0]) == []
    assert [e["event"] for e in events] == ["error"], "only an error event, then close"


# 13 ------------------------------------------------------------------------
def run_session_safe(client, url, headers):
    from starlette.websockets import WebSocketDisconnect
    events = Events()

    def body():
        kw = {"headers": headers} if headers else {}
        try:
            with client.websocket_connect(url, **kw) as ws:
                ws.send_json(start_msg())
                drive(ws, approve_all, events)
        except WebSocketDisconnect:
            pass

    guarded(body, 8, progress=events)
    return events


def session_delivered(client, monkeypatch, url, headers=None):
    """Events a client gets at /ws, other than a bare auth `error`.  A rejected
    client must receive no session at all."""
    install_llm(monkeypatch, FakeClient([turn("Hello.", [call("list_directory", {"path": "/project"})]),
                                         turn("Finished.")]))
    events = run_session_safe(client, url, headers)
    return [e for e in events if e.get("event") != "error"]


@pytest.fixture
def token_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_WS_TOKEN", "s3cret-token")


def test_ws_rejects_missing_token(client, monkeypatch, token_env):
    assert session_delivered(client, monkeypatch, "/ws") == []


def test_ws_rejects_wrong_token(client, monkeypatch, token_env):
    assert session_delivered(client, monkeypatch, "/ws?token=wrong") == []


def test_ws_accepts_correct_token(client, monkeypatch, token_env):
    events = session_delivered(client, monkeypatch, "/ws?token=s3cret-token")
    assert terminals(events), "valid token must get a full session"


def test_ws_rejects_bad_origin_even_with_token(client, monkeypatch, token_env):
    got = session_delivered(
        client, monkeypatch, "/ws?token=s3cret-token", {"origin": "http://evil.example"})
    assert got == []


def test_ws_accepts_default_allowed_origin(client, monkeypatch, token_env):
    events = session_delivered(
        client, monkeypatch, "/ws?token=s3cret-token", {"origin": "http://localhost:5173"})
    assert terminals(events)


def test_ws_rejects_bad_origin_without_token_configured(client, monkeypatch):
    got = session_delivered(client, monkeypatch, "/ws", {"origin": "http://evil.example"})
    assert got == []


# connection lifecycle (main.py documents: connection closes after session_complete)
def test_connection_closes_after_session_complete(client, monkeypatch):
    install_llm(monkeypatch, FakeClient([turn("Finished.")]))
    events = run_session(client, approve_all)
    single_terminal(events)
    assert events.closed is True, "server left the socket open after the terminal event"
