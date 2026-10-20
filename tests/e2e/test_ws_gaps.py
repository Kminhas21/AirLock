"""Acceptance tests added after mutation testing exposed gaps in test_ws_session.py.

scripts/mutation_check.py re-introduced three bugs that the original suite did not catch:
  B6  circumvention detector removed       -> a goal-persistence *warning* still satisfied the old assertion
  B5  retry exhaustion without terminal event -> only a hard auth error was tested
  B15 unexpected server exception text leaked -> only the LLM-error path was tested
Expectations come from SPEC.md / DECISIONS.md only.
"""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

import main
from fakes import (
    FakeClient, approve_all, call, deny_all, of, run_session, start_msg, terminals,
    transient_error, turn,
)


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOWED_ORIGINS", raising=False)

    real = asyncio.sleep

    async def fast(delay, result=None):
        return await real(min(delay, 0.001), result)

    monkeypatch.setattr(asyncio, "sleep", fast)


def test_denied_sibling_tool_raises_a_circumvention_alert_on_that_node(client, monkeypatch):
    email = call("send_email", {"to": "a@b.c", "subject": "s", "body": "b"}, "e1")
    slack = call("send_slack_message", {"channel": "#x", "message": "m"}, "s1")
    fake = FakeClient([turn("Sending.", [email]), turn("Trying another way.", [slack]), turn("Done.")])
    monkeypatch.setattr(main, "get_client", lambda key: (fake, "fake-model"))
    events = run_session(client, deny_all, first=start_msg(scenario="adversarial"))

    pendings = of(events, "tool_pending")
    slack_node = next(p["node_id"] for p in pendings if p["tool_name"] == "send_slack_message")
    circ = [a for a in of(events, "alignment_alert")
            if a["trigger"] == "circumvention_detected" and a["severity"] == "critical"]
    assert circ, "denied circumvention attempt produced no circumvention alert"
    assert all(a["linked_node_id"] == slack_node for a in circ)
    assert len(circ) == 1, "circumvention must alert once per attempt, not once per detector"


def test_exhausted_llm_retries_end_with_one_terminal_event(client, monkeypatch):
    fake = FakeClient([transient_error("connection") for _ in range(10)])
    monkeypatch.setattr(main, "get_client", lambda key: (fake, "fake-model"))
    events = run_session(client, approve_all, timeout=8)

    t = terminals(events)
    assert len(t) == 1 and t[0]["event"] == "session_complete" and t[0]["reason"] == "llm_error"
    assert 2 <= len(fake.calls) <= 4, "expected a bounded number of attempts"


def test_unexpected_server_exception_text_is_not_leaked(client, monkeypatch):
    def boom():
        raise RuntimeError("secret-internal-path /etc/shadow sk-LEAK-777")

    monkeypatch.setattr(main, "reset_environment", boom)
    events = run_session(client, approve_all, timeout=6)

    assert of(events, "error"), "client was not told the session failed"
    assert "sk-LEAK-777" not in json.dumps(events) and "/etc/shadow" not in json.dumps(events)
