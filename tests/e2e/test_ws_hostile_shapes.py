"""Fast, in-process regression tests for what the HOSTILE-model suite (tests/hostile, real HTTP + real process) found.
Each one failed before its fix: the IndexError on empty choices, the crash on list-of-parts content, textless tool-call turns."""
import pytest
from fastapi.testclient import TestClient

import main
from fakes import FakeClient, _Obj, approve_all, call, of, run_session, terminals, turn
from test_ws_session import install_llm

READ = call("read_file", {"path": "/project/a.txt"}, "c1")


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _open_ws(monkeypatch):
    monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOWED_ORIGINS", raising=False)


def test_a_response_with_no_choices_ends_the_session_cleanly(client, monkeypatch):
    install_llm(monkeypatch, FakeClient([_Obj(id="x", model="m", choices=[], usage=None)]))
    events = run_session(client, approve_all)
    t = terminals(events)
    assert len(t) == 1 and t[0]["event"] == "session_complete" and t[0]["reason"] == "llm_error"
    assert "Error" not in t[0].get("message", "") and "index" not in t[0].get("message", "").lower()


def test_content_as_a_list_of_parts_is_joined_not_crashed_on(client, monkeypatch):
    parts = [{"type": "text", "text": "Part one."}, {"type": "text", "text": "Part two."}]
    install_llm(monkeypatch, FakeClient([turn(parts, [READ]), turn("Done.")]))
    events = run_session(client, approve_all)
    assert [r["text"] for r in of(events, "reasoning")][0] == "Part one. Part two."
    assert terminals(events)[0]["event"] == "session_complete"


def test_a_textless_tool_call_turn_still_gets_a_drift_step_and_no_reasoning_node(client, monkeypatch):
    install_llm(monkeypatch, FakeClient([turn(None, [READ]), turn("", [call("list_directory", {"path": "/project"}, "c2")]), turn("Done.")]))
    events = run_session(client, approve_all)
    assert len(of(events, "drift_update")) == 3
    assert len(of(events, "reasoning")) == 1                       # only the final text turn has text
    assert terminals(events)[0]["reason"] == "finished"
