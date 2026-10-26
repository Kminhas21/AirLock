"""Trace-replay mode of the scripted LLM endpoint (httpx against the ASGI app, no sockets)."""
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("fake_llm_under_test", REPO / "tests" / "browser" / "fake_llm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def P(i, text, tool=None, args=None, decision="approve"):
    prop = None if tool is None else {"tool": tool, "args": args or {}, "decision": decision, "label": "ok", "why": "w"}
    return {"i": i, "agent_text": text, "proposal": prop}


TRACE = {
    "id": "t-merge", "category": "channel_switch", "task": "t", "denied_effect_summary": "d",
    "steps": [
        P(0, "zero says hi"),                                                  # leading message-only
        P(1, "one reads", "read_file", {"path": "/p/a.txt"}),
        P(2, "two emails", "send_email", {"to": "a@team.com", "subject": "s", "body": "b"}, "deny"),
        P(3, "three muses"), P(4, "four muses more"),                          # merged into step 5
        P(5, "five posts", "post_to_webhook", {"url": "https://x.example/h", "payload": "p"}),
        P(6, "six wraps up"), P(7, "seven done"),                              # trailing -> final text turn
    ],
}
TRACE_ENDS_ON_PROPOSAL = {
    "id": "t-noend", "category": "aligned_ack", "task": "t", "denied_effect_summary": "d",
    "steps": [P(0, "a", "read_file", {"path": "/x"}), P(1, "b", "list_directory", {"path": "/"})],
}


@pytest.fixture
def mod(tmp_path, monkeypatch):
    f = tmp_path / "traces.json"
    f.write_text(json.dumps([TRACE, TRACE_ENDS_ON_PROPOSAL]))
    monkeypatch.setenv("FAKE_LLM_TRACES", str(f))
    return _load()


@pytest.fixture
async def client(mod):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mod.app), base_url="http://t") as c:
        yield c


def conv(task, n_assistant=0):
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": task}]
    for k in range(n_assistant):
        msgs.append({"role": "assistant", "content": "x", "tool_calls": [
            {"id": f"call_{k}", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]})
        msgs.append({"role": "tool", "tool_call_id": f"call_{k}", "content": "ok"})
    return {"model": "m", "messages": msgs}


async def turn(client, task, k):
    r = await client.post("/v1/chat/completions", json=conv(task, k))
    assert r.status_code == 200
    return r.json()["choices"][0]


async def test_turns_follow_proposal_bearing_steps_and_merge_messages(client):
    task = "TRACE:t-merge please"
    c0 = await turn(client, task, 0)
    # leading message-only step 0 merges into the first proposal turn
    assert c0["message"]["content"] == "zero says hi one reads"
    tc = c0["message"]["tool_calls"][0]["function"]
    assert tc["name"] == "read_file" and json.loads(tc["arguments"]) == {"path": "/p/a.txt"}
    assert c0["finish_reason"] == "tool_calls"

    c1 = await turn(client, task, 1)
    assert c1["message"]["content"] == "two emails"
    assert json.loads(c1["message"]["tool_calls"][0]["function"]["arguments"])["to"] == "a@team.com"

    c2 = await turn(client, task, 2)
    assert c2["message"]["content"] == "three muses four muses more five posts"
    assert c2["message"]["tool_calls"][0]["function"]["name"] == "post_to_webhook"


async def test_trailing_messages_form_final_text_only_turn(client):
    c3 = await turn(client, "TRACE:t-merge", 3)
    assert c3["message"]["content"] == "six wraps up seven done"
    assert "tool_calls" not in c3["message"] and c3["finish_reason"] == "stop"
    # asking beyond the end stays a text-only turn (never raises)
    c9 = await turn(client, "TRACE:t-merge", 9)
    assert "tool_calls" not in c9["message"]


async def test_trace_without_trailing_text_still_ends_with_text_only_turn(client):
    c2 = await turn(client, "TRACE:t-noend", 2)
    assert "tool_calls" not in c2["message"] and c2["message"]["content"]


async def test_tool_call_ids_unique_per_turn(client):
    ids = [(await turn(client, "TRACE:t-merge", k))["message"]["tool_calls"][0]["id"] for k in range(3)]
    assert len(set(ids)) == 3


async def test_trace_info_maps_steps_to_turns(client):
    r = await client.get("/_trace_info", params={"id": "t-merge"})
    assert r.status_code == 200
    info = r.json()
    assert info["id"] == "t-merge"
    assert [t["proposal_step"] for t in info["turns"]] == [1, 2, 5]
    assert [t["ordinal"] for t in info["turns"]] == [0, 1, 2]
    assert [t["steps"] for t in info["turns"]] == [[0, 1], [2], [3, 4, 5]]
    assert [t["decision"] for t in info["turns"]] == ["approve", "deny", "approve"]
    assert [t["tool"] for t in info["turns"]] == ["read_file", "send_email", "post_to_webhook"]
    assert info["final"]["steps"] == [6, 7]
    assert info["step_to_ordinal"] == {"1": 0, "2": 1, "5": 2}


async def test_trace_info_unknown_id_is_404(client):
    assert (await client.get("/_trace_info", params={"id": "nope"})).status_code == 404


async def test_unknown_trace_in_conversation_is_a_clear_error(client):
    r = await client.post("/v1/chat/completions", json=conv("TRACE:nope", 0))
    assert r.status_code == 404


async def test_multiple_files_colon_separated(tmp_path, monkeypatch):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps([TRACE]))
    b.write_text(json.dumps(TRACE_ENDS_ON_PROPOSAL))     # a single object is also accepted
    monkeypatch.setenv("FAKE_LLM_TRACES", f"{a}:{b}")
    m = _load()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.app), base_url="http://t") as c:
        assert (await c.get("/_trace_info", params={"id": "t-noend"})).status_code == 200
        assert (await c.get("/_trace_info", params={"id": "t-merge"})).status_code == 200


async def test_default_trace_file_is_eval_final(monkeypatch):
    monkeypatch.delenv("FAKE_LLM_TRACES", raising=False)
    m = _load()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.app), base_url="http://t") as c:
        assert (await c.get("/_trace_info", params={"id": "gen_a-001"})).status_code == 200


async def test_scripted_scenarios_still_work(client):
    r = await client.post("/v1/chat/completions", json=conv("do the thing", 0))
    m = r.json()["choices"][0]["message"]
    assert m["tool_calls"][0]["function"]["name"] == "list_directory"
    r = await client.post("/v1/chat/completions", json=conv("LONG_RUN", 12))
    assert "tool_calls" not in r.json()["choices"][0]["message"]


async def test_replay_matches_every_real_trace_shape():
    """For all 120 shipped traces: turns == #proposals, content/args round-trip, final turn exists."""
    m = _load()
    traces = json.loads((REPO / "eval" / "final" / "traces.json").read_text())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=m.app), base_url="http://t") as c:
        for t in traces[:40]:
            info = (await c.get("/_trace_info", params={"id": t["id"]})).json()
            props = [s for s in t["steps"] if s["proposal"]]
            assert len(info["turns"]) == len(props)
            for k, s in enumerate(props):
                ch = (await c.post("/v1/chat/completions", json=conv("TRACE:" + t["id"], k))).json()["choices"][0]
                call = ch["message"]["tool_calls"][0]["function"]
                assert call["name"] == s["proposal"]["tool"]
                assert json.loads(call["arguments"]) == s["proposal"]["args"]
                assert ch["message"]["content"].endswith(s["agent_text"])
