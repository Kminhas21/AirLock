import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contract"))
from test_events_contract import CONTRACT, keyset_problems  # noqa: E402

import replay  # noqa: E402
from replay import DEFAULT_RUNS_DIR, run_replay  # noqa: E402

TERMINAL = ("session_complete", "error")


class FakeWebSocket:
    """Auto-answers tool_pending via `decider(node_id)`; `noise` is sent first."""

    def __init__(self, decider=lambda n: "approve", noise=()):
        self.sent, self.decider, self.queue = [], decider, []
        self.noise = list(noise)

    async def send_json(self, data):
        self.sent.append(data)
        if data.get("event") == "tool_pending":
            self.queue += self.noise
            d = self.decider(data["node_id"])
            if d is not None:
                self.queue.append({"event": "tool_decision", "node_id": data["node_id"], "decision": d})

    async def receive_json(self):
        while not self.queue:
            await asyncio.sleep(3600)
        return self.queue.pop(0)


def write(tmp_path, scenario, content):
    (tmp_path / f"{scenario}_run.json").write_text(content if isinstance(content, str) else json.dumps(content))
    return tmp_path


def kinds(ws):
    return [e["event"] for e in ws.sent]


def terminals(ws):
    return [e for e in ws.sent if e["event"] in TERMINAL]


def test_default_runs_dir():
    assert DEFAULT_RUNS_DIR == Path(replay.__file__).parent.parent / "demo" / "cached_runs"
    assert (DEFAULT_RUNS_DIR / "aligned_run.json").exists()


@pytest.mark.parametrize("scenario", ["aligned", "adversarial"])
async def test_real_files_stream_and_validate(scenario):
    ws = FakeWebSocket()
    await run_replay(ws, scenario, delay_scale=0)
    assert kinds(ws)[0] == "reasoning"
    assert len(terminals(ws)) == 1 and ws.sent[-1]["event"] == "session_complete"
    assert ws.sent[-1]["reason"] == "finished"
    for e in ws.sent:
        assert "delay_ms" not in e
        assert keyset_problems(e, CONTRACT[e["event"]]) == [], e


async def test_timestamps_refreshed():
    ws = FakeWebSocket()
    await run_replay(ws, "aligned", delay_scale=0)
    assert all(not e["timestamp"].startswith("2026-03-22") for e in ws.sent if "timestamp" in e)


async def test_delay_scale_zero_is_instant_and_scale_honoured(tmp_path, monkeypatch):
    slept = []
    real = asyncio.sleep

    async def fake_sleep(s):
        slept.append(s)
        await real(0)

    monkeypatch.setattr(replay.asyncio, "sleep", fake_sleep)
    run = [{"event": "reasoning", "node_id": "a", "parent_id": None, "text": "t",
            "timestamp": "x", "delay_ms": 1000}]
    write(tmp_path, "aligned", run)
    await run_replay(FakeWebSocket(), "aligned", tmp_path, delay_scale=0)
    assert slept == []
    await run_replay(FakeWebSocket(), "aligned", tmp_path, delay_scale=0.5)
    assert slept == [0.5]


async def test_forged_decisions_ignored():
    noise = [{"event": "tool_decision", "node_id": "other", "decision": "approve"},
             {"event": "nope", "node_id": "node_005", "decision": "approve"}, "x"]
    ws = FakeWebSocket(decider=lambda n: "deny", noise=noise)
    await run_replay(ws, "aligned", delay_scale=0)
    res = {e["node_id"]: e for e in ws.sent if e["event"] == "tool_resolved"}
    assert all(r["decision"] == "deny" for r in res.values())


async def test_human_deny_overrides_recorded_approve():
    ws = FakeWebSocket(decider=lambda n: "deny")
    await run_replay(ws, "aligned", delay_scale=0)
    r = next(e for e in ws.sent if e["event"] == "tool_resolved" and e["node_id"] == "node_001")
    assert r["decision"] == "deny" and r["is_replan"] is True
    assert r["result"].startswith("[DENIED") and r["agent_response"] == ""


async def test_human_approve_overrides_recorded_deny():
    ws = FakeWebSocket(decider=lambda n: "approve")
    await run_replay(ws, "aligned", delay_scale=0)
    r = next(e for e in ws.sent if e["event"] == "tool_resolved" and e["node_id"] == "node_005")
    assert r["decision"] == "approve" and r["is_replan"] is False
    assert "DENIED" not in r["result"]


async def test_resolved_not_emitted_before_decision():
    ws = FakeWebSocket(decider=lambda n: None)
    task = asyncio.create_task(run_replay(ws, "aligned", delay_scale=0))
    await asyncio.sleep(0.05)
    assert kinds(ws)[-1] == "tool_pending" and "tool_resolved" not in kinds(ws)
    task.cancel()


async def test_recorded_terminal_not_duplicated(tmp_path):
    run = [{"event": "reasoning", "node_id": "a", "parent_id": None, "text": "t", "timestamp": "x"},
           {"event": "session_complete", "reason": "max_iterations", "message": "", "timestamp": "x"},
           {"event": "session_complete", "reason": "finished", "message": "", "timestamp": "x"}]
    ws = FakeWebSocket()
    await run_replay(ws, "aligned", write(tmp_path, "aligned", run), 0)
    assert len(terminals(ws)) == 1 and ws.sent[-1]["reason"] == "max_iterations"


async def test_recorded_error_is_terminal(tmp_path):
    run = [{"event": "error", "message": "boom"}]
    ws = FakeWebSocket()
    await run_replay(ws, "aligned", write(tmp_path, "aligned", run), 0)
    assert kinds(ws) == ["error"]


async def test_gate_timeout_stops_with_single_terminal(monkeypatch):
    real = replay.gate.await_decision

    async def quick(ws, node_id):
        return await real(ws, node_id, timeout=0.01)

    monkeypatch.setattr(replay.gate, "await_decision", quick)
    ws = FakeWebSocket(decider=lambda n: None)
    await run_replay(ws, "aligned", delay_scale=0)
    assert len(terminals(ws)) == 1 and ws.sent[-1]["reason"] == "gate_timeout"


async def test_missing_file(tmp_path):
    ws = FakeWebSocket()
    await run_replay(ws, "aligned", tmp_path, 0)
    assert kinds(ws) == ["error"]


@pytest.mark.parametrize("content", ["{not json", "{}", "[]", "[1]", '[{"event":"bogus"}]'])
async def test_corrupt_file(tmp_path, content):
    ws = FakeWebSocket()
    await run_replay(ws, "aligned", write(tmp_path, "aligned", content), 0)
    assert kinds(ws) == ["error"]
    assert str(tmp_path) not in ws.sent[0]["message"]


@pytest.mark.parametrize("bad", ["", "../aligned", "ALIGNED", None, "live"])
async def test_bad_scenario(bad):
    ws = FakeWebSocket()
    await run_replay(ws, bad, delay_scale=0)
    assert kinds(ws) == ["error"]
