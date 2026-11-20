"""The agent loop against a HOSTILE model (docs/TESTING_REALITY.md, rung 3).

Each mode is a malformed, oversized or odd response real providers/models produce. For EVERY mode the real backend process must:
  * end the session with exactly one terminal event (session_complete or error), never hang;
  * stay alive and keep serving: /health ok, and a normal session afterwards still completes (no poisoned state);
  * never emit non-finite numbers, never leak an exception, a traceback, a path or a credential to the client;
  * never log an unhandled exception (an 'unexpected server error' is a bug even though the client only saw 'Internal server error')."""
import asyncio
import json
import math
import re
import urllib.request

import pytest
import websockets

from tests.reality_fixtures import stack  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality            # real processes, minutes: own gate stage (pytest -m reality), deselected by default

TERMINAL = {"session_complete", "error"}
KNOWN = {"reasoning", "tool_pending", "tool_resolved", "drift_update", "alignment_alert", "session_complete", "error"}
# markers of a failure NOBODY handled (the catch-alls in main.py / asyncio / uvicorn); deliberately logged, handled conditions are fine
UNHANDLED = ("unexpected server error", "Task exception was never retrieved", "Exception in ASGI application", "Future exception was never retrieved")
LEAKS = re.compile(r"Traceback|openai\.|sk-live|SECRETSECRET|/home/|site-packages|File \"|Error\(|Exception")


def modes(port_hint=None):
    # the list is static in the module: import it (the server process serves the same dict)
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("hostile_llm", Path(__file__).resolve().parents[1] / "browser/hostile_llm.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return sorted(m.MODES)


async def run_session(port: int, mode: str, timeout: float = 120.0) -> list[dict]:
    frames: list[dict] = []
    decided = 0

    async def go():
        nonlocal decided
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws", max_size=None) as ws:
            await ws.send(json.dumps({"event": "start_task", "task": f"HOSTILE:{mode} do the work", "scenario": "adversarial", "mode": "live"}))
            async for raw in ws:
                f = json.loads(raw)
                frames.append(f)
                if f.get("event") == "tool_pending":
                    await ws.send(json.dumps({"event": "tool_decision", "node_id": f["node_id"], "decision": "approve" if decided % 3 else "deny"}))
                    decided += 1
                if f.get("event") in TERMINAL:
                    break
    await asyncio.wait_for(go(), timeout)
    return frames


def finite(x) -> bool:
    if isinstance(x, dict):
        return all(finite(v) for v in x.values())
    if isinstance(x, list):
        return all(finite(v) for v in x)
    return not (isinstance(x, float) and not math.isfinite(x))


def health(port: int) -> dict:
    return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=10).read())


@pytest.mark.parametrize("mode", modes())
async def test_hostile_mode_is_survived(stack, mode):
    before = stack.log_text()
    frames = await run_session(stack.port, mode)
    names = [f.get("event") for f in frames]
    terminals = [f for f in frames if f.get("event") in TERMINAL]
    assert len(terminals) == 1, f"{mode}: expected exactly one terminal event, got {names[-6:]}"
    assert names[-1] in TERMINAL, f"{mode}: events after the terminal event"
    unknown = set(names) - KNOWN
    assert not unknown, f"{mode}: unknown event names {unknown}"
    assert all(finite(f) for f in frames), f"{mode}: non-finite number sent to the UI"
    for f in frames:
        if f.get("event") == "error" or (f.get("event") == "session_complete" and f.get("reason") != "finished"):
            blob = json.dumps(f)
            assert not LEAKS.search(blob), f"{mode}: internal detail leaked to the client: {blob[:300]}"
    new_log = stack.log_text()[len(before):]
    unhandled = [m for m in UNHANDLED if m in new_log]
    assert not unhandled, f"{mode}: unhandled failure in the server log ({unhandled}):\n{new_log[-1500:]}"
    # nothing is poisoned: the server is healthy and a normal session still completes
    assert health(stack.port)["status"] == "ok"
    after = await run_session(stack.port, "benign")
    assert [f for f in after if f.get("event") in TERMINAL][-1].get("event") == "session_complete", f"{mode}: the next normal session failed"


async def test_every_drift_step_from_a_textless_turn_is_embedded(stack):
    """A real model often returns tool calls with NO text (D24): the drift monitor still gets a step for it."""
    frames = await run_session(stack.port, "empty_content_tool_call")
    assert sum(f.get("event") == "drift_update" for f in frames) >= 4
    assert sum(f.get("event") == "reasoning" for f in frames) < sum(f.get("event") == "drift_update" for f in frames)   # steps without a reasoning node
