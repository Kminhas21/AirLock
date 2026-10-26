"""Replay of cached, contract-shaped runs (bug B14): no model key needed."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import events
import gate

logger = logging.getLogger(__name__)

DEFAULT_RUNS_DIR = Path(__file__).parent.parent / "demo" / "cached_runs"
SCENARIOS = ("aligned", "adversarial")
TERMINAL = ("session_complete", "error")
KNOWN = {"reasoning", "tool_pending", "tool_resolved", "drift_update",
         "alignment_alert", "session_complete", "error"}
DENIED_RESULT = "[DENIED by human operator. You may not perform this action. Adjust your plan.]"
APPROVED_RESULT = "[APPROVED by human operator. Recorded outcome for this step was a denial.]"


def _load(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("replay file must be a non-empty list")
    for e in data:
        if not isinstance(e, dict) or e.get("event") not in KNOWN:
            raise ValueError("replay file contains an invalid event")
    return data


def _delay_s(ev: dict, scale: float) -> float:
    d = ev.get("delay_ms")
    if isinstance(d, bool) or not isinstance(d, (int, float)) or d <= 0:
        return 0.0
    return d / 1000.0 * max(scale, 0.0)


def _resolved(ev: dict, decision: str) -> dict:
    out = dict(ev)
    if out.get("decision") != decision:
        # recorded text describes the other outcome; do not show it
        out["result"] = DENIED_RESULT if decision == "deny" else APPROVED_RESULT
        out["agent_response"] = ""
    out["decision"] = decision
    out["is_replan"] = decision == "deny"
    return out


async def run_replay(websocket, scenario: str, runs_dir: Path = DEFAULT_RUNS_DIR,
                     delay_scale: float = 1.0) -> None:
    if scenario not in SCENARIOS:
        await websocket.send_json(events.error("Unknown replay scenario"))
        return
    try:
        recorded = _load(Path(runs_dir) / f"{scenario}_run.json")
    except (OSError, ValueError) as exc:  # JSONDecodeError is a ValueError
        logger.warning("replay: cannot load %s: %s", scenario, exc)
        await websocket.send_json(events.error("Replay data unavailable"))
        return

    decisions: dict[str, str] = {}
    for rec in recorded:
        delay = _delay_s(rec, delay_scale)
        if delay:
            await asyncio.sleep(delay)
        ev = {k: v for k, v in rec.items() if k != "delay_ms"}
        kind = ev["event"]
        if "timestamp" in ev:
            ev["timestamp"] = events._ts()
        if kind == "tool_resolved" and ev.get("node_id") in decisions:
            ev = _resolved(ev, decisions[ev["node_id"]])
        await websocket.send_json(ev)
        if kind in TERMINAL:
            return  # never emit two terminal events
        if kind == "tool_pending":
            result = await gate.await_decision(websocket, ev["node_id"])
            decisions[ev["node_id"]] = result.decision
            if result.reason == "timeout":
                await websocket.send_json(events.session_complete(
                    "gate_timeout", "No decision received; replay stopped."))
                return
    await websocket.send_json(events.session_complete("finished"))
