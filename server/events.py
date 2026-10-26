"""Pure builders for server -> client WebSocket events.

Shapes follow frontend/src/types/contracts.ts (authoritative); the contract
test in tests/contract parses that file and fails on any drift.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal


def _ts(now: datetime | None = None) -> str:
    """ISO-8601 UTC timestamp; `now` is injectable for tests."""
    n = now or datetime.now(timezone.utc)
    if n.tzinfo is None:
        n = n.replace(tzinfo=timezone.utc)
    return n.astimezone(timezone.utc).isoformat()


def reasoning(node_id: str, parent_id: str | None, text: str, *, now: datetime | None = None) -> dict:
    return {"event": "reasoning", "node_id": node_id, "parent_id": parent_id,
            "text": text, "timestamp": _ts(now)}


def tool_pending(
    node_id: str,
    parent_id: str | None,
    tool_name: str,
    tool_params: dict[str, Any],
    risk_level: Literal["low", "medium", "high", "critical"],
    reasoning_context: str = "",
    node_type: Literal["tool_call", "replan"] = "tool_call",
    *,
    now: datetime | None = None,
) -> dict:
    return {"event": "tool_pending", "node_id": node_id, "parent_id": parent_id,
            "node_type": node_type, "tool_name": tool_name, "tool_params": tool_params,
            "risk_level": risk_level, "reasoning_context": reasoning_context,
            "timestamp": _ts(now)}


def tool_resolved(
    node_id: str,
    decision: Literal["approve", "deny"],
    result: str,
    is_replan: bool = False,
    agent_response: str = "",
    *,
    now: datetime | None = None,
) -> dict:
    return {"event": "tool_resolved", "node_id": node_id, "decision": decision,
            "result": result, "agent_response": agent_response,
            "is_replan": is_replan, "timestamp": _ts(now)}


def drift_update(
    step_index: int,
    node_id: str,
    coordinates: dict[str, float],
    metrics: dict[str, float],
    mahalanobis_distance: float,
    baseline_breached: bool,
    *,
    now: datetime | None = None,
) -> dict:
    return {"event": "drift_update", "step_index": step_index, "node_id": node_id,
            "coordinates": coordinates, "metrics": metrics,
            "mahalanobis_distance": mahalanobis_distance,
            "baseline_breached": baseline_breached, "timestamp": _ts(now)}


def alignment_alert(
    severity: Literal["warning", "critical"],
    trigger: str,
    message: str,
    linked_node_id: str,
    drift_score: float,
    threshold: float,
) -> dict:
    # Contract has no timestamp on this event.
    return {"event": "alignment_alert", "severity": severity, "trigger": trigger,
            "message": message, "linked_node_id": linked_node_id,
            "drift_score": drift_score, "threshold": threshold}


def session_complete(
    reason: Literal["finished", "max_iterations", "llm_error", "gate_timeout"],
    message: str = "",
    *,
    now: datetime | None = None,
) -> dict:
    return {"event": "session_complete", "reason": reason, "message": message,
            "timestamp": _ts(now)}


def error(message: str) -> dict:
    return {"event": "error", "message": message}
