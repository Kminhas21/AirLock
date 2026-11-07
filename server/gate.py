"""Airlock approval gate: fail-closed wait for a human tool decision."""
import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

GATE_TIMEOUT_S = float(os.getenv("SENTINEL_GATE_TIMEOUT_S", "300"))


@dataclass(frozen=True)
class GateResult:
    decision: Literal["approve", "deny"]
    reason: Literal["human", "timeout", "invalid"]


async def await_decision(
    websocket, node_id: str, timeout: float | None = GATE_TIMEOUT_S
) -> GateResult:
    loop = asyncio.get_running_loop()
    deadline = None if timeout is None else loop.time() + timeout
    while True:
        try:
            if deadline is None:
                msg = await websocket.receive_json()
            else:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return GateResult("deny", "timeout")
                msg = await asyncio.wait_for(websocket.receive_json(), remaining)
        except asyncio.TimeoutError:
            if deadline is not None and loop.time() >= deadline:
                return GateResult("deny", "timeout")
            raise
        if not isinstance(msg, dict):
            logger.warning("gate: ignoring non-dict message while awaiting %s", node_id)
            continue
        if msg.get("event") != "tool_decision" or msg.get("node_id") != node_id:
            logger.warning(
                "gate: ignoring message event=%r node_id=%r while awaiting %s",
                msg.get("event"), msg.get("node_id"), node_id,
            )
            continue
        decision = msg.get("decision")
        if isinstance(decision, str) and decision == "approve":
            return GateResult("approve", "human")
        if decision == "deny":
            return GateResult("deny", "human")
        return GateResult("deny", "invalid")


class DecisionLedger:
    """Ensures a node_id is claimed (and so executed) at most once."""

    def __init__(self) -> None:
        self._claimed: set[str] = set()

    def claim(self, node_id: str) -> bool:
        if node_id in self._claimed:
            return False
        self._claimed.add(node_id)
        return True
