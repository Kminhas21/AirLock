import asyncio
import logging

import pytest
from starlette.websockets import WebSocketDisconnect

from gate import GATE_TIMEOUT_S, DecisionLedger, GateResult, await_decision


class FakeWebSocket:
    """Scripted queue. Items: messages, Exception instances (raised), or 'HANG'."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    async def receive_json(self):
        self.calls += 1
        if not self.script:
            await asyncio.sleep(3600)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if item == "HANG":
            await asyncio.sleep(3600)
        return item


def msg(decision="approve", node_id="n1", event="tool_decision"):
    return {"event": event, "node_id": node_id, "decision": decision}


async def test_approve_exact():
    r = await await_decision(FakeWebSocket([msg("approve")]), "n1", timeout=1)
    assert r == GateResult("approve", "human")


async def test_deny_explicit():
    r = await await_decision(FakeWebSocket([msg("deny")]), "n1", timeout=1)
    assert r == GateResult("deny", "human") or r.decision == "deny"
    assert r.decision == "deny"


@pytest.mark.parametrize("bad", ["APPROVE", "yes", None, "approve ", True, 1, "Approve"])
async def test_garbage_decision_denies_invalid(bad):
    r = await await_decision(FakeWebSocket([msg(bad)]), "n1", timeout=1)
    assert r == GateResult("deny", "invalid")


async def test_missing_decision_denies_invalid():
    m = {"event": "tool_decision", "node_id": "n1"}
    r = await await_decision(FakeWebSocket([m]), "n1", timeout=1)
    assert r == GateResult("deny", "invalid")


async def test_wrong_event_ignored():
    ws = FakeWebSocket([msg("approve", event="other"), msg("deny")])
    r = await await_decision(ws, "n1", timeout=1)
    assert r.decision == "deny" and ws.calls == 2


async def test_wrong_node_ignored():
    ws = FakeWebSocket([msg("approve", node_id="n2"), msg("approve")])
    r = await await_decision(ws, "n1", timeout=1)
    assert r == GateResult("approve", "human") and ws.calls == 2


async def test_non_dict_ignored_and_logged(caplog):
    ws = FakeWebSocket(["approve", ["x"], None, 5, msg("approve")])
    with caplog.at_level(logging.WARNING):
        r = await await_decision(ws, "n1", timeout=1)
    assert r == GateResult("approve", "human") and ws.calls == 5
    assert any(rec.levelno == logging.WARNING for rec in caplog.records)


async def test_ignored_only_then_timeout_denies():
    ws = FakeWebSocket([msg("approve", node_id="zzz")])
    r = await await_decision(ws, "n1", timeout=0.05)
    assert r == GateResult("deny", "timeout")


async def test_timeout_when_silent():
    r = await await_decision(FakeWebSocket(["HANG"]), "n1", timeout=0.05)
    assert r == GateResult("deny", "timeout")


async def test_timeout_is_total_not_per_receive():
    class Drip:
        async def receive_json(self):
            await asyncio.sleep(0.03)
            return {"event": "noise"}

    loop = asyncio.get_running_loop()
    t0 = loop.time()
    r = await await_decision(Drip(), "n1", timeout=0.15)
    assert r == GateResult("deny", "timeout")
    assert loop.time() - t0 < 0.5


async def test_none_timeout_waits_for_message():
    async def late():
        class WS:
            async def receive_json(self):
                await asyncio.sleep(0.1)
                return msg("approve")

        return await await_decision(WS(), "n1", timeout=None)

    assert (await late()).decision == "approve"


async def test_disconnect_propagates():
    ws = FakeWebSocket([WebSocketDisconnect(1000)])
    with pytest.raises(WebSocketDisconnect):
        await await_decision(ws, "n1", timeout=1)


async def test_other_exception_propagates():
    ws = FakeWebSocket([RuntimeError("boom")])
    with pytest.raises(RuntimeError, match="boom"):
        await await_decision(ws, "n1", timeout=1)


def test_result_frozen():
    r = GateResult("deny", "timeout")
    with pytest.raises(Exception):
        r.decision = "approve"


def test_default_timeout_is_float():
    assert isinstance(GATE_TIMEOUT_S, float)


def test_ledger_claim_once_only():
    led = DecisionLedger()
    assert led.claim("a") is True
    assert led.claim("a") is False
    assert led.claim("b") is True
    assert DecisionLedger().claim("a") is True  # no shared module state
