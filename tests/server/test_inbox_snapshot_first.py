"""Regression: a UI that connects while the hub is busy (slow history read) must still receive its snapshot BEFORE any broadcast.
Found as a ~50% flaky test: ui_connected() registered the UI for broadcasts before it had sent the snapshot."""
import asyncio
import time

import inbox_hub


class WS:
    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)

    async def close(self, code=1000):
        pass


class SlowStore:
    def recent_resolved(self, n):          # runs in a worker thread
        time.sleep(0.3)
        return [{"session_id": "s", "call_id": "c", "decision": "deny", "reason": "human"}]


async def test_snapshot_is_the_first_frame_even_if_a_broadcast_happens_during_registration():
    hub = inbox_hub.InboxHub(gate_timeout=5, store=SlowStore())
    ws = WS()
    connecting = asyncio.create_task(hub.ui_connected(ws))
    await asyncio.sleep(0.05)                                            # the UI is registered, the history read is still running
    await hub._broadcast({"event": "inbox_session", "session_id": "s", "state": "closed"})
    await connecting
    await asyncio.sleep(0.05)
    assert [m["event"] for m in ws.sent][:2] == ["inbox_snapshot", "inbox_session"], ws.sent
    assert ws.sent[0]["recent"] and ws.sent[0]["recent"][0]["call_id"] == "c"


async def test_a_ui_whose_snapshot_cannot_be_sent_is_dropped_and_not_left_registered():
    class Broken(WS):
        async def send_json(self, payload):
            raise ConnectionError("gone")

    hub = inbox_hub.InboxHub(gate_timeout=5)
    ui = await hub.ui_connected(Broken())
    assert ui.dead and ui not in hub._uis
