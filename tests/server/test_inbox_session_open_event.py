"""Regression (found by the browser boundary test): the live `inbox_session` open event must carry the session's servers and boundary, or a UI that is
already open shows a sandboxed session as 'unsandboxed'."""
import asyncio

import inbox_hub


class WS:
    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)

    async def close(self, code=1000):
        pass


BOUNDARY = {"fs": {"lifecycle": "per_call", "layers": ["env", "rlimit", "no_new_privs", "netns", "landlock_fs"], "missing": [],
                   "network": "none", "secrets": ["API_TOKEN"]}}


async def test_open_event_carries_servers_and_boundary_to_an_already_connected_ui():
    hub = inbox_hub.InboxHub(gate_timeout=5)
    ui_ws = WS()
    await hub.ui_connected(ui_ws)
    proxy_ws = WS()
    session = await hub.proxy_hello(proxy_ws, {"event": "proxy_hello", "session_id": "s1", "servers": ["fs"], "auto_approve": [], "boundary": BOUNDARY})
    assert session is not None
    await asyncio.sleep(0.1)
    opened = [m for m in ui_ws.sent if m.get("event") == "inbox_session" and m.get("state") == "open"]
    assert len(opened) == 1
    assert opened[0]["servers"] == ["fs"] and opened[0]["boundary"] == BOUNDARY


async def test_open_event_without_boundary_info_says_so_and_does_not_invent_one():
    hub = inbox_hub.InboxHub(gate_timeout=5)
    ui_ws = WS()
    await hub.ui_connected(ui_ws)
    await hub.proxy_hello(WS(), {"event": "proxy_hello", "session_id": "s2", "servers": ["fs"], "auto_approve": []})
    await asyncio.sleep(0.1)
    opened = [m for m in ui_ws.sent if m.get("event") == "inbox_session" and m.get("state") == "open"][0]
    assert opened["servers"] == ["fs"] and opened["boundary"] is None
