"""A call whose arguments exceed the hub's frame limit is denied LOCALLY with a clear reason; the link (and other pending calls) stay up."""
import asyncio

import pytest

from sentinel_proxy import backend
from sentinel_proxy.backend import BackendLink, TOO_LARGE
from server import inbox_hub


def test_the_proxy_and_hub_frame_limits_are_the_same_number():
    assert backend.MAX_FRAME_BYTES == inbox_hub.MAX_FRAME_BYTES


async def test_oversize_call_is_denied_without_touching_the_connection():
    link = BackendLink("ws://127.0.0.1:1/x", {"event": "proxy_hello"}, call_timeout_s=5, token=None)
    sent = []

    class WS:
        async def send(self, data):
            sent.append(data)

    link._ws, link._connected = WS(), True
    d = await link.decide({"event": "proxy_call", "call_id": "c1", "args": {"content": "x" * 1_200_000}})
    assert d.approved is False and d.reason == TOO_LARGE
    assert sent == [], "an oversize frame must never be sent (the hub would drop the link)"
    assert "c1" not in link._pending
