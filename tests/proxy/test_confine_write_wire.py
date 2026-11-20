"""`write` on the wire (DECISIONS D32): a policy approval may carry `{"path": "write"}`; every other right is still refused (`invalid`), and a write
confine on a human approval is ignored. A decision that reaches `Proxy.call` anyway (a hub bug, a forged frame) for something the proxy did not
vouch for itself (`write_confinable`) starts no worker and the downstream never sees the call: tests/proxy/test_confined_call_write.py has the
full proxy path."""
import asyncio
import json

import pytest

from sentinel_proxy import backend


def decide(frame):
    link = backend.BackendLink("ws://x/proxy/ws", {})
    loop = asyncio.new_event_loop()
    try:
        fut = loop.create_future()
        link._pending["c1"] = fut
        link._on_frame(json.dumps({"event": "proxy_decision", "call_id": "c1", **frame}))
        return fut.result()
    finally:
        loop.close()


# --------------------------------------------------------------------------- the wire (no process)


@pytest.mark.parametrize("confine", [{"path": "WRITE"}, {"path": "read|write"}, {"path": "rw"}, {"path": ["write"]}, {"path": "create"},
                                     {"path": "truncate"}, {"path": "append"}, {"path": ""}, {"path": None}, {"path": "Write"}, {"path": " write"}])
def test_a_policy_approval_with_any_right_but_read_list_or_write_is_denied_invalid(confine):
    d = decide({"decision": "approve", "reason": "policy", "confine": confine})
    assert (d.approved, d.reason, d.confine) == (False, "invalid", None)


def test_the_closed_set_of_rights_on_the_wire_is_read_list_and_write():
    assert decide({"decision": "approve", "reason": "policy", "confine": {"p": "read", "q": "list"}}).confine == {"p": "read", "q": "list"}
    for right in ("read", "list", "write"):
        d = decide({"decision": "approve", "reason": "policy", "confine": {"p": right}})
        assert d.approved is True and d.confine == {"p": right}


def test_a_write_confine_on_a_human_approval_is_ignored_not_honoured():
    """Only a POLICY approval carries a confine map; on a human one it is dropped, so it can neither grant nor deny anything."""
    d = decide({"decision": "approve", "reason": "human", "confine": {"path": "write"}})
    assert (d.approved, d.reason, d.confine) == (True, "human", None)
    d = decide({"decision": "deny", "reason": "policy", "confine": {"path": "write"}})
    assert (d.approved, d.confine) == (False, None)


@pytest.mark.parametrize("confine", [{"path": "write"}, {"path": "write", "other": "read"}, {"a": "list", "b": "read", "c": "write"}])
def test_a_write_next_to_other_rights_is_carried_unchanged_the_proxy_decides_what_it_can_grant(confine):
    assert decide({"decision": "approve", "reason": "policy", "confine": confine}).confine == confine


@pytest.mark.asyncio
async def test_send_result_carries_writes_only_when_there_are_some():
    sent = []

    class WS:
        async def send(self, data):
            sent.append(json.loads(data))

    link = backend.BackendLink("ws://x/proxy/ws", {})
    link._ws, link._connected = WS(), True
    await link.send_result("c1", "ok", "done")
    await link.send_result("c2", "ok", "done", writes=[{"path": "/w/a.md"}])
    await link.send_result("c3", "ok", "done", writes=[])
    assert "writes" not in sent[0] and sent[1]["writes"] == [{"path": "/w/a.md"}] and "writes" not in sent[2]
