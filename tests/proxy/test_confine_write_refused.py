"""`write` is refused at the proxy layers too (phase 1 of the "narrow write right" plan; see tests/proxy/test_sandbox_grants_spec.py for the
sandbox side): the hub's decision on the wire, and a decision that reaches `Proxy.call` anyway (a hub bug, a forged frame) must not start a
worker that can write, and the downstream must never see the call."""
import asyncio
import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import pytest

from sentinel_proxy import backend, sandbox
from sentinel_proxy.backend import Decision
from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy
from tests.no_skip_plugin import sandbox_skipif

HERE = Path(__file__).resolve().parent
FAIL = str(HERE / "fake_downstream_fail.py")


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


@pytest.mark.parametrize("confine", [{"path": "write"}, {"path": "WRITE"}, {"path": "read|write"}, {"path": "rw"}, {"path": ["write"]},
                                     {"path": "read", "dest": "write"}, {"a": "list", "b": "read", "c": "write"}, {"path": "create"},
                                     {"path": "truncate"}, {"path": "append"}, {"path": ""}, {"path": None}])
def test_a_policy_approval_with_any_right_but_read_or_list_is_denied_invalid(confine):
    d = decide({"decision": "approve", "reason": "policy", "confine": confine})
    assert (d.approved, d.reason, d.confine) == (False, "invalid", None)


def test_the_closed_set_of_rights_on_the_wire_is_read_and_list():
    assert decide({"decision": "approve", "reason": "policy", "confine": {"p": "read", "q": "list"}}).confine == {"p": "read", "q": "list"}
    for right in ("read", "list"):
        assert decide({"decision": "approve", "reason": "policy", "confine": {"p": right}}).approved is True


def test_a_write_confine_on_a_human_approval_is_ignored_not_honoured():
    """Only a POLICY approval carries a confine map; on a human one it is dropped, so it can neither grant nor deny anything."""
    d = decide({"decision": "approve", "reason": "human", "confine": {"path": "write"}})
    assert (d.approved, d.reason, d.confine) == (True, "human", None)
    d = decide({"decision": "deny", "reason": "policy", "confine": {"path": "write"}})
    assert (d.approved, d.confine) == (False, None)


# --------------------------------------------------------------------------- a forged decision that reaches the proxy


class Link:
    def __init__(self, decision):
        self.decision, self.frames, self.results = decision, [], []

    async def decide(self, frame):
        self.frames.append(frame)
        return self.decision

    async def send_result(self, call_id, status, summary):
        self.results.append((call_id, status, summary))


@pytest.mark.slow
@sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok() or not sandbox.probe()["unshare_net"],
                reason="confined workers need Landlock, openat2 and a network namespace on this host")
@pytest.mark.parametrize("lifecycle", ["session", "per_call"])
async def test_a_write_decision_that_reaches_the_proxy_starts_no_worker_and_writes_nothing(tmp_path, lifecycle):
    w = tmp_path / "w"
    w.mkdir()
    (w / "a.txt").write_text("A")
    c = parse_config({"servers": {"fs": {"command": sys.executable, "args": [FAIL], "lifecycle": lifecycle,
                                         "sandbox": {"read": [str(w)], "runtime": [str(HERE)], "network": "none"}}}})
    link = Link(Decision(True, "policy", confine={"path": "write"}))
    stack = AsyncExitStack()
    p = Proxy(c, link)
    await stack.__aenter__()
    await p.start_downstreams(stack)
    seen = []
    original = p.open_session

    def spy(sc, **kw):
        seen.append(kw.get("spec"))
        return original(sc, **kw)
    p.open_session = spy
    try:
        res = await p.call("try_write", {"path": str(w / "a.txt")})
        res_new = await p.call("try_write", {"path": str(w / "new.txt")})
    finally:
        await stack.aclose()
    # the narrowed spec was refused by the sandbox before any process started: an error, never a successful write
    assert res.is_error and res_new.is_error
    assert "write:ok" not in " ".join(c_.text for c_ in res.content + res_new.content)
    assert (w / "a.txt").read_text() == "A" and not (w / "new.txt").exists()
    assert [r[1] for r in link.results] == ["error", "error"] and len(link.frames) == 2
    assert all(s is not None and s["grants"] and s["grants"][0][2] == "write" for s in seen)      # the proxy did pass `write` on: the sandbox said no
