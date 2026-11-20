"""The proxy's confined-call FAILURE paths (phase 1 of the "narrow write right" plan). For a read, a worker that dies or times out is just an
error; for a write it may have happened already, so these pin what is reported, that nothing is retried, and that no worker is reused:

  * a worker that times out: one result "worker timed out" (an error, NOT a denial), the call_tool sent once, no retry, the process gone;
  * a worker whose tool raises an MCP error / is_error / crashes mid-call: one error result, the secret scrubbed, the process gone;
  * at most once: one call = one hub decision, one worker, one call_tool, one result; a denied call spawns nothing;
  * no reuse: the next confined call runs in a different, fresh process (also after a timeout and after a crash);
  * a session server that dies mid-session is marked dead and later calls are refused without asking the hub;
  * a required sandbox that reports no status is refused at startup (the unit cases of `_check_status` are in test_proxy_check_status.py).

In-process: the real Proxy, real sandboxed processes, a scripted hub link (tests/proxy/test_confined_call.py is the template)."""
import asyncio
import os
import re
import sys
import time
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import pytest

from mcp.shared.exceptions import MCPError

from sentinel_proxy import sandbox
from sentinel_proxy.backend import Decision
from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy, SandboxRefused
from tests.no_skip_plugin import sandbox_skipif

HERE = Path(__file__).resolve().parent
FAIL = str(HERE / "fake_downstream_fail.py")

pytestmark = [pytest.mark.slow,  # GATE_TIER=pr: real sandboxed processes (docs/TESTING_REALITY.md "CI tiers")
              sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok() or not sandbox.probe()["unshare_net"],
                             reason="confined workers need Landlock, openat2 and a network namespace on this host")]

POLICY_READ = Decision(True, "policy", confine={"path": "read"})
HUMAN = Decision(True, "human")


class Link:
    def __init__(self, decision):
        self.decision, self.frames, self.results = decision, [], []

    async def decide(self, frame):
        self.frames.append(frame)
        return self.decision(frame) if callable(self.decision) else self.decision

    async def send_result(self, call_id, status, summary):
        self.results.append((call_id, status, summary))


def cfg(w, lifecycle="session", call_timeout_s=60, **extra):
    """`call_timeout_s` covers the worker's START (trampoline, initialize, status) as well as the call: the timeout tests use 4 s, not the minimum
    1 s, so a loaded host cannot time the worker out before `call_tool` is even sent."""
    server = {"command": sys.executable, "args": [FAIL], "lifecycle": lifecycle, "call_timeout_s": call_timeout_s,
              "sandbox": {"read": [str(w)], "runtime": [str(HERE)], "network": "none"}, **extra}
    return parse_config({"servers": {"fs": server}})


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a.txt").write_text("A")
    return d


class Spy:
    """Counts what the proxy does: every spawned process (with its stderr tap) and every call_tool it sends."""

    def __init__(self, proxy):
        self.spawns, self.calls = [], []
        original = proxy.open_session

        @asynccontextmanager
        async def wrapped(sc, **kw):
            async with original(sc, **kw) as (session, tap):
                self.spawns.append((kw.get("label"), kw.get("spec") is not None, tap))
                real = session.call_tool

                async def call_tool(name, args, *a, **k):
                    self.calls.append(name)
                    return await real(name, args, *a, **k)
                session.call_tool = call_tool
                yield session, tap
        proxy.open_session = wrapped

    def workers(self):
        return [tap for _label, confined, tap in self.spawns if confined]

    @staticmethod
    def pid(tap):
        m = [re.fullmatch(r"PID (\d+)", ln) for ln in tap.tail]
        got = [int(x.group(1)) for x in m if x]
        assert got, tap.tail
        return got[0]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ")[1][0] != "Z"      # a zombie is dead
    except OSError:
        return False


async def gone(pid, within=5.0):
    end = time.monotonic() + within
    while time.monotonic() < end:
        if not alive(pid):
            return True
        await asyncio.sleep(0.05)
    return not alive(pid)


async def running(c, link):
    stack = AsyncExitStack()
    p = Proxy(c, link)
    await stack.__aenter__()
    await p.start_downstreams(stack)
    return p, stack


def text(res):
    return " ".join(c.text for c in res.content)


# --------------------------------------------------------------------------- timeout


@pytest.mark.parametrize("lifecycle", ["session", "per_call"])
async def test_a_timed_out_confined_worker_is_an_error_not_a_denial_run_once_and_gone(w, lifecycle):
    p, stack = await running(cfg(w, lifecycle, call_timeout_s=4), Link(POLICY_READ))
    spy = Spy(p)
    try:
        t0 = time.monotonic()
        res = await p.call("hang", {"path": str(w / "a.txt"), "seconds": 60})
        took = time.monotonic() - t0
        [tap] = spy.workers()
        pid = Spy.pid(tap)
        assert await gone(pid), "the timed-out worker is still running"       # barrier: the call has returned and the worker is dead; the spy counts below show no retry
    finally:
        await stack.aclose()
    assert res.is_error and took < 20
    assert text(res) == "Downstream server 'fs': worker timed out"       # an error the agent may report; NOT "Denied by SENTINEL"
    assert [(c, s, m) for c, s, m in p.link.results] == [(p.link.frames[0]["call_id"], "error", "worker timed out")]
    assert len(p.link.frames) == 1 and spy.calls == ["hang"] and len(spy.workers()) == 1       # at most once: no retry, no second worker


async def test_after_a_timeout_the_next_confined_call_gets_a_fresh_process(w):
    p, stack = await running(cfg(w, call_timeout_s=4), Link(POLICY_READ))
    spy = Spy(p)
    try:
        await p.call("hang", {"path": str(w / "a.txt"), "seconds": 60})
        res = await p.call("pid", {"path": str(w / "a.txt")})
        first, second = (Spy.pid(t) for t in spy.workers())
        assert await gone(first)
    finally:
        await stack.aclose()
    assert not res.is_error and text(res) == f"pid={second}" and first != second
    assert spy.calls == ["hang", "pid"] and [r[1] for r in p.link.results] == ["error", "ok"]
    await_pid_gone = not alive(second)
    assert await_pid_gone


# --------------------------------------------------------------------------- the tool fails


async def test_a_tool_that_returns_is_error_is_one_error_result_and_the_worker_is_gone(w):
    p, stack = await running(cfg(w), Link(POLICY_READ))
    spy = Spy(p)
    try:
        res = await p.call("tool_error", {"path": str(w / "a.txt")})
        [tap] = spy.workers()
        assert await gone(Spy.pid(tap))
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "the tool says no"
    assert [(s, m) for _c, s, m in p.link.results] == [("error", "the tool says no")] and spy.calls == ["tool_error"]


async def test_an_mcp_error_raised_by_a_confined_worker_reaches_the_agent_and_the_hub_with_its_message(w):
    """The worker's JSON-RPC error is raised inside the transport's task group (an ExceptionGroup); `_call_worker` unwraps it, so the agent
    and the hub get the real MCP message. An error, not a denial; once; the worker gone."""
    p, stack = await running(cfg(w), Link(POLICY_READ))
    spy = Spy(p)
    try:
        res = await p.call("boom_mcp", {"path": str(w / "a.txt")})
        [tap] = spy.workers()
        assert await gone(Spy.pid(tap))
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Downstream server 'fs' returned an error: bad things happened"
    assert [(s, m) for _c, s, m in p.link.results] == [("error", "bad things happened")] and spy.calls == ["boom_mcp"]
    assert not text(res).startswith("Denied by SENTINEL")


async def test_the_result_summary_sent_to_the_hub_is_scrubbed_of_the_calls_secret(w, monkeypatch):
    monkeypatch.setenv("HOST_API_KEY", "s3cr3t-value-123")
    c = cfg(w, "per_call", secrets={"API_KEY": {"from_env": "HOST_API_KEY", "tools": ["echo_secret"]}})
    p, stack = await running(c, Link(POLICY_READ))
    try:
        res = await p.call("echo_secret", {"path": str(w / "a.txt")})
    finally:
        await stack.aclose()
    assert not res.is_error and "key=" in text(res)
    assert "s3cr3t-value-123" not in repr(p.link.results) and p.link.results[0][1:] == ("ok", "key=[REDACTED]")


async def test_a_confined_worker_that_crashes_mid_call_is_an_error_run_once_and_the_next_call_is_fresh(w):
    p, stack = await running(cfg(w), Link(POLICY_READ))
    spy = Spy(p)
    try:
        t0 = time.monotonic()
        res = await p.call("crash", {"path": str(w / "a.txt")})
        took = time.monotonic() - t0
        nxt = await p.call("pid", {"path": str(w / "a.txt")})
        crashed, fresh = (Spy.pid(t) for t in spy.workers())
        assert await gone(crashed)
    finally:
        await stack.aclose()
    assert res.is_error and took < 20
    assert text(res) == "Downstream server 'fs' returned an error: Connection closed"          # the real message, unwrapped
    assert not text(res).startswith("Denied by SENTINEL")
    assert p.link.results[0][1:] == ("error", "Connection closed")
    assert spy.calls == ["crash", "pid"] and crashed != fresh and text(nxt) == f"pid={fresh}"
    assert [r[1] for r in p.link.results] == ["error", "ok"] and len(p.link.frames) == 2


@pytest.mark.parametrize("exc, shown, summary", [
    (MCPError(-32602, "nope s3cr3t-value-123"), "Downstream server 'fs' returned an error: nope [REDACTED]", "nope [REDACTED]"),
    (TimeoutError(), "Downstream server 'fs': worker timed out", "worker timed out"),
    (RuntimeError("boom s3cr3t-value-123"), "Downstream server 'fs' failed: RuntimeError", "worker failed: RuntimeError"),
])
async def test_what_the_worker_session_itself_raises_is_one_error_result_scrubbed_and_never_a_denial(w, monkeypatch, exc, shown, summary):
    """The three handlers around the worker session (an MCP error, a timeout that escapes the inner guard, anything else) are reached when the
    SESSION raises; the SDK reports a tool's own JSON-RPC error as an ExceptionGroup instead (see the unwrapping test above). Each reports once,
    as an error, and keeps the call's secret out of what the agent and the hub are told."""
    monkeypatch.setenv("HOST_API_KEY", "s3cr3t-value-123")
    c = cfg(w, "per_call", secrets={"API_KEY": {"from_env": "HOST_API_KEY", "tools": ["pid"]}})
    p, stack = await running(c, Link(POLICY_READ))
    calls = []

    @asynccontextmanager
    async def raising(sc, **kw):
        calls.append(kw.get("spec") is not None)
        raise exc
        yield                                                          # pragma: no cover

    p.open_session = raising
    try:
        res = await p.call("pid", {"path": str(w / "a.txt")})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == shown and "s3cr3t" not in text(res)
    assert [(s, m) for _c, s, m in p.link.results] == [("error", summary)] and calls == [True]
    assert not text(res).startswith("Denied by SENTINEL")


# --------------------------------------------------------------------------- at most once / no reuse


async def test_every_confined_call_is_one_decision_one_worker_one_call_tool_one_result(w):
    p, stack = await running(cfg(w), Link(POLICY_READ))
    spy = Spy(p)
    try:
        outs = [await p.call("pid", {"path": str(w / "a.txt")}) for _ in range(3)]
        pids = [Spy.pid(t) for t in spy.workers()]
        for pid in pids:
            assert await gone(pid)
    finally:
        await stack.aclose()
    assert len(pids) == 3 and len(set(pids)) == 3 and [text(o) for o in outs] == [f"pid={x}" for x in pids]
    assert len(p.link.frames) == 3 and len({f["call_id"] for f in p.link.frames}) == 3
    assert [r[0] for r in p.link.results] == [f["call_id"] for f in p.link.frames]          # one result per call, in order
    assert spy.calls == ["pid"] * 3 and len(spy.spawns) == 3


async def test_a_denied_confined_call_spawns_nothing_and_a_session_call_never_uses_a_worker(w):
    link = Link(Decision(False, "human"))
    p, stack = await running(cfg(w), link)
    spy = Spy(p)
    try:
        denied = await p.call("pid", {"path": str(w / "a.txt")})
        link.decision = HUMAN                                              # a human approval: the session process, no worker
        human = await p.call("pid", {"path": str(w / "a.txt")})
        link.decision = POLICY_READ
        auto = await p.call("pid", {"path": str(w / "a.txt")})
    finally:
        await stack.aclose()
    assert denied.is_error and text(denied) == "Denied by SENTINEL: human" and p.link.results[0][1] == "ok"
    assert len(spy.workers()) == 1 and spy.calls == ["pid"]               # one worker, one call_tool; the human call used the session process
    assert text(human) != text(auto) and text(auto) == f"pid={Spy.pid(spy.workers()[0])}"       # different processes
    assert [r[1] for r in p.link.results] == ["ok", "ok"]


async def test_a_confined_worker_cannot_write_where_the_hub_said_read(w):
    """The tool that writes its path: the narrowed spec gives the named file READ_FILE only (phase 1: no write right exists)."""
    p, stack = await running(cfg(w), Link(POLICY_READ))
    try:
        named = await p.call("try_write", {"path": str(w / "a.txt")})
        new = await p.call("try_write", {"path": str(w / "new.txt")})
    finally:
        await stack.aclose()
    assert text(named) == "write:errno=13" and text(new) == "write:errno=13"
    assert (w / "a.txt").read_text() == "A" and not (w / "new.txt").exists()


# --------------------------------------------------------------------------- a session server that died


async def test_a_session_server_that_crashes_mid_call_is_marked_dead_and_later_calls_never_reach_the_hub(w):
    """The SDK reports a dead pipe as an MCP error ("Connection closed"): that is the downstream dying, so it is marked dead."""
    link = Link(HUMAN)
    p, stack = await running(cfg(w), link)
    try:
        first = await p.call("crash", {})
        dead, n_frames = p.downstreams["fs"].dead, len(link.frames)
        again = await p.call("pid", {})
        n_after = len(link.frames)
    finally:
        await stack.aclose()
    assert first.is_error and text(first) == "Downstream server 'fs' returned an error: Connection closed"
    assert dead is True and again.is_error and text(again) == "Downstream server 'fs' is not running" and n_after == n_frames == 1


async def test_an_ordinary_tool_error_from_a_session_server_does_not_mark_it_dead(w):
    link = Link(HUMAN)
    p, stack = await running(cfg(w), link)
    try:
        first = await p.call("boom_mcp", {})
        dead = p.downstreams["fs"].dead
        again = await p.call("pid", {})
    finally:
        await stack.aclose()
    assert first.is_error and text(first) == "Downstream server 'fs' returned an error: bad things happened"
    assert dead is False and not again.is_error and len(link.frames) == 2


async def test_a_downstream_whose_transport_fails_is_marked_dead_and_later_calls_never_reach_the_hub(w):
    link = Link(HUMAN)
    p, stack = await running(cfg(w), link)
    session = p.downstreams["fs"].session

    async def broken(*a, **k):
        raise OSError("pipe closed")
    session.call_tool = broken
    try:
        res = await p.call("pid", {})
        dead, n_frames = p.downstreams["fs"].dead, len(link.frames)
        later = await p.call("pid", {})
        n_after = len(link.frames)
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Downstream server 'fs' failed: OSError" and dead is True
    assert link.results == [(link.frames[0]["call_id"], "error", "downstream failed: OSError")]
    assert later.is_error and text(later) == "Downstream server 'fs' is not running"
    assert n_after == n_frames == 1                                         # the hub was not asked about a call that cannot run


async def test_a_session_servers_mcp_error_keeps_it_alive(w):
    link = Link(HUMAN)
    p, stack = await running(cfg(w), link)
    try:
        res = await p.call("boom_mcp", {})
        alive_after = not p.downstreams["fs"].dead
        ok = await p.call("pid", {})
    finally:
        await stack.aclose()
    assert res.is_error and "returned an error: bad things happened" in text(res) and alive_after and not ok.is_error
    assert link.results[0][1] == "error"


# --------------------------------------------------------------------------- startup


async def test_startup_refuses_a_required_sandbox_whose_worker_reports_no_status(w, monkeypatch):
    """A downstream started WITHOUT the trampoline (no status line) is refused when `require` is set, not used unconfined."""
    monkeypatch.setattr(sandbox, "sandbox_params", lambda spec, cmd, args, env=None: (cmd, list(args), dict(env or {})))
    p = Proxy(cfg(w), Link(HUMAN))
    stack = AsyncExitStack()
    await stack.__aenter__()
    try:
        with pytest.raises(SandboxRefused, match="reported no status"):
            await p.start_downstreams(stack)
    finally:
        await stack.aclose()
