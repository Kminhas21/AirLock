"""A policy approval with `confine` runs in a fresh, kernel-confined worker (DECISIONS D31), in-process: the real Proxy, real sandboxed
downstream processes, a scripted hub link. A session server keeps its own process for human approvals; an auto-allowed path call never
reaches it. A worker whose status does not prove the confinement is killed before `call_tool`."""
import json
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import pytest

from sentinel_proxy import confine, sandbox
from sentinel_proxy.backend import Decision
from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy
from tests.no_skip_plugin import sandbox_skipif

pytestmark = [pytest.mark.slow,  # GATE_TIER=pr: real sandboxed processes (docs/TESTING_REALITY.md "CI tiers")
              sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok() or not sandbox.probe()["unshare_net"],
                             reason="confined workers need Landlock, openat2 and a network namespace on this host")]

HERE = Path(__file__).resolve().parent
PROBE = str(HERE / "fake_downstream_probe.py")
LOG = str(HERE / "fake_downstream.py")


class Link:
    """The hub: every call gets `decision`; frames and results are recorded."""

    def __init__(self, decision):
        self.decision, self.frames, self.results = decision, [], []

    async def decide(self, frame):
        self.frames.append(frame)
        return self.decision(frame) if callable(self.decision) else self.decision

    async def send_result(self, call_id, status, summary):
        self.results.append((call_id, status, summary))


POLICY_READ = Decision(True, "policy", confine={"path": "read"})
HUMAN = Decision(True, "human")


def cfg(w, lifecycle="session", runtime=True, command=sys.executable, args=(PROBE,)):
    sb = {"read": [str(w)], "runtime": [str(HERE)], "network": "none"} if runtime else {"read": [str(w), str(HERE)], "network": "none"}
    return parse_config({"servers": {"fs": {"command": command, "args": list(args), "sandbox": sb, "lifecycle": lifecycle}}})


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a.txt").write_text("A")
    (d / "b.txt").write_text("B")
    (d / "notes.txt").symlink_to(d / "b.txt")
    return d


async def call(proxy, tool, args):
    res = await proxy.call(tool, args)
    text = " ".join(c.text for c in res.content)
    try:
        return res.is_error, json.loads(text)
    except ValueError:
        return res.is_error, text


async def running(c, link):
    stack = AsyncExitStack()
    p = Proxy(c, link)
    await stack.__aenter__()
    await p.start_downstreams(stack)
    return p, stack


@pytest.mark.parametrize("lifecycle", ["session", "per_call"])
async def test_an_auto_allowed_path_call_runs_in_a_fresh_worker_that_reads_only_the_named_file(w, lifecycle):
    link = Link(lambda f: POLICY_READ if f["call_id"] != "human" else HUMAN)
    p, stack = await running(cfg(w, lifecycle), link)
    try:
        link.decision = HUMAN
        _, human = await call(p, "read_path", {"path": str(w / "a.txt"), "also": str(w / "b.txt")})
        link.decision = POLICY_READ
        err, auto = await call(p, "read_path", {"path": str(w / "a.txt"), "also": str(w / "b.txt")})
        _, auto2 = await call(p, "read_path", {"path": str(w / "a.txt")})
    finally:
        await stack.aclose()
    assert human["path"] == "ok:A" and human["also"] == "ok:B"              # the server's own sandbox: read [w]
    assert not err and auto["path"] == "ok:A" and auto["also"] == "err:EACCES"  # the narrowed spec: only the named file
    assert auto["pid"] != auto2["pid"] and (lifecycle == "per_call" or auto["pid"] != human["pid"])
    assert link.frames[0]["confinable"] is True and "resolved" not in link.frames[0]


async def test_a_symlinked_name_gets_no_grant_even_when_the_hub_allows_it(w):
    p, stack = await running(cfg(w), Link(POLICY_READ))
    try:
        err, out = await call(p, "read_path", {"path": str(w / "notes.txt")})
        frame = p.link.frames[0]
    finally:
        await stack.aclose()
    assert out["path"] == "err:EACCES"
    assert frame["confinable"] is False and frame["links"] == {"path": str(w / "b.txt")}


async def test_a_worker_whose_status_does_not_prove_the_confinement_is_killed_before_call_tool(w, tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    c = parse_config({"servers": {"fs": {"command": sys.executable, "args": [LOG], "env": {"FAKE_DOWNSTREAM_LOG": str(log)},
                                         "sandbox": {"read": [str(w)], "runtime": [str(HERE)], "network": "none",
                                                     "env_allow": ["FAKE_DOWNSTREAM_LOG"], "write": [str(tmp_path)]}}}})
    p, stack = await running(c, Link(POLICY_READ))
    real = sandbox.sandbox_params
    try:
        # from here on, workers start WITHOUT the trampoline: no status line, no Landlock
        monkeypatch.setattr(sandbox, "sandbox_params", lambda spec, cmd, args, env=None: (cmd, list(args), dict(env or {})))
        err, out = await call(p, "read_file", {"path": str(w / "a.txt")})
    finally:
        monkeypatch.setattr(sandbox, "sandbox_params", real)
        await stack.aclose()
    assert err and out == "Denied by SENTINEL: confine_failed", out
    assert not log.exists() or "read_file" not in log.read_text()          # call_tool was never sent
    assert p.link.results[-1][1:] == ("error", "confine_failed")


async def test_a_policy_approval_of_a_path_call_without_confine_is_refused(w, tmp_path):
    p, stack = await running(cfg(w), Link(Decision(True, "policy")))
    try:
        err, out = await call(p, "read_path", {"path": str(w / "a.txt")})
        err2, out2 = await call(p, "whoami_env2", {})                            # no path value: the session serves it
    finally:
        await stack.aclose()
    assert err and out == "Denied by SENTINEL: unconfined"
    assert not err2 and "env_names" in out2


async def test_a_server_that_cannot_be_confined_never_runs_a_confined_call_unconfined(w):
    p, stack = await running(cfg(w, runtime=False), Link(POLICY_READ))
    try:
        err, out = await call(p, "read_path", {"path": str(w / "a.txt")})
        frame = p.link.frames[0]
        b = p.boundary()["fs"]
    finally:
        await stack.aclose()
    assert err and out == "Denied by SENTINEL: confine_failed"
    assert frame["confinable"] is False
    assert b["confinable"] is False and b["confine_why"] == "no sandbox.runtime"
