"""Enforcement boundary (EB2): sandboxed servers, per-call workers, just-in-time secrets, boundary/secrets_used frames.

Real processes: the real proxy, the real trampoline, a real downstream (fake_downstream_probe.py). Tests that need kernel
features this host lacks are skipped with a reason.
"""
import asyncio
import glob
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

import pytest

from sentinel_proxy import sandbox
from sentinel_proxy.config import ConfigError, parse_config

from conftest import ROOT, agent, make_config
from test_proxy_integration import _raw_agent

PROBE_SERVER = str(Path(__file__).with_name("fake_downstream_probe.py"))
HERE = str(Path(__file__).resolve().parent)
_P = sandbox.probe()
CAN_SANDBOX = _P["landlock_abi"] >= 1 and (_P["unshare_net"] or _P["landlock_abi"] >= 4)
needs_sandbox = pytest.mark.skipif(not CAN_SANDBOX, reason=f"host cannot enforce the sandbox (probe={_P})")
SECRET = "TOPSECRET-value-8c1f"


def text(res):
    return "".join(c.text for c in res.content)


def sbx_dirs():
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "sentinel-sbx-*")))


def pids(pidfile):
    return [int(x) for x in pidfile.read_text().split()] if pidfile.exists() else []


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:  # a zombie still answers kill(0)
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


async def wait_until(fn, timeout=15):
    t0 = time.monotonic()
    while not fn():
        if time.monotonic() - t0 > timeout:
            return False
        await asyncio.sleep(0.05)
    return True


def server_cfg(tmp_path, *, network="none", **over):
    allowed = tmp_path / "allowed"
    allowed.mkdir(exist_ok=True)
    pidfile = allowed / "pids.txt"
    sc = {"command": sys.executable, "args": [PROBE_SERVER], "env": {"FAKE_PID_FILE": str(pidfile)},
          "sandbox": {"read": [HERE], "write": [str(allowed)], "network": network, "env_allow": ["FAKE_PID_FILE"],
                      "require": True}}
    sc.update(over)
    return sc, allowed, pidfile


# ---------------------------------------------------------------------------- config validation

def base(**over):
    sc = {"command": "x", "sandbox": {"network": "none"}, "lifecycle": "per_call",
          "secrets": {"API_KEY": {"from_env": "HOST_KEY", "tools": ["t"]}}}
    sc.update(over)
    return {"servers": {"s": sc}}


def test_valid_boundary_config():
    c = parse_config(base()).servers["s"]
    assert c.lifecycle == "per_call" and c.call_timeout_s == 60.0 and c.secrets_for("t") == ["API_KEY"]
    assert c.secrets_for("other") == [] and c.sandbox["require"] is True


@pytest.mark.parametrize("over,msg", [
    ({"lifecycle": "session"}, "per_call"),
    ({"sandbox": None}, "require a \"sandbox\""),
    ({"lifecycle": "forever"}, "lifecycle"),
    ({"secrets": {"api_key": {"from_env": "H", "tools": ["t"]}}}, "secret name"),
    ({"secrets": {"A B": {"from_env": "H", "tools": ["t"]}}}, "secret name"),
    ({"secrets": {"K": {"from_env": "H", "tools": []}}}, "tools"),
    ({"secrets": {"K": {"from_env": "H", "tools": [""]}}}, "tools"),
    ({"secrets": {"K": {"from_env": "H", "tools": "t"}}}, "tools"),
    ({"secrets": {"K": {"from_env": "H=1", "tools": ["t"]}}}, "from_env"),
    ({"secrets": {"K": {"from_env": "H", "tools": ["t"], "extra": 1}}}, "exactly"),
    ({"secrets": []}, "secrets"),
    ({"call_timeout_s": 0}, "call_timeout_s"),
    ({"call_timeout_s": 601}, "call_timeout_s"),
    ({"call_timeout_s": True}, "call_timeout_s"),
    ({"call_timeout_s": "5"}, "call_timeout_s"),
    ({"sandbox": {"bogus": 1}}, "servers.s.sandbox"),
    ({"sandbox": {"network": "everywhere"}}, "servers.s.sandbox"),
    ({"sandbox": {"write": ["relative"]}}, "servers.s.sandbox"),
])
def test_invalid_boundary_config(over, msg):
    with pytest.raises(ConfigError, match=msg):
        parse_config(base(**over))


def test_timeout_bounds_accepted():
    assert parse_config(base(call_timeout_s=1)).servers["s"].call_timeout_s == 1.0
    assert parse_config(base(call_timeout_s=600)).servers["s"].call_timeout_s == 600.0


# ---------------------------------------------------------------------------- hello / frames

async def test_unsandboxed_server_boundary_and_empty_secrets_used(tmp_path, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg) as s:
        await s.call_tool("echo", {})
    assert backend.of("proxy_hello")[0]["boundary"] == {
        "fs": {"lifecycle": "session", "layers": [], "missing": [], "network": "host", "secrets": []}}
    assert backend.of("proxy_call")[0]["secrets_used"] == []


@needs_sandbox
async def test_session_sandbox_enforced_for_real(tmp_path, backend):
    sc, allowed, pidfile = server_cfg(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    before = sbx_dirs()
    try:
        async with agent(cfg, {"CANARY_PROXY_ENV": "canary-value"}) as s:
            who = json.loads(text(await s.call_tool("whoami_env", {})))
            outside = json.loads(text(await s.call_tool("try_write", {"path": str(tmp_path / "outside.txt")})))
            inside = json.loads(text(await s.call_tool("try_write", {"path": str(allowed / "in.txt")})))
            net = json.loads(text(await s.call_tool("try_net", {"port": port})))
    finally:
        listener.close()
    assert "CANARY_PROXY_ENV" not in who["env_names"] and "FAKE_PID_FILE" in who["env_names"]
    assert outside["write"].startswith("err:") and not (tmp_path / "outside.txt").exists()
    assert inside["write"] == "ok" and (allowed / "in.txt").exists()
    assert net["net"].startswith("err:"), net  # network none: the listener is unreachable
    b = backend.of("proxy_hello")[0]["boundary"]["p"]
    assert b["lifecycle"] == "session" and b["network"] == "none" and b["missing"] == [] and b["secrets"] == []
    assert "landlock_fs" in b["layers"] and "env" in b["layers"] and ("netns" in b["layers"] or "landlock_net" in b["layers"])
    assert await wait_until(lambda: not any(alive(p) for p in pids(pidfile)))
    assert sbx_dirs() <= before, "private HOME of the session server was not removed"


# ---------------------------------------------------------------------------- per-call workers and secrets

def secret_server(tmp_path, **over):
    sc, allowed, pidfile = server_cfg(
        tmp_path, lifecycle="per_call",
        secrets={"API_KEY": {"from_env": "HOST_API_KEY", "tools": ["whoami_env"]}}, **over)
    sc["sandbox"]["env_allow"] = ["FAKE_PID_FILE"]  # the secret is NOT listed: the proxy adds it for the one call only
    return sc, allowed, pidfile


@needs_sandbox
async def test_secret_only_for_listed_tool_only_during_call_and_never_leaks(tmp_path, backend):
    sc, _, pidfile = secret_server(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    errfile = tmp_path / "proxy.stderr"
    before = sbx_dirs()
    with open(errfile, "w") as el:
        async with agent(cfg, {"HOST_API_KEY": SECRET, "CANARY_PROXY_ENV": "c"}, errlog=el) as s:
            assert sorted(t.name for t in (await s.list_tools()).tools) == sorted(
                ["whoami_env", "whoami_env2", "try_write", "try_net", "sleep"])
            assert len(pids(pidfile)) == 1 and not await wait_until(lambda: alive(pids(pidfile)[0]), 0.5)  # startup worker closed
            first = json.loads(text(await s.call_tool("whoami_env", {"secret_var": "API_KEY"})))
            second = json.loads(text(await s.call_tool("whoami_env2", {"secret_var": "API_KEY"})))
            third = json.loads(text(await s.call_tool("whoami_env", {})))
            await backend.wait_for("proxy_result", n=3)
    assert first["secret"] == SECRET and "API_KEY" in first["env_names"]
    assert second["secret"] is None and "API_KEY" not in second["env_names"]
    assert "CANARY_PROXY_ENV" not in first["env_names"] and "HOST_API_KEY" not in first["env_names"]
    assert third["secret"] is None
    hello = backend.of("proxy_hello")[0]["boundary"]["p"]
    assert hello["lifecycle"] == "per_call" and hello["secrets"] == ["API_KEY"] and hello["network"] == "none"
    assert "landlock_fs" in hello["layers"]
    calls = backend.of("proxy_call")
    assert [(c["tool"], c["secrets_used"]) for c in calls] == [
        ("whoami_env", ["API_KEY"]), ("whoami_env2", []), ("whoami_env", ["API_KEY"])]
    assert len(pids(pidfile)) == 4  # startup worker + one fresh worker per approved call
    assert await wait_until(lambda: not any(alive(p) for p in pids(pidfile))), "a worker outlived its call"
    assert sbx_dirs() <= before, "worker HOME dirs left behind"
    # names only in frames; the value never reaches the hub or our stderr
    assert SECRET not in json.dumps(backend.frames)
    results = backend.of("proxy_result")
    assert all(r["status"] == "ok" for r in results) and "[REDACTED]" in results[0]["summary"]
    err = errfile.read_text()
    assert SECRET not in err and "[REDACTED]" in err  # the worker printed the value on stderr; the proxy scrubbed it


@needs_sandbox
async def test_missing_host_secret_denies_and_starts_no_worker(tmp_path, backend):
    sc, _, pidfile = secret_server(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    env = {"HOST_API_KEY": ""}  # present but empty counts as missing
    async with agent(cfg, env) as s:
        res = await s.call_tool("whoami_env", {"secret_var": "API_KEY"})
        await backend.wait_for("proxy_result")
        res2 = await s.call_tool("whoami_env2", {})  # unlisted tool needs no secret: runs fine
    assert res.is_error and text(res) == "Denied by SENTINEL: secret_unavailable"
    r = backend.of("proxy_result")[0]
    assert r["status"] == "error" and "secret_unavailable" in r["summary"]
    assert not res2.is_error
    assert len(pids(pidfile)) == 2  # startup worker + the second call only


@needs_sandbox
async def test_call_timeout_kills_worker(tmp_path, backend):
    sc, _, pidfile = secret_server(tmp_path, call_timeout_s=1)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    before = sbx_dirs()
    async with agent(cfg, {"HOST_API_KEY": SECRET}) as s:
        t0 = time.monotonic()
        res = await asyncio.wait_for(s.call_tool("sleep", {"seconds": 60}), 30)
        took = time.monotonic() - t0
    assert res.is_error and "worker timed out" in text(res) and took < 20
    assert backend.of("proxy_result")[0]["status"] == "error"
    assert await wait_until(lambda: not any(alive(p) for p in pids(pidfile)))
    assert sbx_dirs() <= before


@needs_sandbox
async def test_agent_cancel_kills_worker(tmp_path, backend):
    sc, _, pidfile = secret_server(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    proc, send = await _raw_agent(cfg, {"HOST_API_KEY": SECRET})
    try:
        await send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "sleep", "arguments": {"seconds": 60}}})
        assert await wait_until(lambda: len(pids(pidfile)) == 2), "worker never started"
        worker = pids(pidfile)[1]
        assert alive(worker)
        await send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}})
        assert await wait_until(lambda: not alive(worker), 20), "worker survived the agent's cancel"
    finally:
        proc.kill()
        await proc.wait()


@needs_sandbox
async def test_denied_call_starts_no_worker(tmp_path, backend):
    backend.on_call = backend.deny
    sc, _, pidfile = secret_server(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    async with agent(cfg, {"HOST_API_KEY": SECRET}) as s:
        res = await s.call_tool("whoami_env", {"secret_var": "API_KEY"})
    assert res.is_error and len(pids(pidfile)) == 1  # startup worker only
    assert backend.of("proxy_call")[0]["secrets_used"] == ["API_KEY"]  # the human saw the grant before deciding


@needs_sandbox
async def test_no_sandbox_home_dirs_left_after_many_calls(tmp_path, backend):
    sc, _, _ = secret_server(tmp_path)
    cfg, _ = make_config(tmp_path, backend.url, servers={"p": sc})
    before = sbx_dirs()
    async with agent(cfg, {"HOST_API_KEY": SECRET}) as s:
        for _ in range(4):
            assert not (await s.call_tool("whoami_env2", {})).is_error
    assert sbx_dirs() <= before


# ---------------------------------------------------------------------------- fail closed

async def test_unenforceable_boundary_refuses_start_exit_4_and_server_never_runs(tmp_path, monkeypatch, capsys):
    from sentinel_proxy.cli import serve
    monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 0, "unshare_net": False})
    sc, _, pidfile = server_cfg(tmp_path)
    cfg = parse_config({"servers": {"p": sc}, "backend": "ws://127.0.0.1:9/x"})
    assert await serve(cfg) == 4
    assert "landlock_fs" in capsys.readouterr().err and not pidfile.exists()


async def test_require_false_is_not_refused_by_the_precheck(tmp_path, monkeypatch):
    from sentinel_proxy.proxy import check_feasible
    monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 0, "unshare_net": False})
    check_feasible("p", {"network": "none", "require": False})  # no raise
    from sentinel_proxy.proxy import SandboxRefused
    with pytest.raises(SandboxRefused):
        check_feasible("p", {"network": "none", "require": True})
    with pytest.raises(SandboxRefused):
        monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 1, "unshare_net": False})
        check_feasible("p", {"network": "loopback", "require": True})
