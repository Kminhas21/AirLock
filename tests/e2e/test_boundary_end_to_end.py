"""Enforcement boundary, full stack, no mocks of our own code: real backend (token, working monitor) + real stdio proxy with a SANDBOXED per-call
downstream (Landlock + network namespace) holding a just-in-time secret + a human client on /inbox/ws. Proves what the operator sees (boundary, the
credentials warning data), what the sandbox enforces (no write outside, no network), and that the secret exists only inside the approved call."""
import asyncio
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest
import websockets

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("proxy_helpers", ROOT / "tests/proxy/conftest.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

PROBE = str(ROOT / "tests/proxy/fake_downstream_probe.py")
TOKEN = "e2e-secret-token"
SECRET = "sk-live-0123456789-VERY-SECRET"


def start_backend():
    port = H.free_port()
    env = {**os.environ, "SENTINEL_EMBEDDER": "minilm", "SENTINEL_MONITOR": "action_sim", "SENTINEL_GATE_TIMEOUT_S": "300", "OMP_NUM_THREADS": "1",
           "HF_HUB_OFFLINE": "1", "SENTINEL_WS_TOKEN": TOKEN}
    for k in ("SENTINEL_POLICY", "SENTINEL_EVENT_LOG"):
        env.pop(k, None)
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(port), "--log-level", "warning"],
                         cwd=ROOT / "server", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(400):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            return p, port
        except Exception:
            time.sleep(0.2)
    p.kill()
    raise RuntimeError("backend did not start")


@pytest.fixture
def backend():
    procs = []

    def make():
        p, port = start_backend()
        procs.append(p)
        return port

    yield make
    for p in procs:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=20)
        except Exception:
            p.kill()
            p.wait()


async def next_event(ws, name, timeout=60, **where):
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == name and all(e.get(k) == v for k, v in where.items()):
                return e
    return await asyncio.wait_for(go(), timeout)


def ui(port):
    return websockets.connect(f"ws://127.0.0.1:{port}/inbox/ws?token={TOKEN}")


async def decide(u, pend, decision):
    await u.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": decision}))


def config(tmp_path, port, sid, **server_over):
    allowed = tmp_path / "allowed"
    allowed.mkdir(exist_ok=True)
    srv = {"command": sys.executable, "args": [PROBE], "lifecycle": "per_call", "call_timeout_s": 30,
           "sandbox": {"read": [str(ROOT / "tests/proxy")], "write": [str(allowed)], "network": "none", "env_allow": [], "require": True},
           "secrets": {"API_TOKEN": {"from_env": "E2E_HOST_SECRET", "tools": ["whoami_env"]}}}
    srv.update(server_over)
    cfg = {"session_id": sid, "backend": f"ws://127.0.0.1:{port}/proxy/ws", "servers": {"fs": srv}, "auto_approve": ["fs:whoami_env", "fs:try_write", "fs:try_net"]}
    path = tmp_path / f"{sid}.json"
    path.write_text(json.dumps(cfg))
    return path, allowed


def agent(path):
    return H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN, "E2E_HOST_SECRET": SECRET})


def out(res):
    return json.loads("".join(c.text for c in res.content))


def sbx_dirs():
    return {p for p in Path(tempfile.gettempdir()).glob("sentinel-sbx-*")}


async def test_boundary_secrets_and_enforcement_end_to_end(tmp_path, backend):
    port = backend()
    path, allowed = config(tmp_path, port, "bnd-1")
    before = sbx_dirs()
    seen_frames = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    lport = listener.getsockname()[1]
    async with ui(port) as u:
        snap_task = asyncio.create_task(next_event(u, "inbox_snapshot"))
        await snap_task
        async with agent(path) as a:
            sess = await next_event(u, "inbox_session", session_id="bnd-1", state="open")
            # what the operator sees about the boundary: names and layers, never values
            snap2 = None
            async with ui(port) as u2:
                snap2 = await next_event(u2, "inbox_snapshot")
            b = [s for s in snap2["sessions"] if s["session_id"] == "bnd-1"][0]["boundary"]
            assert b["fs"]["lifecycle"] == "per_call" and b["fs"]["network"] == "none" and b["fs"]["secrets"] == ["API_TOKEN"]
            assert "landlock_fs" in b["fs"]["layers"] and b["fs"]["missing"] == []
            assert SECRET not in json.dumps(snap2)

            # a call that RECEIVES a credential is held for the human even though the proxy lists it in auto_approve
            t = asyncio.create_task(a.call_tool("whoami_env", {"secret_var": "API_TOKEN"}))
            p = await next_event(u, "inbox_pending", session_id="bnd-1")
            seen_frames.append(p)
            assert p["secrets_used"] == ["API_TOKEN"] and p["tool"] == "whoami_env"
            await decide(u, p, "approve")
            r = out(await asyncio.wait_for(t, 60))
            assert r["secret"] == SECRET and "API_TOKEN" in r["env_names"]          # inside the approved call, the worker had it...
            assert "E2E_HOST_SECRET" not in r["env_names"], "the host variable the secret came from is not forwarded"
            assert set(r["env_names"]) - {"LC_CTYPE"} == {"API_TOKEN", "HOME", "LANG", "PATH", "TMPDIR"}, r["env_names"]   # nothing else of the proxy's environment

            # ...but no other tool ever sees it, and the sandbox refuses writes outside and any network
            t = asyncio.create_task(a.call_tool("try_write", {"path": str(tmp_path / "outside.txt")}))
            p = await next_event(u, "inbox_pending", session_id="bnd-1")
            assert p["secrets_used"] == [] and p["tool"] == "try_write"
            await decide(u, p, "approve")
            assert out(await asyncio.wait_for(t, 60))["write"].startswith("err:")
            assert not (tmp_path / "outside.txt").exists()
            t = asyncio.create_task(a.call_tool("try_write", {"path": str(allowed / "inside.txt")}))
            p = await next_event(u, "inbox_pending", session_id="bnd-1")
            await decide(u, p, "approve")
            assert out(await asyncio.wait_for(t, 60))["write"] == "ok" and (allowed / "inside.txt").exists()
            t = asyncio.create_task(a.call_tool("try_net", {"port": lport}))
            p = await next_event(u, "inbox_pending", session_id="bnd-1")
            await decide(u, p, "approve")
            assert out(await asyncio.wait_for(t, 60))["net"].startswith("err:")
            listener.close()
            t = asyncio.create_task(a.call_tool("whoami_env", {"secret_var": "API_TOKEN"}))
            p = await next_event(u, "inbox_pending", session_id="bnd-1")
            await decide(u, p, "deny")                                                # denied: no worker, no secret
            assert (await asyncio.wait_for(t, 30)).is_error
    # the credential never travelled to the hub, and no private sandbox directory is left behind
    assert SECRET not in json.dumps(seen_frames)
    time.sleep(0.5)
    assert sbx_dirs() - before == set(), "private sandbox HOME directories were left behind"


async def test_a_server_that_cannot_run_inside_its_sandbox_is_never_run_unsandboxed(tmp_path, backend):
    port = backend()
    path, _ = config(tmp_path, port, "bnd-2", sandbox={"read": [], "write": [], "network": "none", "env_allow": [], "require": True,
                                                       "rlimits": {"cpu_s": 10, "mem_mb": 1, "nofile": 16, "nproc": 8, "fsize_mb": 1}})
    # a server that cannot even start under impossible limits (1 MB of memory) must NOT be silently run unsandboxed: the proxy exits non-zero
    code, err, _ = await H.run_proxy_exit(path, {"SENTINEL_WS_TOKEN": TOKEN, "E2E_HOST_SECRET": SECRET})
    assert code != 0
    assert SECRET not in err
