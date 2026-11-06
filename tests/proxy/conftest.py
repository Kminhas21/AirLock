import asyncio
import json
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from websockets.asyncio.server import serve

ROOT = Path(__file__).resolve().parents[2]
DOWNSTREAM = str(Path(__file__).with_name("fake_downstream.py"))


class FakeBackend:
    """Scriptable /proxy/ws stand-in. `on_call(ws, frame)` decides what to do with each proxy_call."""

    def __init__(self):
        self.frames: list[dict] = []
        self.hello_reply = "ack"  # "ack" | "reject:<reason>" | "silent"
        self.on_call = self.approve
        self.conns: list = []
        self.url = ""
        self._server = None

    async def reply(self, ws, frame, decision, reason="human"):
        await ws.send(json.dumps({"event": "proxy_decision", "call_id": frame["call_id"], "decision": decision, "reason": reason}))

    async def approve(self, ws, frame):
        await self.reply(ws, frame, "approve")

    async def deny(self, ws, frame):
        await self.reply(ws, frame, "deny", "human")

    async def handler(self, ws):
        self.conns.append(ws)
        try:
            async for raw in ws:
                f = json.loads(raw)
                self.frames.append(f)
                if f.get("event") == "proxy_hello":
                    if self.hello_reply == "ack":
                        await ws.send(json.dumps({"event": "hello_ack", "session_id": f["session_id"]}))
                    elif self.hello_reply.startswith("reject:"):
                        await ws.send(json.dumps({"event": "hello_reject", "reason": self.hello_reply[7:]}))
                        await ws.close()
                elif f.get("event") == "proxy_call":
                    await self.on_call(ws, f)
        except Exception:
            pass

    def of(self, event):
        return [f for f in self.frames if f.get("event") == event]

    async def wait_for(self, event, n=1, timeout=10):
        async def poll():
            while len(self.of(event)) < n:
                await asyncio.sleep(0.02)
        await asyncio.wait_for(poll(), timeout)

    async def kick(self):
        for ws in list(self.conns):
            await ws.close()


@pytest.fixture
async def backend():
    b = FakeBackend()
    async with serve(b.handler, "127.0.0.1", 0) as server:
        b._server = server
        b.url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/proxy/ws"
        yield b


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_config(tmp_path, backend_url, servers=None, **extra):
    log = tmp_path / "downstream.log"
    base = {"command": sys.executable, "args": [DOWNSTREAM], "env": {"FAKE_DOWNSTREAM_LOG": str(log)}}
    cfg = {"backend": backend_url, "session_id": "t1", "servers": servers or {"fs": base}}
    cfg.update(extra)
    p = tmp_path / "proxy.json"
    p.write_text(json.dumps(cfg))
    return p, log


def proxy_params(cfg_path, env=None):
    e = {"SENTINEL_PROXY_CONNECT_WAIT_S": "1", "PYTHONUNBUFFERED": "1"}
    e.update(env or {})
    return StdioServerParameters(command=sys.executable, args=["-m", "sentinel_proxy", "--config", str(cfg_path)],
                                 cwd=str(ROOT), env=e)


@asynccontextmanager
async def agent(cfg_path, env=None, errlog=None):
    """The 'agent': the SDK's own stdio client talking to the real proxy subprocess."""
    kw = {"errlog": errlog} if errlog is not None else {}
    async with stdio_client(proxy_params(cfg_path, env), **kw) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            yield s


async def run_proxy_exit(cfg_path, env=None, timeout=20):
    """Run the proxy without an agent; return (exit_code, stderr)."""
    e = {**__import__("os").environ, "SENTINEL_PROXY_CONNECT_WAIT_S": "1", **(env or {})}
    p = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "sentinel_proxy", "--config", str(cfg_path), cwd=str(ROOT), env=e,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        raise
    return p.returncode, err.decode(), out.decode()
