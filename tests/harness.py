"""Shared harness for tests that run the REAL pieces as processes (hostile model, real MCP servers, load): a backend, a real stdio proxy
with a scripted agent in front of it, and an operator websocket that decides calls. Nothing here fakes the hub, proxy or MCP layer."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable

import websockets

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "harness-token-0123456789abcdef"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, proc: subprocess.Popen | None = None, seconds: int = 120) -> None:
    for _ in range(seconds * 4):
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"process exited early: {proc.returncode}")
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"{url} never came up")


class Backend:
    """The real backend (uvicorn main:app) in a subprocess, legacy-token mode so /inbox/ws and /proxy/ws are open to TOKEN."""

    def __init__(self, log: Path, env: dict[str, str] | None = None):
        self.port = free_port()
        self.log = log
        base = {**os.environ, "SENTINEL_WS_TOKEN": TOKEN, "SENTINEL_EMBEDDER": "minilm", "SENTINEL_MONITOR": "action_sim", "HF_HUB_OFFLINE": "1",
                "SENTINEL_GATE_TIMEOUT_S": "120", **(env or {})}
        for k in ("SENTINEL_IDENTITY_FILE", "SENTINEL_ALLOWED_ORIGINS"):
            if k not in (env or {}):
                base.pop(k, None)
        self._lf = open(log, "w")
        self.proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(self.port), "--log-level", "info"],
                                     cwd=ROOT / "server", env=base, stdout=self._lf, stderr=subprocess.STDOUT)
        wait_http(f"http://127.0.0.1:{self.port}/health", self.proc)

    @property
    def ws(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def log_text(self) -> str:
        return self.log.read_text(errors="replace")

    def rss_mb(self) -> float:
        for line in Path(f"/proc/{self.proc.pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
        return 0.0

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()
        self._lf.close()


class Agent:
    """A scripted MCP agent behind the REAL stdio proxy (tests/proxy/agent_cli.py --serve); one call at a time."""

    def __init__(self, proc: asyncio.subprocess.Process):
        self.proc = proc

    @classmethod
    async def start(cls, backend: Backend, session: str, servers: dict, tmp: Path, extra_cfg: dict | None = None) -> "Agent":
        cfg = tmp / f"{session}.json"
        cfg.write_text(json.dumps({"session_id": session, "backend": f"{backend.ws}/proxy/ws", "servers": servers, **(extra_cfg or {})}))
        proc = await asyncio.create_subprocess_exec(sys.executable, str(ROOT / "tests/proxy/agent_cli.py"), "--serve", str(cfg), cwd=ROOT,
                                                    env={**os.environ, "SENTINEL_WS_TOKEN": TOKEN}, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=256 * 1024 * 1024)
        return cls(proc)

    async def call(self, tool: str, args: dict, timeout: float = 120.0) -> dict:
        self.proc.stdin.write((json.dumps({"tool": tool, "args": args}) + "\n").encode())
        await self.proc.stdin.drain()
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
        if not line:
            raise RuntimeError("agent exited")
        return json.loads(line)

    async def stop(self) -> None:
        try:
            self.proc.stdin.close()
            await asyncio.wait_for(self.proc.wait(), 20)
        except Exception:
            self.proc.kill()


class Operator:
    """An operator websocket that decides every held call with `decide(pending_frame) -> "approve" | "deny" | None` (None = leave it held)."""

    def __init__(self, ws, decide: Callable[[dict], str | None], think: Callable[[], float] | None = None):
        self.ws, self.decide, self.think = ws, decide, think
        self.resolved: list[dict] = []
        self.pending_seen: list[dict] = []
        self.frames = 0
        self._task = asyncio.create_task(self._run())
        self._answered: set[tuple[str, str]] = set()

    @classmethod
    async def connect(cls, backend: Backend, decide, think=None) -> "Operator":
        ws = await websockets.connect(f"{backend.ws}/inbox/ws?token={TOKEN}", max_size=None)
        return cls(ws, decide, think)

    async def _answer(self, p: dict) -> None:
        key = (p["session_id"], p["call_id"])
        if key in self._answered:
            return
        verdict = self.decide(p)
        if verdict and self.think:
            await asyncio.sleep(self.think())               # a human takes a moment
        if verdict:
            self._answered.add(key)
            await self.ws.send(json.dumps({"event": "inbox_decision", "session_id": p["session_id"], "call_id": p["call_id"], "decision": verdict}))

    async def _run(self) -> None:
        try:
            async for raw in self.ws:
                f = json.loads(raw)
                self.frames += 1
                ev = f.get("event")
                if ev == "inbox_pending":
                    self.pending_seen.append(f)
                    await self._answer(f)
                elif ev == "inbox_snapshot":
                    for s in f.get("sessions", []):
                        for p in s.get("pending", []):
                            await self._answer({**p, "session_id": s["session_id"]})
                elif ev == "inbox_resolved":
                    self.resolved.append(f)
        except websockets.ConnectionClosed:
            pass

    async def close(self) -> None:
        await self.ws.close()
        self._task.cancel()
