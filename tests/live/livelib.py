"""Helpers for the live workflow suites (tests/live, tests/claude): third-party server isolation, the real event-log CLI, a local HTTP target
that counts hits, and log queries. A plain module on purpose (no conftest.py: a second conftest shadows `from conftest import` in older suites)."""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from tests.harness import ROOT

LOG_KEY = "live-test-log-key-0123456789abcdef"


def dc_env(home: Path) -> dict[str, str]:
    """Desktop Commander with a private HOME (its config, history and feature-flag cache land there, never in the real ~) and NO outbound traffic:
    DESKTOP_COMMANDER_DISABLE_TELEMETRY is its documented hard kill-switch (dist/utils/capture.js), DC_FLAG_URL points its feature-flag fetch at
    a closed local port instead of desktopcommander.app. The proxy's downstream gets no HTTPS_PROXY (the MCP SDK's default environment)."""
    home.mkdir(parents=True, exist_ok=True)
    return {"HOME": str(home), "NO_COLOR": "1", "DESKTOP_COMMANDER_DISABLE_TELEMETRY": "1", "DC_FLAG_URL": "http://127.0.0.1:9/flags.json"}


def dc_server(command: str, home: Path) -> dict:
    return {"command": command, "args": [], "env": dc_env(home)}


def run_cli(*args: str, key: str | None = LOG_KEY) -> subprocess.CompletedProcess:
    """The REAL event-log CLI (`python -m eventlog_cli`, cwd=server), as an operator runs it."""
    env = {"PATH": os.environ["PATH"], "HF_HUB_OFFLINE": "1", **({"SENTINEL_LOG_KEY": key} if key else {})}
    return subprocess.run([sys.executable, "-m", "eventlog_cli", *args], cwd=ROOT / "server", env=env, capture_output=True, text=True, timeout=300)


def cli(*args: str, key: str | None = LOG_KEY) -> tuple[int, str]:
    r = run_cli(*args, key=key)
    return r.returncode, r.stdout + r.stderr


def cli_json(*args: str, key: str | None = LOG_KEY):
    r = run_cli(*args, "--json", key=key)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)


def events(db: Path, session: str | None = None) -> list[dict]:
    r = run_cli("export", str(db), "--jsonl", *(["--session", session] if session else []))
    assert r.returncode == 0, r.stdout + r.stderr
    return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]


def decisions(evs: list[dict]) -> dict[str, dict]:
    """call_id -> the decision payload (decision, actor, reason, note)."""
    return {e["call_id"]: e["payload"] for e in evs if e["kind"] == "decision"}


def proposals(evs: list[dict]) -> dict[str, dict]:
    return {e["call_id"]: e["payload"] for e in evs if e["kind"] == "call_proposed"}


class HitCounter:
    """A local HTTP server standing in for an exfiltration target: every request is recorded. 0 hits = nothing left the gate."""

    def __init__(self):
        self.hits: list[str] = []
        hits = self.hits

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"EXFIL-TARGET-RESPONSE")

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class ScriptedHuman:
    """An operator on the REAL /inbox/ws (legacy token mode): `decide(card) -> (verdict, note | None)`, verdict "approve" | "deny" | None (= keep
    it held). Every card it was shown is kept in .cards."""

    def __init__(self, ws_base: str, decide):
        self.ws_base, self.decide, self.cards, self._seen = ws_base, decide, [], set()

    async def __aenter__(self):
        import asyncio
        import websockets
        from tests.harness import TOKEN
        self.ws = await websockets.connect(f"{self.ws_base}/inbox/ws?token={TOKEN}", max_size=None)
        self._task = asyncio.create_task(self._run())
        return self

    async def __aexit__(self, *exc):
        self._task.cancel()
        await self.ws.close()

    async def _answer(self, p: dict) -> None:
        key = (p["session_id"], p["call_id"])
        if key in self._seen:
            return
        self._seen.add(key)
        self.cards.append(p)
        verdict, note = self.decide(p)
        if verdict:
            frame = {"event": "inbox_decision", "session_id": p["session_id"], "call_id": p["call_id"], "decision": verdict}
            if note:
                frame["note"] = note
            await self.ws.send(json.dumps(frame))

    async def _run(self) -> None:
        import websockets
        try:
            async for raw in self.ws:
                f = json.loads(raw)
                if f.get("event") == "inbox_pending":
                    await self._answer(f)
                elif f.get("event") == "inbox_snapshot":
                    for s in f.get("sessions", []):
                        for p in s.get("pending", []):
                            await self._answer({**p, "session_id": s["session_id"]})
        except websockets.ConnectionClosed:
            pass
