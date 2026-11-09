"""Load driver for the hub (docs/TESTING_REALITY.md, rung 6): many real proxy-protocol sessions, several operators deciding concurrently
(so decisions RACE), abrupt disconnects mid-call, real MiniLM + action_sim monitor, hash-chained event log. Used by tests/load and runnable alone:
    python -m tests.load.loadlib --sessions 200 --calls 30 --seconds 600"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import websockets

from tests.harness import ROOT, TOKEN, Backend, Operator

KEY = "load-test-log-key-0123456789"
TOOLS = [("read_file", {"path": "/project/docs/{n}.txt"}), ("list_directory", {"path": "/project/{n}"}), ("write_file", {"path": "/tmp/out{n}.txt", "content": "report {n}"}),
         ("send_email", {"to": "alice@team.com", "subject": "status {n}", "body": "on track"}), ("query_database", {"query": "SELECT * FROM t{n}"})]


@dataclass
class Report:
    sessions: int = 0
    calls_decided: int = 0
    aborted_sessions: int = 0
    aborted_calls: set[str] = field(default_factory=set)          # call_ids sent just before the agent host died
    latencies: list[float] = field(default_factory=list)
    decisions: dict[str, str] = field(default_factory=dict)       # call_id -> approve|deny as the CLIENT saw it
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0
    rss_start_mb: float = 0.0
    rss_end_mb: float = 0.0
    health_samples: list[float] = field(default_factory=list)

    def pct(self, q: float) -> float:
        xs = sorted(self.latencies)
        return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0

    def summary(self) -> dict:
        return {"sessions": self.sessions, "calls_decided": self.calls_decided, "aborted_sessions": self.aborted_sessions, "seconds": round(self.seconds, 1),
                "calls_per_s": round(self.calls_decided / max(self.seconds, 1e-9), 1), "p50_s": round(self.pct(.5), 3), "p95_s": round(self.pct(.95), 3),
                "p99_s": round(self.pct(.99), 3), "max_s": round(max(self.latencies or [0]), 3), "rss_mb": [round(self.rss_start_mb), round(self.rss_end_mb)],
                "worst_health_s": round(max(self.health_samples or [0]), 3), "errors": len(self.errors)}


async def _session(backend: Backend, i: int, calls: int, rep: Report, rnd: random.Random, abort_at: int | None, stop_at: float) -> None:
    sid = f"load-{i}-{uuid.uuid4().hex[:6]}"
    try:
        async with websockets.connect(f"{backend.ws}/proxy/ws?token={TOKEN}", max_size=None, ping_interval=None) as ws:
            await ws.send(json.dumps({"event": "proxy_hello", "session_id": sid, "servers": ["fs"], "auto_approve": [], "boundary": {}}))
            for n in range(calls):
                if time.monotonic() > stop_at:
                    break
                tool, args = rnd.choice(TOOLS)
                args = {k: v.format(n=n) for k, v in args.items()}
                cid = uuid.uuid4().hex
                t0 = time.perf_counter()
                await ws.send(json.dumps({"event": "proxy_call", "call_id": cid, "server": "fs", "tool": tool, "args": args, "auto": False, "secrets_used": []}))
                if abort_at is not None and n == abort_at:
                    rep.aborted_sessions += 1
                    rep.aborted_calls.add(cid)
                    # even index: abort_at is 0, so hello + call + close go out back to back, the hello_ack is never awaited
                    if i % 2:                                          # half of the aborters: the call is HELD for a moment, then the agent host dies
                        await asyncio.sleep(rnd.uniform(0.08, 0.3))    # the other half: closed in the same instant as the proposal
                    await ws.close()
                    return
                while True:
                    f = json.loads(await asyncio.wait_for(ws.recv(), 180))
                    if f.get("event") == "proxy_decision" and f.get("call_id") == cid:
                        break
                rep.latencies.append(time.perf_counter() - t0)
                rep.decisions[cid] = f["decision"]
                rep.calls_decided += 1
                await ws.send(json.dumps({"event": "proxy_result", "call_id": cid, "status": "ok" if f["decision"] == "approve" else "error", "summary": "done"}))
    except Exception as e:  # noqa: BLE001 - every failure is a finding
        rep.errors.append(f"session {sid}: {type(e).__name__}: {str(e)[:120]}")


async def run_load(backend: Backend, *, sessions: int, calls: int, operators: int = 3, abort_fraction: float = 0.1, seconds: float = 600.0, seed: int = 7) -> Report:
    rnd = random.Random(seed)
    rep = Report(sessions=sessions, rss_start_mb=backend.rss_mb())
    ops = [await Operator.connect(backend, lambda p, r=random.Random(seed + k): "approve" if r.random() < 0.7 else "deny", think=lambda r=random.Random(seed + 100 + k): r.uniform(0.0, 0.05))
           for k in range(operators)]
    stop = {"flag": False}

    async def probe():                                                  # the hub must stay responsive WHILE loaded
        while not stop["flag"]:
            t = time.perf_counter()
            try:
                await asyncio.to_thread(lambda: urllib.request.urlopen(f"http://127.0.0.1:{backend.port}/health", timeout=30).read())
                rep.health_samples.append(time.perf_counter() - t)
            except Exception as e:  # noqa: BLE001
                rep.errors.append(f"health probe: {type(e).__name__}")
            await asyncio.sleep(0.5)

    t0 = time.monotonic()
    pr = asyncio.create_task(probe())
    aborters = set(rnd.sample(range(sessions), int(sessions * abort_fraction)))
    await asyncio.gather(*[_session(backend, i, calls, rep, random.Random(seed * 1000 + i), ((0 if i % 2 == 0 else rnd.randrange(1, max(2, calls))) if i in aborters else None), t0 + seconds)
                           for i in range(sessions)])
    await asyncio.sleep(1.0)                                            # let the last broadcasts land
    stop["flag"] = True
    await pr
    rep.seconds = time.monotonic() - t0
    rep.rss_end_mb = backend.rss_mb()
    for o in ops:
        await o.close()
    return rep


def verify_log(db: Path) -> tuple[int, str, list[dict]]:
    env = {"SENTINEL_LOG_KEY": KEY, "PATH": "/usr/bin:/bin:/usr/local/bin"}
    v = subprocess.run([sys.executable, "-m", "eventlog_cli", "verify", str(db)], cwd=ROOT / "server", env=env, capture_output=True, text=True)
    ex = subprocess.run([sys.executable, "-m", "eventlog_cli", "export", str(db), "--jsonl"], cwd=ROOT / "server", env=env, capture_output=True, text=True)
    return v.returncode, v.stdout + v.stderr, [json.loads(line) for line in ex.stdout.splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=100)
    ap.add_argument("--calls", type=int, default=20)
    ap.add_argument("--operators", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=600)
    a = ap.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="load-"))
    b = Backend(tmp / "backend.log", {"SENTINEL_EVENT_LOG": str(tmp / "events.db"), "SENTINEL_LOG_KEY": KEY})
    try:
        rep = asyncio.run(run_load(b, sessions=a.sessions, calls=a.calls, operators=a.operators, seconds=a.seconds))
    finally:
        b.stop()
    print(json.dumps(rep.summary(), indent=1))
    code, out, _ = verify_log(tmp / "events.db")
    print("event log verify:", code, out.strip().splitlines()[-1] if out.strip() else "")
    return 0 if not rep.errors and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
