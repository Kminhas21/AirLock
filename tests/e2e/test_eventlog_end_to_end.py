"""Durable event log, no mocks of our own code: real uvicorn backend with SENTINEL_EVENT_LOG + a real stdio proxy + real downstream + a human
client, then the real CLI over the resulting database. Covers: a normal session is fully logged and verifies; secrets are redacted on disk;
kill -9 with a call pending => the restart resolves it as `restart`, the chain verifies, the Inbox snapshot shows it as history; tampering with
the file is detected by `verify` AND makes the backend refuse proxy sessions (never run unlogged)."""
import asyncio
import importlib.util
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
import websockets

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("proxy_helpers", ROOT / "tests/proxy/conftest.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

TOKEN = "e2e-secret-token"
KEY = "an-event-log-key-0123456789"


def start_backend(db: Path, port=None, extra=None):
    port = port or H.free_port()
    env = {**os.environ, "SENTINEL_EMBEDDER": "stub", "SENTINEL_MONITOR": "rules", "SENTINEL_GATE_TIMEOUT_S": "300", "OMP_NUM_THREADS": "1",
           "HF_HUB_OFFLINE": "1", "SENTINEL_WS_TOKEN": TOKEN, "SENTINEL_EVENT_LOG": str(db), "SENTINEL_LOG_KEY": KEY, **(extra or {})}
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(port), "--log-level", "warning"],
                         cwd=ROOT / "server", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(300):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
            return p, port
        except Exception:
            time.sleep(0.2)
    p.kill()
    raise RuntimeError("backend did not start")


@pytest.fixture
def backends():
    procs = []
    yield procs
    for p in procs:
        p.kill()
        p.wait()


def stop_gracefully(p):
    p.send_signal(signal.SIGTERM)       # uvicorn runs the lifespan shutdown => the store writes its final checkpoint
    p.wait(timeout=30)


def cli(*args, key=True):
    env = {**os.environ, **({"SENTINEL_LOG_KEY": KEY} if key else {})}
    return subprocess.run([sys.executable, "-m", "eventlog_cli", *args], cwd=ROOT / "server", env=env, capture_output=True, text=True, timeout=60)


async def next_event(ws, name, timeout=20):
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == name:
                return e
    return await asyncio.wait_for(go(), timeout)


def ui(port):
    return websockets.connect(f"ws://127.0.0.1:{port}/inbox/ws?token={TOKEN}")


async def decide(u, pend, decision):
    await u.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": decision}))


def agent(tmp_path, port, sid="log-e2e"):
    path, log = H.make_config(tmp_path, f"ws://127.0.0.1:{port}/proxy/ws", session_id=sid)
    return path, log, H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN})


async def run_session(tmp_path, port):
    path, log, ctx = agent(tmp_path, port)
    async with ui(port) as u:
        async with ctx as a:
            t = asyncio.create_task(a.call_tool("write_file", {"path": "/tmp/a", "password": "hunter2-SECRET", "note": "x"}))
            p = await next_event(u, "inbox_pending")
            await decide(u, p, "approve")
            assert not (await asyncio.wait_for(t, 20)).is_error
            t = asyncio.create_task(a.call_tool("echo", {"n": 2}))
            p = await next_event(u, "inbox_pending")
            await decide(u, p, "deny")
            assert (await asyncio.wait_for(t, 20)).is_error
            t = asyncio.create_task(a.call_tool("echo", {"n": 3}))
            p = await next_event(u, "inbox_pending")
            t.cancel()                                            # the agent abandons a call
            await next_event(u, "inbox_resolved")


async def test_a_normal_session_is_fully_logged_verifies_and_hides_secrets(tmp_path, backends):
    db = tmp_path / "events.db"
    proc, port = start_backend(db)
    backends.append(proc)
    await run_session(tmp_path, port)
    stop_gracefully(proc)
    v = cli("verify", str(db))
    assert v.returncode == 0, v.stdout + v.stderr
    shown = cli("show", str(db), "--session", "log-e2e")
    assert shown.returncode == 0 and "write_file" in shown.stdout and "cancelled" in shown.stdout
    lines = [json.loads(l) for l in cli("export", str(db), "--jsonl").stdout.splitlines() if l.strip()]
    kinds = [e["kind"] for e in lines]
    for k in ("log_open", "proxy_hello", "call_proposed", "decision", "checkpoint"):
        assert k in kinds
    decisions = [(e["payload"]["decision"], e["payload"]["reason"]) for e in lines if e["kind"] == "decision"]
    assert decisions == [("approve", "human"), ("deny", "human"), ("deny", "cancelled")]
    assert b"hunter2-SECRET" not in db.read_bytes(), "secrets are redacted BEFORE storage, also from tool output echoed back by the downstream"
    assert any(b"[REDACTED]" in l.encode() for l in cli("export", str(db), "--jsonl").stdout.splitlines())
    results = [e for e in lines if e["kind"] == "call_result"]
    assert results and all(set(e["payload"]) == {"status", "summary_len"} for e in results), "by default tool output text is not stored at all"


async def test_kill_9_with_a_pending_call_is_resolved_as_restart_and_the_chain_verifies(tmp_path, backends):
    db = tmp_path / "events.db"
    proc, port = start_backend(db)
    backends.append(proc)
    path, log, ctx = agent(tmp_path, port)
    async with ui(port) as u:
        async with ctx as a:
            t = asyncio.create_task(a.call_tool("write_file", {"path": "/tmp/pending"}))
            await next_event(u, "inbox_pending")
            proc.kill()                                           # kill -9 while the call waits for the human
            proc.wait()
            res = await asyncio.wait_for(t, 30)
            assert res.is_error and "Denied by SENTINEL" in res.content[0].text
    assert not log.exists() or log.read_text() == "", "nothing reached the downstream"
    proc2, port2 = start_backend(db)                              # restart on the same database: open() recovers
    backends.append(proc2)
    async with ui(port2) as u:
        snap = await next_event(u, "inbox_snapshot")
        recent = snap["recent"]
        assert [(r["tool"], r["decision"], r["reason"]) for r in recent][:1] == [("write_file", "deny", "restart")]
    stop_gracefully(proc2)
    assert cli("verify", str(db)).returncode == 0
    lines = [json.loads(l) for l in cli("export", str(db), "--jsonl").stdout.splitlines() if l.strip()]
    restart = [e for e in lines if e["kind"] == "decision" and e["payload"]["reason"] == "restart"]
    assert len(restart) == 1 and restart[0]["payload"]["actor"] == "system", "exactly one restart decision for the orphaned call"


async def test_tampering_is_detected_and_the_backend_refuses_to_run_unlogged(tmp_path, backends):
    db = tmp_path / "events.db"
    proc, port = start_backend(db)
    backends.append(proc)
    await run_session(tmp_path, port)
    stop_gracefully(proc)
    assert cli("verify", str(db)).returncode == 0
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE events SET payload = REPLACE(payload, '\"approve\"', '\"deny\"') WHERE kind = 'decision' AND seq = (SELECT MIN(seq) FROM events WHERE kind = 'decision')")
    conn.commit()
    conn.close()
    bad = cli("verify", str(db))
    assert bad.returncode == 1 and "seq" in (bad.stdout + bad.stderr).lower()
    # a backend started on the tampered log refuses every proxy session (hello_reject log_unavailable): never silently unlogged
    proc2, port2 = start_backend(db)
    backends.append(proc2)
    async with websockets.connect(f"ws://127.0.0.1:{port2}/proxy/ws?token={TOKEN}") as ws:
        await ws.send(json.dumps({"event": "proxy_hello", "session_id": "late", "servers": ["fs"], "auto_approve": []}))
        reply = json.loads(await asyncio.wait_for(ws.recv(), 20))
        assert reply == {"event": "hello_reject", "reason": "log_unavailable"}


async def test_without_the_key_a_chain_is_still_checked_but_truncation_is_not_detectable(tmp_path, backends):
    db = tmp_path / "events.db"
    proc, port = start_backend(db)
    backends.append(proc)
    await run_session(tmp_path, port)
    stop_gracefully(proc)
    out = cli("verify", str(db), key=False)
    assert out.returncode in (0, 1)       # a keyed log opened without the key cannot check MACs: it must SAY so, never claim full assurance
    assert "key" in (out.stdout + out.stderr).lower()


async def test_opt_in_result_summaries_are_scrubbed_of_secret_argument_values(tmp_path, backends):
    """The downstream echoes its arguments (password included) in its output. By default only status+length are logged; with SENTINEL_LOG_RESULTS=1 the
    summary is stored but every secret value of THAT call is scrubbed from it."""
    db = tmp_path / "events.db"
    proc, port = start_backend(db, extra={"SENTINEL_LOG_RESULTS": "1"})
    backends.append(proc)
    await run_session(tmp_path, port)
    stop_gracefully(proc)
    assert b"hunter2-SECRET" not in db.read_bytes()
    results = [e for e in (json.loads(l) for l in cli("export", str(db), "--jsonl").stdout.splitlines() if l.strip()) if e["kind"] == "call_result"]
    assert results and "[REDACTED]" in results[0]["payload"]["summary"] and "write_file" in results[0]["payload"]["summary"]
