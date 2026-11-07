"""Identity, tenancy and escalation, full stack, no mocks of our own code: real backend with SENTINEL_IDENTITY_FILE (two tenants, three roles, a JWT operator,
per-agent tokens, escalation levels with a webhook channel), real stdio proxies authenticating with agent tokens, real websocket operators, a local HTTP server
as the notification target, the real event log and CLI."""
import asyncio
import hashlib
import http.server
import importlib.util
import json
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import jwt
import pytest
import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("proxy_helpers", ROOT / "tests/proxy/conftest.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
TOK = {n: secrets.token_urlsafe(24) for n in ("alice", "bob", "vera", "gina", "ag_acme", "ag_globex")}
LOGKEY = "an-event-log-key-0123456789"


class Hook:
    """A local HTTP server that records the webhook POSTs it receives."""

    def __init__(self):
        self.posts = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                outer.posts.append(json.loads(self.rfile.read(n) or b"{}"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def make_identity(tmp_path, hook_port, pem_path):
    ident = {
        "version": 1,
        "tenants": {
            "acme": {"name": "Acme", "escalation": {"levels": [{"after_s": 1, "notify": ["hook"]}, {"after_s": 3, "notify": ["hook"]}]},
                     "channels": {"hook": {"type": "webhook", "url": f"http://127.0.0.1:{hook_port}/hook", "format": "json", "allow_http_loopback": True}}},
            "globex": {"name": "Globex"},
        },
        "operators": [
            {"id": "alice", "tenant": "acme", "role": "admin", "token_sha256": sha(TOK["alice"])},
            {"id": "bob", "tenant": "acme", "role": "approver", "token_sha256": sha(TOK["bob"])},
            {"id": "vera", "tenant": "acme", "role": "viewer", "token_sha256": sha(TOK["vera"])},
            {"id": "zed", "tenant": "acme", "role": "approver", "jwt_sub": "zed@acme.test"},
            {"id": "gina", "tenant": "globex", "role": "approver", "token_sha256": sha(TOK["gina"])},
        ],
        "agents": [
            {"id": "ci-acme", "tenant": "acme", "token_sha256": sha(TOK["ag_acme"]), "servers": ["fs"]},
            {"id": "ci-globex", "tenant": "globex", "token_sha256": sha(TOK["ag_globex"])},
        ],
        "jwt": {"issuer": "https://sso.test", "audience": "sentinel", "algorithms": ["RS256"], "public_key_file": str(pem_path), "leeway_s": 0},
    }
    p = tmp_path / "identity.json"
    p.write_text(json.dumps(ident))
    return p


def start_backend(identity, log=None):
    port = H.free_port()
    env = {**os.environ, "SENTINEL_EMBEDDER": "stub", "SENTINEL_MONITOR": "rules", "SENTINEL_GATE_TIMEOUT_S": "300", "OMP_NUM_THREADS": "1",
           "HF_HUB_OFFLINE": "1", "SENTINEL_IDENTITY_FILE": str(identity)}
    for k in ("SENTINEL_WS_TOKEN", "SENTINEL_POLICY", "SENTINEL_EVENT_LOG"):
        env.pop(k, None)
    if log:
        env.update({"SENTINEL_EVENT_LOG": str(log), "SENTINEL_LOG_KEY": LOGKEY})
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
def world(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = tmp_path / "sso.pem"
    pem.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    hook = Hook()
    ident = make_identity(tmp_path, hook.port, pem)
    logdb = tmp_path / "events.db"
    proc, port = start_backend(ident, logdb)
    yield type("W", (), dict(port=port, hook=hook, priv=priv, tmp=tmp_path, logdb=logdb, proc=proc))
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=20)
    except Exception:
        proc.kill()
        proc.wait()
    hook.close()


def mint(priv, sub="zed@acme.test", exp_in=300, aud="sentinel", iss="https://sso.test"):
    return jwt.encode({"sub": sub, "iss": iss, "aud": aud, "exp": int(time.time()) + exp_in}, priv, algorithm="RS256")


async def operator(port, token=None, *, header=True, frame=False, query=False):
    """Connect to /inbox/ws and return (ws, first_event_after_auth)."""
    url = f"ws://127.0.0.1:{port}/inbox/ws" + (f"?token={token}" if query else "")
    hdrs = {"Authorization": f"Bearer {token}"} if (token and header) else {}
    ws = await websockets.connect(url, additional_headers=hdrs)
    if frame and token:
        await ws.send(json.dumps({"event": "auth", "token": token}))
    return ws


async def recv_until(ws, name, timeout=20, **where):
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == name and all(e.get(k) == v for k, v in where.items()):
                return e
    return await asyncio.wait_for(go(), timeout)


async def expect_rejected(ws, timeout=15):
    """The connection must end CLOSED with 1008 and must never deliver a snapshot or an auth_ok; an auth_error frame may come first
    (a connection that never presents a credential is simply closed after the 5 s first-frame window)."""
    seen = []
    try:
        while True:
            e = json.loads(await asyncio.wait_for(ws.recv(), timeout))
            seen.append(e)
            assert e.get("event") not in ("auth_ok", "inbox_snapshot"), e
            if e.get("event") == "auth_error":
                assert e["reason"] in ("unauthorized", "throttled"), e
    except websockets.ConnectionClosed as c:
        assert c.rcvd is not None and c.rcvd.code == 1008, c
        return seen


async def no_event(ws, name, seconds=2.0):
    """Assert NO event called `name` arrives within `seconds` (other events are skipped)."""
    async def go():
        while True:
            e = json.loads(await ws.recv())
            assert e.get("event") != name, e
    try:
        await asyncio.wait_for(go(), seconds)
    except asyncio.TimeoutError:
        return


def proxy(w, sid, token, tenant_dir, servers=None):
    d = w.tmp / tenant_dir
    d.mkdir(exist_ok=True)
    path, log = H.make_config(d, f"ws://127.0.0.1:{w.port}/proxy/ws", servers=servers, session_id=sid)
    return log, H.agent(path, {"SENTINEL_AGENT_TOKEN": token})


async def decide(ws, pend, decision):
    await ws.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": decision}))


# ------------------------------------------------------------------------------------------------------------------------------------ authentication

async def test_authentication_matrix(world):
    # header, first frame, JWT all work and report the principal
    ws = await operator(world.port, TOK["bob"])
    ok = await recv_until(ws, "auth_ok")
    assert ok["principal"] == {"id": "bob", "tenant": "acme", "role": "approver"}
    snap = await recv_until(ws, "inbox_snapshot")
    assert snap["principal"]["id"] == "bob" and snap["capabilities"]["can_decide"] is True
    await ws.close()
    ws = await operator(world.port, TOK["vera"], header=False, frame=True)
    assert (await recv_until(ws, "auth_ok"))["principal"]["role"] == "viewer"
    snap = await recv_until(ws, "inbox_snapshot")
    assert snap["capabilities"]["can_decide"] is False
    await ws.close()
    ws = await operator(world.port, mint(world.priv), header=False, frame=True)
    assert (await recv_until(ws, "auth_ok"))["principal"] == {"id": "zed", "tenant": "acme", "role": "approver"}
    await ws.close()
    # no credential at all, wrong token, a query token (ignored in identity mode), expired / wrong-audience / forged JWTs
    for kw in ({"token": None}, {"token": "nope"}, {"token": TOK["bob"], "header": False, "query": True},
               {"token": mint(world.priv, exp_in=-5), "header": False, "frame": True}, {"token": mint(world.priv, aud="other"), "header": False, "frame": True},
               {"token": mint(world.priv, sub="mallory@evil.test"), "header": False, "frame": True}):
        ws = await operator(world.port, **kw)
        await expect_rejected(ws)
    # throttle: repeated failures from one address are refused for a while, even with a valid credential afterwards
    for _ in range(6):
        ws = await operator(world.port, "nope")
        await expect_rejected(ws)
    ws = await operator(world.port, TOK["bob"])
    seen = await expect_rejected(ws)
    assert [e for e in seen if e.get("event") == "auth_error"] and seen[0]["reason"] == "throttled"


async def test_agents_authenticate_and_cannot_declare_servers_outside_their_allowlist(world):
    async def hello(token, servers):
        hdr = {"Authorization": f"Bearer {token}"} if token else {}
        async with websockets.connect(f"ws://127.0.0.1:{world.port}/proxy/ws", additional_headers=hdr) as ws:
            await ws.send(json.dumps({"event": "proxy_hello", "session_id": "raw-1", "servers": servers, "auto_approve": []}))
            return json.loads(await asyncio.wait_for(ws.recv(), 10))
    assert (await hello(TOK["ag_acme"], ["fs"]))["event"] == "hello_ack"
    assert await hello(TOK["ag_acme"], ["secretsrv"]) == {"event": "hello_reject", "reason": "forbidden_server"}
    assert await hello(None, ["fs"]) == {"event": "hello_reject", "reason": "unauthorized"}
    assert await hello(TOK["bob"], ["fs"]) == {"event": "hello_reject", "reason": "unauthorized"}     # an OPERATOR token is not an agent credential


# ------------------------------------------------------------------------------------------------------------------------------------ tenancy and roles

async def test_tenants_never_see_or_decide_each_others_calls_and_viewers_cannot_decide(world):
    log_a, ctx_a = proxy(world, "shared-id", TOK["ag_acme"], "a")
    log_g, ctx_g = proxy(world, "shared-id", TOK["ag_globex"], "g")         # the SAME session id in two tenants must work side by side
    bob = await operator(world.port, TOK["bob"])
    vera = await operator(world.port, TOK["vera"])
    gina = await operator(world.port, TOK["gina"])
    for w_ in (bob, vera, gina):
        await recv_until(w_, "inbox_snapshot")
    async with ctx_a as a, ctx_g as g:
        ta = asyncio.create_task(a.call_tool("echo", {"who": "acme"}))
        pb = await recv_until(bob, "inbox_pending")
        pv = await recv_until(vera, "inbox_pending")
        assert pb["call_id"] == pv["call_id"] and pb["agent_id"] == "ci-acme" and pb["tenant"] == "acme"
        await no_event(gina, "inbox_pending", 1.5)                           # globex sees nothing of acme
        # a viewer cannot decide; the call stays pending
        await decide(vera, pv, "approve")
        forb = await recv_until(vera, "inbox_forbidden")
        assert (forb["action"], forb["reason"]) == ("decide", "role")
        assert not ta.done()
        # globex's operator forging acme's call id changes nothing and learns nothing (silently ignored)
        await decide(gina, pb, "approve")
        await asyncio.sleep(1.0)
        assert not ta.done()
        # the acme approver decides; the decision names the operator and reaches only acme
        await decide(bob, pb, "approve")
        res = await asyncio.wait_for(ta, 20)
        assert not res.is_error
        r = await recv_until(vera, "inbox_resolved")
        assert r["operator"] == "bob"
        await no_event(gina, "inbox_resolved", 1.0)
        # globex's own call with the same session id is independent
        tg = asyncio.create_task(g.call_tool("echo", {"who": "globex"}))
        pg = await recv_until(gina, "inbox_pending")
        assert pg["agent_id"] == "ci-globex" and pg["tenant"] == "globex"
        await no_event(bob, "inbox_pending", 1.0)
        await decide(gina, pg, "deny")
        assert (await asyncio.wait_for(tg, 20)).is_error
    for w_ in (bob, vera, gina):
        await w_.close()


# ------------------------------------------------------------------------------------------------------------------------------------ escalation and audit

async def test_unanswered_calls_escalate_notify_a_webhook_without_arguments_and_are_audited(world):
    log, ctx = proxy(world, "esc-1", TOK["ag_acme"], "e")
    bob = await operator(world.port, TOK["bob"])
    await recv_until(bob, "inbox_snapshot")
    async with ctx as a:
        t = asyncio.create_task(a.call_tool("write_file", {"path": "/tmp/very-secret-path.txt", "password": "hunter2-SECRET"}))
        p = await recv_until(bob, "inbox_pending")
        assert p["escalation_level"] == 0
        e1 = await recv_until(bob, "inbox_escalated", timeout=15)
        e2 = await recv_until(bob, "inbox_escalated", timeout=15)
        assert (e1["level"], e2["level"]) == (1, 2) and e1["call_id"] == p["call_id"]
        for _ in range(50):
            if len(world.hook.posts) >= 2:
                break
            await asyncio.sleep(0.1)
        assert len(world.hook.posts) == 2
        body = json.dumps(world.hook.posts)
        assert "very-secret-path" not in body and "hunter2" not in body, "notifications never carry arguments by default"
        assert all(x["tool"] == "write_file" and x["tenant"] == "acme" and x["agent_id"] == "ci-acme" and x["call_id"] == p["call_id"] for x in world.hook.posts)
        await decide(bob, p, "deny")
        assert (await asyncio.wait_for(t, 20)).is_error
        n = len(world.hook.posts)
        await asyncio.sleep(2.5)
        assert len(world.hook.posts) == n, "no notification after the call was resolved"
    await bob.close()
    world.proc.send_signal(signal.SIGTERM)
    world.proc.wait(timeout=30)
    out = subprocess.run([sys.executable, "-m", "eventlog_cli", "export", str(world.logdb), "--jsonl"], cwd=ROOT / "server", capture_output=True, text=True,
                         env={**os.environ, "SENTINEL_LOG_KEY": LOGKEY})
    events = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    kinds = [e["kind"] for e in events]
    assert "notification" in kinds and "proxy_hello" in kinds
    dec = [e for e in events if e["kind"] == "decision"][0]["payload"]
    assert dec["operator"] == "bob" and dec["tenant"] == "acme"
    hello = [e for e in events if e["kind"] == "proxy_hello"][0]["payload"]
    assert hello["agent_id"] == "ci-acme" and hello["tenant"] == "acme"
    assert b"hunter2-SECRET" not in world.logdb.read_bytes()
