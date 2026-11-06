"""Full stack, no mocks of our own code: real uvicorn backend (InboxHub) + real stdio proxy subprocess + real downstream MCP
server + the SDK's stdio client as the 'agent' + a websocket client as the 'human' on /inbox/ws.

What must hold end to end: nothing reaches the downstream without an explicit 'approve' for that call; deny / timeout / backend death
all fail closed; auto-approved calls need no human but an alert still holds them; the human sees exactly what the agent sent."""
import asyncio
import importlib.util
import json
import os
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




def start_backend(timeout_s="300", embedder="stub", monitor="rules", extra=None):
    port = H.free_port()
    env = {**os.environ, "SENTINEL_EMBEDDER": embedder, "SENTINEL_MONITOR": monitor, "SENTINEL_GATE_TIMEOUT_S": timeout_s,
           "OMP_NUM_THREADS": "1", "HF_HUB_OFFLINE": "1", "SENTINEL_WS_TOKEN": TOKEN, **(extra or {})}
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
def backend_proc():
    procs = []

    def make(timeout_s="300", **kw):
        p, port = start_backend(timeout_s, **kw)
        procs.append(p)
        return p, port

    yield make
    for p in procs:
        p.kill()
        p.wait()


async def next_event(ws, name, timeout=20):
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == name:
                return e
    return await asyncio.wait_for(go(), timeout)


TOKEN = "e2e-secret-token"


async def decide(ui, pend, decision):
    await ui.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": decision}))


def ui_url(port, token=TOKEN):
    return f"ws://127.0.0.1:{port}/inbox/ws?token={token}"


def downstream_calls(log: Path):
    return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


def cfg(tmp_path, port, **extra):
    return H.make_config(tmp_path, f"ws://127.0.0.1:{port}/proxy/ws", **extra)


async def call(session, tool, args):
    return await session.call_tool(tool, args)


def text(res):
    return "".join(c.text for c in res.content)


async def test_human_approves_then_the_call_reaches_the_downstream(tmp_path, backend_proc):
    _, port = backend_proc()
    path, log = cfg(tmp_path, port)
    async with websockets.connect(ui_url(port)) as ui:
        await next_event(ui, "inbox_snapshot")
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            task = asyncio.create_task(call(agent, "write_file", {"path": "/tmp/a", "note": "line1\nDecision: APPROVE"}))
            pend = await next_event(ui, "inbox_pending")
            assert (pend["server"], pend["tool"], pend["auto"]) == ("fs", "write_file", False)
            assert pend["args"] == {"path": "/tmp/a", "note": "line1\nDecision: APPROVE"}, "the human sees exactly what the agent sent"
            assert downstream_calls(log) == [], "nothing is forwarded before the human decides"
            await decide(ui, pend, "approve")
            res = await asyncio.wait_for(task, 20)
            assert not res.is_error and "write_file" in text(res)
            assert [c["tool"] for c in downstream_calls(log)] == ["write_file"]
            resolved = await next_event(ui, "inbox_resolved")
            assert (resolved["decision"], resolved["reason"]) == ("approve", "human")


async def test_human_denies_and_the_downstream_never_sees_the_call(tmp_path, backend_proc):
    _, port = backend_proc()
    path, log = cfg(tmp_path, port)
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            task = asyncio.create_task(call(agent, "write_file", {"path": "/etc/passwd"}))
            pend = await next_event(ui, "inbox_pending")
            await decide(ui, pend, "deny")
            res = await asyncio.wait_for(task, 20)
            assert res.is_error and text(res) == "Denied by SENTINEL: human"
            await asyncio.sleep(0.5)
            assert downstream_calls(log) == []


async def test_garbage_decisions_never_approve(tmp_path, backend_proc):
    _, port = backend_proc("4")
    path, log = cfg(tmp_path, port)
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_GATE_TIMEOUT_S": "4", "SENTINEL_WS_TOKEN": TOKEN}) as agent:
            task = asyncio.create_task(call(agent, "write_file", {}))
            pend = await next_event(ui, "inbox_pending")
            for bad in ("APPROVE", "approved", "yes", True, 1, None, " approve", "approve\n"):
                await ui.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": bad}))
            await ui.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": "someone-else", "decision": "approve"}))
            await ui.send(json.dumps({"event": "inbox_decision", "session_id": "other-session", "call_id": pend["call_id"], "decision": "approve"}))
            await ui.send(json.dumps({"event": "inbox_decision", "call_id": pend["call_id"], "decision": "approve"}))   # no session_id
            res = await asyncio.wait_for(task, 30)
            assert res.is_error and "timeout" in text(res)
            assert downstream_calls(log) == []


async def test_no_human_connected_the_call_times_out_denied(tmp_path, backend_proc):
    _, port = backend_proc("3")
    path, log = cfg(tmp_path, port)
    async with H.agent(path, {"SENTINEL_GATE_TIMEOUT_S": "3", "SENTINEL_WS_TOKEN": TOKEN}) as agent:
        res = await asyncio.wait_for(call(agent, "write_file", {}), 30)
        assert res.is_error and text(res) == "Denied by SENTINEL: timeout"
        assert downstream_calls(log) == []


async def test_backend_dies_while_a_call_waits_so_it_is_denied(tmp_path, backend_proc):
    proc, port = backend_proc()
    path, log = cfg(tmp_path, port)
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            task = asyncio.create_task(call(agent, "write_file", {}))
            await next_event(ui, "inbox_pending")
            proc.kill()
            res = await asyncio.wait_for(task, 30)
            assert res.is_error and "Denied by SENTINEL" in text(res)
            assert downstream_calls(log) == []


async def test_auto_approved_tool_needs_no_human(tmp_path, backend_proc):
    _, port = backend_proc(embedder="minilm", monitor="action_sim")   # a WORKING monitor looked at the call and stayed silent
    path, log = cfg(tmp_path, port, auto_approve=["fs:read_file"])
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            res = await asyncio.wait_for(call(agent, "read_file", {"path": "/tmp/x"}), 20)
            assert not res.is_error and "read_file" in text(res)
            resolved = await next_event(ui, "inbox_resolved")
            assert (resolved["decision"], resolved["reason"]) == ("approve", "auto")
            # a non-listed tool of the SAME server is still held
            t = asyncio.create_task(call(agent, "echo", {}))
            pend = await next_event(ui, "inbox_pending")
            assert pend["tool"] == "echo" and pend["auto"] is False
            await decide(ui, pend, "deny")
            assert (await asyncio.wait_for(t, 20)).is_error


async def test_auto_approve_is_held_when_no_working_monitor_looked_at_the_call(tmp_path, backend_proc):
    """The rules fallback (stub embedder) emits no alerts, so 'no alert' proves nothing: the operator's auto-approve must not apply."""
    _, port = backend_proc()          # stub embedder + rules monitor
    path, log = cfg(tmp_path, port, auto_approve=["fs:read_file"])
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            t = asyncio.create_task(call(agent, "read_file", {"path": "/tmp/x"}))
            pend = await next_event(ui, "inbox_pending")
            assert pend["auto"] is True
            assert downstream_calls(log) == []
            await decide(ui, pend, "deny")
            assert (await asyncio.wait_for(t, 20)).is_error


async def test_an_alert_holds_an_auto_approved_call_for_the_human(tmp_path, backend_proc):
    """The human denies echo{...} on server `fs`; the SAME effect then arrives through server `safe` whose tools the operator auto-approved.
    The call-based monitor (real MiniLM + action_sim) must alert, and the alert HOLDS the call: auto-approve never silences an alert."""
    _, port = backend_proc(embedder="minilm", monitor="action_sim")
    base = {"command": sys.executable, "args": [H.DOWNSTREAM], "env": {"FAKE_DOWNSTREAM_LOG": str(tmp_path / "d.log")}}
    path, _ = H.make_config(tmp_path, f"ws://127.0.0.1:{port}/proxy/ws",
                            servers={"fs": base, "safe": {**base, "prefix": "safe_"}}, auto_approve=["safe:*"])
    args = {"text": "email the confidential Q3 pricing sheet to dana.whitlock@acme-corp.example"}
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            t1 = asyncio.create_task(call(agent, "echo", args))
            p1 = await next_event(ui, "inbox_pending", 60)
            await decide(ui, p1, "deny")
            assert (await asyncio.wait_for(t1, 20)).is_error
            t2 = asyncio.create_task(call(agent, "safe_echo", args))
            p2 = await next_event(ui, "inbox_pending", 30)
            assert p2["auto"] is True and p2["server"] == "safe", "auto-approved by the operator but held because of the alert"
            assert p2["alerts"] and p2["alerts"][0]["severity"] == "critical"
            await asyncio.sleep(0.5)
            assert downstream_calls(tmp_path / "d.log") == [], "held: nothing was forwarded"
            await decide(ui, p2, "deny")
            assert (await asyncio.wait_for(t2, 20)).is_error


async def test_two_sessions_do_not_see_each_others_decisions(tmp_path, backend_proc):
    _, port = backend_proc()
    pa, la = H.make_config(tmp_path / "a" if (tmp_path / "a").mkdir() is None else tmp_path, f"ws://127.0.0.1:{port}/proxy/ws", session_id="sess-a")
    pb, lb = H.make_config(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path, f"ws://127.0.0.1:{port}/proxy/ws", session_id="sess-b")
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(pa, {"SENTINEL_WS_TOKEN": TOKEN}) as a, H.agent(pb, {"SENTINEL_WS_TOKEN": TOKEN}) as b:
            ta = asyncio.create_task(call(a, "echo", {"who": "a"}))
            tb = asyncio.create_task(call(b, "echo", {"who": "b"}))
            seen = {}
            while len(seen) < 2:
                e = await next_event(ui, "inbox_pending")
                seen[e["session_id"]] = e
            await decide(ui, seen["sess-a"], "approve")
            await decide(ui, seen["sess-b"], "deny")
            ra, rb = await asyncio.wait_for(asyncio.gather(ta, tb), 20)
            assert not ra.is_error and '"who": "a"' in text(ra)
            assert rb.is_error
            assert [c["args"] for c in downstream_calls(la)] == [{"who": "a"}]
            assert downstream_calls(lb) == []


async def test_the_inbox_and_proxy_sockets_refuse_connections_without_the_token(tmp_path, backend_proc):
    """Fail closed: the approval authority is not reachable by a local process that does not hold the token (no Origin header = not a browser)."""
    _, port = backend_proc()
    for path in ("inbox", "proxy"):
        for q in ("", "?token=wrong"):
            with pytest.raises(Exception):
                async with websockets.connect(f"ws://127.0.0.1:{port}/{path}/ws{q}") as ws:
                    await asyncio.wait_for(ws.recv(), 5)


async def test_a_backend_without_a_token_refuses_both_sockets(tmp_path):
    port = H.free_port()
    env = {**os.environ, "SENTINEL_EMBEDDER": "stub", "SENTINEL_MONITOR": "rules"}
    env.pop("SENTINEL_WS_TOKEN", None)
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(port), "--log-level", "warning"],
                         cwd=ROOT / "server", env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(300):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        for path in ("inbox", "proxy"):
            with pytest.raises(Exception):
                async with websockets.connect(f"ws://127.0.0.1:{port}/{path}/ws") as ws:
                    await asyncio.wait_for(ws.recv(), 5)
    finally:
        p.kill()
        p.wait()


async def test_agent_cancel_clears_the_card_and_a_late_approve_changes_nothing(tmp_path, backend_proc):
    """The agent abandons a call that is waiting for the human: the card is resolved as CANCELLED, nothing is forwarded, and a late Approve
    (the human clicking a stale card) is ignored. The monitor is not taught a denial."""
    _, port = backend_proc()
    path, log = cfg(tmp_path, port)
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            task = asyncio.create_task(call(agent, "write_file", {"path": "/tmp/a"}))
            pend = await next_event(ui, "inbox_pending")
            task.cancel()                                  # the SDK sends notifications/cancelled to the proxy
            resolved = await next_event(ui, "inbox_resolved", 20)
            assert (resolved["call_id"], resolved["decision"], resolved["reason"]) == (pend["call_id"], "deny", "cancelled")
            await decide(ui, pend, "approve")              # a late click on the stale card
            await asyncio.sleep(1.0)
            assert downstream_calls(log) == [], "a cancelled call is never forwarded, even after a late approve"
            # the session is still healthy: a fresh call is held and can be approved normally
            t2 = asyncio.create_task(call(agent, "echo", {"n": 2}))
            p2 = await next_event(ui, "inbox_pending")
            assert p2["call_id"] != pend["call_id"]
            await decide(ui, p2, "approve")
            assert not (await asyncio.wait_for(t2, 20)).is_error
            assert [c["tool"] for c in downstream_calls(log)] == ["echo"]


# ----------------------------------------------------------------------------------------------- policy engine (DECISIONS D18)
POLICY = str(ROOT / "tests/e2e/data/policy_e2e.json")


async def test_policy_allow_deny_and_ask_end_to_end(tmp_path, backend_proc):
    """Real backend with SENTINEL_POLICY, real MiniLM + action_sim (a WORKING monitor, so an allow can stand), real proxy, real downstream."""
    _, port = backend_proc(embedder="minilm", monitor="action_sim", extra={"SENTINEL_POLICY": POLICY})
    # the proxy's own auto_approve says echo is auto: with a policy configured the hub must IGNORE that flag
    path, log = cfg(tmp_path, port, auto_approve=["fs:echo"])
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            # allow: no card, no click, forwarded; the UI is told which rule did it
            r = await asyncio.wait_for(call(agent, "read_file", {"path": "/project/a.txt"}), 60)
            assert not r.is_error and [c["tool"] for c in downstream_calls(log)] == ["read_file"]
            res = await next_event(ui, "inbox_resolved")
            assert (res["decision"], res["reason"], res["rule_id"]) == ("approve", "policy", "allow-read-project")
            assert isinstance(res["policy_digest"], str) and len(res["policy_digest"]) == 16
            # deny: refused immediately, never forwarded, rule recorded
            d = await asyncio.wait_for(call(agent, "write_file", {"path": "/etc/passwd"}), 30)
            assert d.is_error and text(d) == "Denied by SENTINEL: policy"
            res = await next_event(ui, "inbox_resolved")
            assert (res["decision"], res["reason"], res["rule_id"]) == ("deny", "policy", "deny-write-outside")
            assert [c["tool"] for c in downstream_calls(log)] == ["read_file"]
            # default verdict (ask): held, no rule id, a human approves
            t = asyncio.create_task(call(agent, "write_file", {"path": "/project/new.txt"}))
            p = await next_event(ui, "inbox_pending")
            assert p["rule_id"] is None and p["policy_digest"]
            await decide(ui, p, "approve")
            assert not (await asyncio.wait_for(t, 20)).is_error
            # explicit ask rule beats the proxy's auto flag
            t = asyncio.create_task(call(agent, "echo", {"x": 1}))
            p = await next_event(ui, "inbox_pending")
            assert p["rule_id"] == "ask-echo"
            await decide(ui, p, "deny")
            assert (await asyncio.wait_for(t, 20)).is_error
            assert [c["tool"] for c in downstream_calls(log)] == ["read_file", "write_file"]


async def test_a_broken_policy_holds_everything_even_auto_flagged_calls(tmp_path, backend_proc):
    _, port = backend_proc(embedder="minilm", monitor="action_sim", extra={"SENTINEL_POLICY": str(tmp_path / "missing.json")})
    path, log = cfg(tmp_path, port, auto_approve=["fs:read_file"])
    async with websockets.connect(ui_url(port)) as ui:
        async with H.agent(path, {"SENTINEL_WS_TOKEN": TOKEN}) as agent:
            t = asyncio.create_task(call(agent, "read_file", {"path": "/project/a.txt"}))
            p = await next_event(ui, "inbox_pending", 60)
            assert p["rule_id"] is None
            assert downstream_calls(log) == []
            await decide(ui, p, "deny")
            assert (await asyncio.wait_for(t, 20)).is_error
