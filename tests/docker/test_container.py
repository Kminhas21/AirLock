"""The built image, for real: it must come up healthy with the model baked in, serve the UI, authenticate, refuse bad config, run read-only and non-root,
persist its data, and carry a call from a proxy in another container to a human decision and back."""
import asyncio
import json

import pytest
import websockets

from conftest import ADMIN, AGENT, BOOT_ENV, DEMO_IMAGE, IMAGE, sh

pytestmark = pytest.mark.docker


async def operator(port, token, *, header=True):
    hdr = {"Authorization": f"Bearer {token}"} if header else {}
    ws = await websockets.connect(f"ws://127.0.0.1:{port}/inbox/ws", additional_headers=hdr)
    if not header:
        await ws.send(json.dumps({"event": "auth", "token": token}))
    return ws


async def recv_until(ws, name, timeout=60, **where):
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == name and all(e.get(k) == v for k, v in where.items()):
                return e
    return await asyncio.wait_for(go(), timeout)


def test_the_image_starts_healthy_runs_as_non_root_and_has_the_model_baked_in(start):
    c = start(env=BOOT_ENV)
    assert c.health() == "healthy"
    assert sh("docker", "exec", c.id, "id", "-u").stdout.strip() == "10001"
    h = c.get_json("/health")
    assert h["status"] == "ok"
    assert h["embedder"] == "minilm" and h["monitor"] == "action_sim", f"the baked-in model was not used (no network needed at run time): {h}"
    assert h["monitor_errors"] == 0 and h["session_fallbacks"] == 0


def test_the_root_filesystem_is_read_only_but_the_data_volume_and_tmp_are_writable(start, volume):
    c = start(env=BOOT_ENV, volume=volume)
    assert sh("docker", "exec", c.id, "sh", "-c", "touch /app/x", check=False).returncode != 0
    assert sh("docker", "exec", c.id, "sh", "-c", "touch /tmp/x && touch /var/lib/sentinel/x").returncode == 0


def test_the_ui_is_served_with_security_headers_and_the_api_routes_still_win(start):
    import urllib.request
    c = start(env=BOOT_ENV)
    r = urllib.request.urlopen(c.url("/"), timeout=10)
    body = r.read().decode()
    assert r.status == 200 and "<div id=\"root\">" in body or "<div id='root'>" in body or "id=\"root\"" in body
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert c.get_json("/health")["status"] == "ok"
    import re
    asset = re.search(r'/assets/[\w\-.]+\.js', body).group(0)
    a = urllib.request.urlopen(c.url(asset), timeout=10)
    assert a.status == 200 and "immutable" in a.headers["Cache-Control"]


async def test_sign_in_works_with_the_bootstrap_credentials_and_is_refused_otherwise(start):
    c = start(env=BOOT_ENV)
    ws = await operator(c.port, ADMIN)
    ok = await recv_until(ws, "auth_ok")
    assert ok["principal"] == {"id": "admin", "tenant": "default", "role": "admin"}
    assert (await recv_until(ws, "inbox_snapshot"))["capabilities"]["can_decide"] is True
    await ws.close()
    ws = await operator(c.port, ADMIN, header=False)                       # the browser's way: first frame
    assert (await recv_until(ws, "auth_ok"))["principal"]["id"] == "admin"
    await ws.close()
    for bad in ("not-the-token", AGENT):                                  # an AGENT token is not an operator credential
        ws = await operator(c.port, bad)
        with pytest.raises(websockets.ConnectionClosed):
            while True:
                assert json.loads(await asyncio.wait_for(ws.recv(), 15))["event"] != "auth_ok"


@pytest.mark.parametrize("env,message", [
    ({}, "no credentials configured"),
    ({"SENTINEL_WS_TOKEN": "short"}, "at least 16"),
    ({"SENTINEL_BOOTSTRAP_ADMIN_TOKEN": "tiny", "SENTINEL_BOOTSTRAP_AGENT_TOKEN": "x" * 30}, "must be at least"),
    ({"SENTINEL_BOOTSTRAP_ADMIN_TOKEN": "x" * 30, "SENTINEL_BOOTSTRAP_AGENT_TOKEN": "x" * 30}, "must differ"),
    ({"SENTINEL_IDENTITY_FILE": "/etc/sentinel/missing.json"}, "not readable"),
])
def test_bad_configuration_fails_fast_with_a_clear_message_instead_of_starting(env, message):
    cmd = ["docker", "run", "--rm", "--read-only", "--tmpfs", "/var/lib/sentinel:uid=10001,mode=700"]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    r = sh(*cmd, IMAGE, "check", check=False)
    assert r.returncode == 2, r.stdout + r.stderr
    assert message in r.stderr
    assert not any(v in r.stdout + r.stderr for v in env.values() if len(v) >= 16), "a credential value was printed"


def test_no_credential_is_baked_into_the_image(start):
    cfg = sh("docker", "image", "inspect", "-f", "{{json .Config.Env}}", IMAGE).stdout
    assert ADMIN not in cfg and AGENT not in cfg
    for needle in ("TOKEN=", "SECRET=", "PASSWORD=", "LOG_KEY="):
        assert needle not in cfg, needle
    hist = sh("docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", IMAGE).stdout
    assert ADMIN not in hist and AGENT not in hist and "buildca" not in hist.replace("--mount=type=secret,id=buildca,required=false", "")


async def test_a_call_from_a_proxy_in_another_container_is_held_decided_logged_and_the_data_survives_a_restart(start, volume, network):
    c = start(env=BOOT_ENV, volume=volume, network=network, name=f"sentinel-{network[-8:]}")
    # the demo proxy config addresses the hub as `sentinel`: give the hub that network alias
    sh("docker", "network", "connect", "--alias", "sentinel", network, c.id, check=False)
    demo = sh("docker", "run", "-d", "--network", network, "--read-only", "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL",
              "-e", f"SENTINEL_AGENT_TOKEN={AGENT}", "-e", "SENTINEL_AGENT_PASSTHROUGH=SENTINEL_AGENT_TOKEN", "--entrypoint", "python", DEMO_IMAGE,
              "/app/demo_agent/agent_cli.py", "/etc/sentinel/demo-proxy.json", "write_file", '{"path": "/tmp/report.txt", "content": "q3"}').stdout.strip()
    try:
        ws = await operator(c.port, ADMIN)
        await recv_until(ws, "auth_ok")
        pend = await recv_until(ws, "inbox_pending", timeout=90)
        assert (pend["tool"], pend["agent_id"], pend["tenant"]) == ("write_file", "agent", "default")
        assert pend["args"] == {"path": "/tmp/report.txt", "content": "q3"}
        await ws.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": "approve"}))
        resolved = await recv_until(ws, "inbox_resolved")
        assert (resolved["decision"], resolved["operator"]) == ("approve", "admin")
        assert sh("docker", "wait", demo, timeout=90).stdout.strip() == "0", sh("docker", "logs", demo, check=False).stdout
        out = sh("docker", "logs", demo, check=False).stdout
        assert '"is_error": false' in out
        await ws.close()
    finally:
        sh("docker", "rm", "-f", demo, check=False)
    c.stop()                                                                # graceful: the event log writes its final checkpoint
    # a SECOND container on the same volume: identity persisted (bootstrap did not rewrite it), log verifies and holds the decision
    v = sh("docker", "run", "--rm", "-v", f"{volume}:/var/lib/sentinel", "-e", f"SENTINEL_LOG_KEY={BOOT_ENV['SENTINEL_LOG_KEY']}", IMAGE,
           "python", "-m", "eventlog_cli", "verify", "/var/lib/sentinel/events.db", check=False, timeout=120)
    assert v.returncode == 0, v.stdout + v.stderr
    ex = sh("docker", "run", "--rm", "-v", f"{volume}:/var/lib/sentinel", IMAGE, "python", "-m", "eventlog_cli", "export", "/var/lib/sentinel/events.db", "--jsonl").stdout
    decisions = [json.loads(l)["payload"] for l in ex.splitlines() if '"kind": "decision"' in l or '"kind":"decision"' in l]
    assert [(d["decision"], d["operator"]) for d in decisions] == [("approve", "admin")]
    c2 = start(env=BOOT_ENV, volume=volume)
    ws = await operator(c2.port, ADMIN)
    assert (await recv_until(ws, "auth_ok"))["principal"]["id"] == "admin"      # the same credentials still work after the restart
    await ws.close()
