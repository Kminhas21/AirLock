"""docker-compose.yml, for real: valid, starts the hub healthy with the hardened settings, and the demo profile carries a call to a human decision."""
import asyncio
import json
import secrets
import subprocess
import urllib.request
import uuid
from pathlib import Path

import pytest
import websockets

from conftest import EMBEDDINGS, free_port, next_pending, sh

pytestmark = pytest.mark.docker
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def stack(tmp_path):
    admin, agent = secrets.token_hex(16), secrets.token_hex(16)
    port = free_port()
    project = f"sentineltest{uuid.uuid4().hex[:6]}"
    env = tmp_path / ".env"
    env.write_text(f"SENTINEL_BOOTSTRAP_ADMIN_TOKEN={admin}\nSENTINEL_BOOTSTRAP_AGENT_TOKEN={agent}\nSENTINEL_HOST_PORT={port}\n"
                   f"SENTINEL_ALLOWED_ORIGINS=http://localhost:{port}\nSENTINEL_LOG_KEY={secrets.token_hex(16)}\n")

    def compose(*args, check=True, timeout=300):
        return sh("docker", "compose", "-p", project, "--env-file", str(env), "-f", str(ROOT / "docker-compose.yml"), *args, check=check, timeout=timeout)

    base = ["docker", "compose", "-p", project, "--env-file", str(env), "-f", str(ROOT / "docker-compose.yml")]
    yield type("S", (), dict(compose=staticmethod(compose), argv=staticmethod(lambda *a: base + list(a)), admin=admin, agent=agent, port=port, project=project))
    compose("--profile", "demo", "down", "-v", "--remove-orphans", check=False, timeout=120)


def test_the_compose_file_is_valid_and_renders_the_hardened_settings(stack):
    cfg = json.loads(stack.compose("config", "--format", "json").stdout)
    s = cfg["services"]["sentinel"]
    assert s["read_only"] is True and s["cap_drop"] == ["ALL"] and "no-new-privileges:true" in s["security_opt"]
    assert s["ports"][0]["host_ip"] == "127.0.0.1" and int(s["ports"][0]["published"]) == stack.port
    assert "demo-agent" not in cfg["services"], "the demo profile must not be part of a plain `up`"


async def test_up_serves_the_hub_and_the_demo_profile_carries_a_call_to_a_human_decision(stack):
    stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", timeout=260)
    h = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{stack.port}/health", timeout=10).read())
    assert h["status"] == "ok" and h["embedder"] == ("minilm" if EMBEDDINGS else "stub")
    # the demo agent blocks until a human decides, so start it in the background through compose
    proc = subprocess.Popen(stack.argv("--profile", "demo", "run", "--rm", "demo-agent"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ws = await websockets.connect(f"ws://127.0.0.1:{stack.port}/inbox/ws", additional_headers={"Authorization": f"Bearer {stack.admin}"})
    try:
        async def until(name, timeout=120):
            async def go():
                while True:
                    e = json.loads(await ws.recv())
                    if e.get("event") == name:
                        return e
            return await asyncio.wait_for(go(), timeout)
        await until("auth_ok")
        try:
            pend = await next_pending(ws, 150)
        except TimeoutError:
            proc.kill()
            raise AssertionError("no held call reached the operator; demo-agent said:\n" + (proc.communicate()[0] or "")[-2500:])
        assert pend["tool"] == "write_file" and pend["args"]["path"] == "/tmp/report.txt"
        await ws.send(json.dumps({"event": "inbox_decision", "session_id": pend["session_id"], "call_id": pend["call_id"], "decision": "deny"}))
        out, _ = proc.communicate(timeout=120)
        assert '"is_error": true' in out and "Denied by SENTINEL: human" in out, out[-1500:]
    finally:
        await ws.close()
        proc.kill()
