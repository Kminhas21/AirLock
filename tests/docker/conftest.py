import asyncio
import json
"""Real-container tests (marker `docker`). Skipped unless SENTINEL_DOCKER_TESTS=1 and the images exist:
    scripts/docker_test.sh            builds the images (tests gate the build), then runs these
They never build anything themselves; they use SENTINEL_TEST_IMAGE (default sentinel:local) and SENTINEL_TEST_DEMO_IMAGE (default sentinel:demo)."""
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid

import pytest

IMAGE = os.environ.get("SENTINEL_TEST_IMAGE", "sentinel:local")
DEMO_IMAGE = os.environ.get("SENTINEL_TEST_DEMO_IMAGE", "sentinel:demo")
EMBEDDINGS = os.environ.get("SENTINEL_TEST_EMBEDDINGS", "1") == "1"      # was the image built with PyTorch and the baked-in model?
ADMIN, AGENT = secrets.token_hex(16), secrets.token_hex(16)        # fresh per run; they only ever exist in the test process and the containers' environment


def pytest_collection_modifyitems(config, items):
    reason = None
    if os.environ.get("SENTINEL_DOCKER_TESTS") != "1":
        reason = "SENTINEL_DOCKER_TESTS=1 not set"
    elif not shutil.which("docker") or subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        reason = "docker is not available"
    elif subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        reason = f"image {IMAGE} not built (run scripts/docker_test.sh)"
    if not reason:
        return
    for item in items:
        if item.get_closest_marker("docker") is not None:        # the MARKER, not the keyword: the directory is called `docker` too
            item.add_marker(pytest.mark.skip(reason=reason))


def sh(*args, check=True, timeout=120):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise AssertionError(f"{' '.join(args[:4])}... failed ({r.returncode}): {r.stdout[-500:]} {r.stderr[-800:]}")
    return r


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Container:
    def __init__(self, cid, port, name):
        self.id, self.port, self.name = cid, port, name

    def logs(self):
        r = sh("docker", "logs", self.id, check=False)
        return r.stdout + r.stderr

    def health(self):
        r = sh("docker", "inspect", "-f", "{{.State.Health.Status}}", self.id, check=False)
        return r.stdout.strip()

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def get_json(self, path):
        return json.loads(urllib.request.urlopen(self.url(path), timeout=10).read())

    def stop(self, timeout=30):
        sh("docker", "stop", "-t", str(timeout), self.id, check=False, timeout=timeout + 30)


@pytest.fixture
def start():
    """start(env=..., volume=..., network=..., name=..., extra=[...]) -> Container (healthy). Everything started is removed afterwards."""
    started = []

    def _start(env=None, volume=None, network=None, name=None, extra=(), wait_healthy=True, image=None):
        port = free_port()
        name = name or f"sentineltest-{uuid.uuid4().hex[:8]}"
        cmd = ["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:8080", "--read-only", "--tmpfs", "/tmp:size=64m,mode=1777",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "3g"]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if volume:
            cmd += ["-v", f"{volume}:/var/lib/sentinel"]
        if network:
            cmd += ["--network", network]
        cmd += list(extra) + [image or IMAGE]
        cid = sh(*cmd).stdout.strip()
        c = Container(cid, port, name)
        started.append(c)
        if wait_healthy:
            deadline = time.time() + 150
            while time.time() < deadline:
                if c.health() == "healthy":
                    break
                if sh("docker", "inspect", "-f", "{{.State.Running}}", cid, check=False).stdout.strip() != "true":
                    raise AssertionError("container exited early:\n" + c.logs()[-2000:])
                time.sleep(1.5)
            else:
                raise AssertionError("container never became healthy:\n" + c.logs()[-2000:])
        return c

    yield _start
    for c in started:
        sh("docker", "rm", "-f", "-v", c.id, check=False)


@pytest.fixture
def volume():
    name = f"sentineltest-vol-{uuid.uuid4().hex[:8]}"
    sh("docker", "volume", "create", name)
    yield name
    sh("docker", "volume", "rm", "-f", name, check=False)


@pytest.fixture
def network():
    name = f"sentineltest-net-{uuid.uuid4().hex[:8]}"
    sh("docker", "network", "create", name)
    yield name
    sh("docker", "network", "rm", name, check=False)


BOOT_ENV = {"SENTINEL_BOOTSTRAP_ADMIN_TOKEN": ADMIN, "SENTINEL_BOOTSTRAP_AGENT_TOKEN": AGENT, "SENTINEL_ALLOWED_ORIGINS": "http://localhost:8080",
            "SENTINEL_EVENT_LOG": "/var/lib/sentinel/events.db", "SENTINEL_LOG_KEY": secrets.token_hex(16)}


async def next_pending(ws, timeout=120):
    """The first held call an operator sees. A late-joining operator gets it inside `inbox_snapshot`
    (sessions[].pending); one already connected gets a live `inbox_pending` -- both are the same call."""
    async def go():
        while True:
            e = json.loads(await ws.recv())
            if e.get("event") == "inbox_pending":
                return e
            if e.get("event") == "inbox_snapshot":
                for sess in e.get("sessions", []):
                    if sess.get("pending"):
                        return {**sess["pending"][0], "session_id": sess["session_id"]}
    return await asyncio.wait_for(go(), timeout)
