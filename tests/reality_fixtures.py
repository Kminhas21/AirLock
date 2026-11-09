"""Fixtures for the reality suites (tests/hostile, tests/realdeps, tests/load). A plain module on purpose: a second `conftest.py` would shadow the
`from conftest import ...` used by the older suites (their imports resolve to whichever conftest was loaded last)."""
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from tests.harness import ROOT, Backend

DEPS = ROOT / ".realdeps"



def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(url: str, proc: subprocess.Popen, seconds: int = 120):
    for _ in range(seconds * 4):
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early: {proc.returncode}")
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError(f"{url} never came up")


class Stack:
    def __init__(self, port: int, llm_port: int, log: Path):
        self.port, self.llm_port, self.log = port, llm_port, log

    def log_text(self) -> str:
        return self.log.read_text(errors="replace") if self.log.exists() else ""


@pytest.fixture(scope="session")
def stack(tmp_path_factory):
    llm_port, port = _port(), _port()
    log = tmp_path_factory.mktemp("hostile") / "backend.log"
    llm = subprocess.Popen([sys.executable, str(ROOT / "tests/browser/hostile_llm.py"), str(llm_port)], cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = {**os.environ, "OPENROUTER_API_KEY": "test-key", "OPENROUTER_BASE_URL": f"http://127.0.0.1:{llm_port}/v1",
           "SENTINEL_EMBEDDER": "minilm", "SENTINEL_MONITOR": "action_sim", "HF_HUB_OFFLINE": "1", "SENTINEL_GATE_TIMEOUT_S": "60",
           "SENTINEL_DEFAULT_MODEL": "gpt-4o-mini"}
    for k in ("SENTINEL_WS_TOKEN", "SENTINEL_IDENTITY_FILE", "SENTINEL_ALLOWED_ORIGINS"):
        env.pop(k, None)
    with open(log, "w") as lf:
        backend = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--port", str(port), "--log-level", "info"],
                                   cwd=ROOT / "server", env=env, stdout=lf, stderr=subprocess.STDOUT)
        try:
            _wait(f"http://127.0.0.1:{llm_port}/modes", llm)
            _wait(f"http://127.0.0.1:{port}/health", backend)
            yield Stack(port, llm_port, log)
        finally:
            backend.terminate()
            llm.terminate()
            for p in (backend, llm):
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()



@pytest.fixture(scope="session")
def realdeps():
    r = subprocess.run(["bash", str(ROOT / "scripts/realdeps_setup.sh")], capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        msg = f"real MCP servers could not be installed (no network?):\n{(r.stdout + r.stderr)[-800:]}"
        if os.environ.get("REALDEPS_REQUIRED") == "1":
            pytest.fail(msg)                              # the gate: a missing dependency is a FAILURE, never a silent skip
        pytest.skip(msg)
    return {"filesystem": str(DEPS / "node_modules/.bin/mcp-server-filesystem"), "memory": str(DEPS / "node_modules/.bin/mcp-server-memory"),
            "time": str(DEPS / "tv/bin/mcp-server-time")}



@pytest.fixture(scope="session")
def backend(tmp_path_factory):
    b = Backend(tmp_path_factory.mktemp("realdeps") / "backend.log")
    yield b
    b.stop()
