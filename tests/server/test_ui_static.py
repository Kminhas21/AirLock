"""The backend can serve the built UI (SENTINEL_UI_DIR); API and websocket routes must keep priority, and the static mount must be safe."""
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import ui_static

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def ui_dir(tmp_path):
    d = tmp_path / "dist"
    (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text("<!doctype html><title>ui</title>")
    (d / "assets" / "app-abc123.js").write_text("console.log(1)")
    (tmp_path / "secret.txt").write_text("TOP-SECRET")           # a sibling of dist: must never be reachable
    return d


def make_app(ui_dir):
    app = FastAPI()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"hello": 1})
        await websocket.close()

    assert ui_static.mount_ui(app, ui_dir) is True
    return app


def test_index_and_assets_are_served_with_headers_and_caching(ui_dir):
    c = TestClient(make_app(ui_dir))
    r = c.get("/")
    assert r.status_code == 200 and "<title>ui</title>" in r.text
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-cache"
    a = c.get("/assets/app-abc123.js")
    assert a.status_code == 200 and "immutable" in a.headers["cache-control"] and a.headers["x-content-type-options"] == "nosniff"


def test_api_and_websocket_routes_win_over_the_static_mount(ui_dir):
    c = TestClient(make_app(ui_dir))
    assert c.get("/health").json() == {"status": "ok"}
    with c.websocket_connect("/ws") as ws:
        assert ws.receive_json() == {"hello": 1}


def test_a_websocket_to_an_unknown_path_is_closed_cleanly_not_with_an_error(ui_dir):
    c = TestClient(make_app(ui_dir))
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/not/a/route"):
            pass
    assert e.value.code == 1008


@pytest.mark.parametrize("path", ["/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt", "/assets/../../secret.txt", "//etc/passwd", "/%00", "/assets/%2e%2e/%2e%2e/secret.txt"])
def test_path_traversal_never_reaches_files_outside_the_ui_directory(ui_dir, path):
    r = TestClient(make_app(ui_dir)).get(path)
    assert "TOP-SECRET" not in r.text and "root:" not in r.text
    assert r.status_code in (400, 404) or r.text.startswith("<!doctype html>")


def test_unknown_files_are_404_and_methods_other_than_get_are_refused(ui_dir):
    c = TestClient(make_app(ui_dir))
    assert c.get("/nope.js").status_code == 404
    assert c.post("/").status_code in (404, 405)


def test_a_missing_or_incomplete_directory_mounts_nothing(tmp_path):
    app = FastAPI()
    assert ui_static.mount_ui(app, tmp_path / "missing") is False
    (tmp_path / "empty").mkdir()
    assert ui_static.mount_ui(app, tmp_path / "empty") is False                  # no index.html
    assert ui_static.mount_ui_from_env(app, {}) is False and ui_static.mount_ui_from_env(app, {"SENTINEL_UI_DIR": "  "}) is False
    assert TestClient(app).get("/").status_code == 404


def test_the_real_app_serves_the_ui_only_when_asked_and_keeps_its_own_routes(ui_dir):
    """Import server/main.py in a fresh interpreter (the mount happens at import time)."""
    code = (
        "import json; from fastapi.testclient import TestClient; import main; c = TestClient(main.app)\n"
        "r = c.get('/'); h = c.get('/health')\n"
        "print(json.dumps({'root': r.status_code, 'title': '<title>ui</title>' in r.text, 'health': h.json()['status'], 'inbox_ws_unauth': None}))\n"
        "try:\n"
        "    with c.websocket_connect('/inbox/ws'):\n"
        "        pass\n"
        "except Exception as e:\n"
        "    print(type(e).__name__)\n")
    env = {**os.environ, "SENTINEL_EMBEDDER": "stub", "HF_HUB_OFFLINE": "1"}
    env.pop("SENTINEL_WS_TOKEN", None)
    served = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "server", env={**env, "SENTINEL_UI_DIR": str(ui_dir)}, capture_output=True, text=True, timeout=120)
    assert served.returncode == 0, served.stderr
    assert '"root": 200' in served.stdout and '"title": true' in served.stdout and '"health": "ok"' in served.stdout
    assert "WebSocketDisconnect" in served.stdout                              # /inbox/ws still refuses unauthenticated clients: the mount did not shadow it
    plain = subprocess.run([sys.executable, "-c", code], cwd=ROOT / "server", env=env, capture_output=True, text=True, timeout=120)
    assert '"root": 404' in plain.stdout and '"health": "ok"' in plain.stdout   # without SENTINEL_UI_DIR nothing is served


# ------------------------------------------------------------------------------------------------------------------------------------ journeys vs the product
# First full-tier run on GitHub: W2/W4 (read_file auto-allowed by a rule with no sandbox) and W5 (a sandboxed server started with a bare `python`) failed.
# They were written before D31 (kernel-confined auto-allows: an unsandboxed server asks every time; policy_e2e.json lost its read rule) and before the
# runner fix of cb635a0 (the sandbox trampoline looks a bare command up in /usr/bin only, and a GitHub runner's python is under /opt/hostedtoolcache).
import json as _json
import re as _re
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parents[2]
_JOURNEYS = sorted((_ROOT / "frontend" / "journeys").glob("j*.spec.ts"))
# the test image copies frontend/src but not frontend/journeys: these run on the host and in CI, not inside the image's test stage
needs_journeys = pytest.mark.skipif(not _JOURNEYS, reason="frontend/journeys is not in this tree (the Docker test stage)")


@needs_journeys
def test_no_journey_starts_a_sandboxed_server_with_a_bare_python():
    bad = []
    for f in _JOURNEYS:
        lines = f.read_text().splitlines()
        for i, line in enumerate(lines):
            if "sandbox:" in line and any('command: "python"' in l for l in lines[max(0, i - 2):i + 1]):
                bad.append(f"{f.name}:{i + 1}")
    assert bad == [], f"a sandboxed server needs the absolute interpreter (lib.ts `pythonPath()`): {bad}"


@needs_journeys
def test_every_rule_a_journey_expects_exists_in_the_policy_it_copies():
    rules = {r["id"] for r in _json.loads((_ROOT / "tests" / "e2e" / "data" / "policy_e2e.json").read_text())["rules"]}
    for f in _JOURNEYS:
        text = f.read_text()
        if "policy_e2e.json" not in text:
            continue
        named = set(_re.findall(r'data-rule-id="([\w-]+)"', text)) | set(_re.findall(r"auto-allowed by rule ([\w-]+)", text))
        assert named <= rules, (f.name, sorted(named - rules))


@needs_journeys
def test_a_journey_that_expects_a_standing_read_rule_to_auto_allow_uses_a_sandboxed_server_with_runtime():
    text = (_ROOT / "frontend" / "journeys" / "j2-operator.spec.ts").read_text()
    line = next(l for l in text.splitlines() if 'agent("w2-second-session"' in l)
    assert "sandboxedServer" in line, "D31: an unsandboxed server asks every time, so a standing rule only decides in a sandboxed session"
    lib = (_ROOT / "frontend" / "journeys" / "lib.ts").read_text()
    assert "runtime:" in lib and "pythonPath" in lib
