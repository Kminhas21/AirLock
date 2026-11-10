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
