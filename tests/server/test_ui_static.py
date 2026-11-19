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


# ---- structural guards (they parse the spec text; each is proven red against a deliberately broken copy of the REAL journeys below)
_PATH_KEYS = r"(?:path|paths|file|files|file_path|filename|dir|directory|destination|source|src|dest)"


def _enclosing_object(text: str, idx: int) -> str:
    depth, i = 0, idx
    while i > 0:
        i -= 1
        if text[i] == "}":
            depth += 1
        elif text[i] == "{":
            if depth == 0:
                break
            depth -= 1
    start, depth = i, 0
    for j in range(start, len(text)):
        depth += (text[j] == "{") - (text[j] == "}")
        if depth == 0:
            return text[start:j + 1]
    return text[start:]


def server_config_problems(text: str) -> list[str]:
    """Any server config with a sandbox or runtime whose command is a non-absolute string literal (the trampoline looks a bare command up in
    /usr/bin only; on a GitHub runner the interpreter is under /opt/hostedtoolcache)."""
    out = []
    for m in _re.finditer(r"\bcommand:\s*([^,}\n]+)", text):
        obj = _enclosing_object(text, m.start())
        expr = m.group(1).strip()
        if ("sandbox" in obj or "runtime" in obj) and _re.match(r"""["'`]""", expr) and not _re.match(r"""["'`]/""", expr):
            out.append(f"sandboxed server with the non-absolute command {expr}")
    return out


def _agent_definition(text: str, var: str) -> str:
    m = _re.search(rf"(?:const|let)\s+{_re.escape(var)}\s*=\s*", text)
    if not m:
        return ""
    i, depth = m.end(), 0
    for j in range(i, len(text)):
        depth += text[j] in "([{"
        depth -= text[j] in ")]}"
        if depth == 0 and text[j] in ";\n":
            return text[i:j]
    return text[i:]


def unconfined_auto_allow_problems(text: str) -> list[str]:
    """A call with a path-like argument that the journey awaits DIRECTLY and expects to succeed (no card, no click) is auto-allowed by a rule; after
    D31 that needs a sandboxed server with runtime (an unsandboxed one asks every time, and the call hangs). Calls held for a card are assigned
    without await and decided by a click: not flagged."""
    out = []
    for m in _re.finditer(r"""(?:(?:const|let)\s+(\w+)\s*=\s*)?await\s+(\w+)\.call\(\s*["'](\w+)["']\s*,\s*\{([^}]*)\}""", text):
        name, var, tool, args = m.groups()
        if not _re.search(rf"\b{_PATH_KEYS}\s*:", args):
            continue
        tail = text[m.end(): m.end() + 120]
        expects_ok = _re.match(r"\)\)?\.is_error\)\.toBe\(false\)", tail) is not None or (name and _re.search(rf"expect\({name}\.is_error\)\.toBe\(false\)", text))
        if not expects_ok:
            continue
        defn = _agent_definition(text, var)
        if "sandboxedServer(" not in defn and not ("sandbox" in defn and "runtime" in defn):
            out.append(f"{var}.call({tool!r}, path-like args) is expected to succeed with no card but {var} has no sandboxed server with runtime")
    return out


def missing_rule_problems(text: str, defined: set[str]) -> list[str]:
    named = set(_re.findall(r'data-rule-id="([\w-]+)"', text)) | set(_re.findall(r"auto-allowed by rule ([\w-]+)", text))
    return sorted(f"rule {r} does not exist in the policy this journey uses" for r in named - defined)


def _policy_rules(text: str) -> set[str]:
    ids = set(_re.findall(r'["\']id["\']\s*:\s*["\']([\w-]+)["\']', text))
    for rel in _re.findall(r'["\'](tests/[\w./-]+\.json)["\']', text):
        f = _ROOT / rel
        if f.exists():
            ids |= {r["id"] for r in _json.loads(f.read_text()).get("rules", [])}
    return ids


def _journey_problems(text: str) -> list[str]:
    return server_config_problems(text) + unconfined_auto_allow_problems(text) + missing_rule_problems(text, _policy_rules(text))


@needs_journeys
def test_the_audited_journeys_are_clean_under_every_structural_guard():
    assert len(_JOURNEYS) >= 8
    bad = {f.name: p for f in _JOURNEYS if (p := _journey_problems(f.read_text()))}
    lib = (_ROOT / "frontend" / "journeys" / "lib.ts").read_text()
    assert bad == {} and server_config_problems(lib) == []


def _scratch(name, old, new):
    text = (_ROOT / "frontend" / "journeys" / name).read_text()
    assert old in text, (name, old)
    return text.replace(old, new)


@needs_journeys
def test_guard_bare_python_for_a_sandboxed_server_is_red_on_a_broken_copy():
    assert server_config_problems(_scratch("j5-boundary.spec.ts", "command: pythonPath(),", 'command: "python",'))
    assert server_config_problems(_scratch("j5-boundary.spec.ts", "command: pythonPath(),", "command: 'python3',"))
    assert server_config_problems('const s = { command: "/usr/bin/python3", sandbox: { runtime: [] } };') == []        # an absolute literal is fine
    assert server_config_problems('const s = { command: "python", args: [] };') == []                                   # unsandboxed: not this guard's business


@needs_journeys
def test_guard_unconfined_auto_allow_is_red_on_a_broken_copy():
    assert unconfined_auto_allow_problems(_scratch("j2-operator.spec.ts", "agent(\"w2-second-session\", { fs: sandboxedServer([DOWNSTREAM]) })", 'agent("w2-second-session")'))
    assert unconfined_auto_allow_problems('const b = agent("x");\nexpect((await b.call("read_file", { path: "/p" })).is_error).toBe(false);')
    assert unconfined_auto_allow_problems('const c = startAgent({ dir });\nconst r = await c.call("write_file", { file: "/p" });\nexpect(r.is_error).toBe(false);')
    assert unconfined_auto_allow_problems('const c = startAgent({ servers: { fs: sandboxedServer([D]) } });\nexpect((await c.call("read_file", { path: "/p" })).is_error).toBe(false);') == []
    assert unconfined_auto_allow_problems('const c = agent("x");\nconst held = c.call("read_file", { path: "/p" });') == []                   # held for a card, decided by a click
    assert unconfined_auto_allow_problems('const c = agent("x");\nconst d = await c.call("write_file", { path: "/etc/passwd" });\nexpect(d.text).toBe("Denied");') == []


@needs_journeys
def test_guard_a_rule_that_does_not_exist_is_red_on_a_broken_copy():
    text = _scratch("j4-policy.spec.ts", "allow-echo-n", "allow-read-project")
    assert missing_rule_problems(text, _policy_rules(text))
    assert missing_rule_problems('data-rule-id="a" auto-allowed by rule b', {"a"}) == ["rule b does not exist in the policy this journey uses"]
