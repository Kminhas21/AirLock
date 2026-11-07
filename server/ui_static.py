"""Serve the BUILT UI (frontend/dist) from the backend itself, so one container / one origin serves both (no CORS, no second web server).

Enabled only when SENTINEL_UI_DIR points at a directory. Mounted LAST in main.py, so every API and websocket route keeps priority over the static
files. Static responses get conservative headers; a websocket request that reaches the static mount (an unknown path) is closed with 1008 instead of
raising inside Starlette."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Mapping

from starlette.staticfiles import StaticFiles

log = logging.getLogger(__name__)

ENV_VAR = "SENTINEL_UI_DIR"
_SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
)


class _StaticWithHeaders:
    """ASGI wrapper around StaticFiles: security headers, sane caching, and a clean close for websocket scopes."""

    def __init__(self, directory: str):
        self._static = StaticFiles(directory=directory, html=True)

    async def __call__(self, scope: Mapping[str, Any], receive, send) -> None:
        if scope["type"] == "websocket":
            await receive()                                   # the connect message
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        path = scope.get("path", "")

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in {h for h, _ in _SECURITY_HEADERS}]
                headers.extend(_SECURITY_HEADERS)
                if path.startswith("/assets/"):               # hashed file names: cache for a year
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"public, max-age=31536000, immutable"))
                elif path in ("/", "/index.html") or path.endswith(".html"):
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"no-cache"))
                message = {**message, "headers": headers}
            await send(message)

        await self._static(scope, receive, send_with_headers)


def mount_ui(app: Any, directory: str | os.PathLike) -> bool:
    """Mount the UI at '/'. False (and nothing mounted) when the directory does not exist or has no index.html."""
    d = Path(directory)
    if not d.is_dir() or not (d / "index.html").is_file():
        log.warning("SENTINEL_UI_DIR=%s is not a directory with an index.html; the UI is NOT served", d)
        return False
    app.mount("/", _StaticWithHeaders(str(d)), name="ui")
    log.info("serving the UI from %s", d)
    return True


def mount_ui_from_env(app: Any, env: Mapping[str, str] = os.environ) -> bool:
    d = (env.get(ENV_VAR) or "").strip()
    return mount_ui(app, d) if d else False
