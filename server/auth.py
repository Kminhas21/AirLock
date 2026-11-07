"""WebSocket access control (A1 / bug B3). Pure: no FastAPI/Starlette imports."""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Mapping

DEFAULT_ALLOWED_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")


@dataclass(frozen=True)
class AccessResult:
    allowed: bool
    reason: str  # "open" | "ok" | "bad_token" | "bad_origin"


def _allowed_origins(env: Mapping[str, str]) -> set[str]:
    parsed = {o.strip() for o in env.get("SENTINEL_ALLOWED_ORIGINS", "").split(",")}
    parsed.discard("")
    return parsed or set(DEFAULT_ALLOWED_ORIGINS)


def check_ws_access(
    origin: str | None, token: str | None, env: Mapping[str, str] = os.environ
) -> AccessResult:
    # An Origin header that is present (even empty or "null") must be allow-listed;
    # only a truly absent header (non-browser client) skips the check.
    if origin is not None and origin not in _allowed_origins(env):
        return AccessResult(False, "bad_origin")

    expected = env.get("SENTINEL_WS_TOKEN", "")
    if not expected:
        return AccessResult(True, "open")
    # Encode to bytes: compare_digest raises TypeError on non-ASCII str.
    if not hmac.compare_digest((token or "").encode(), expected.encode()):
        return AccessResult(False, "bad_token")
    return AccessResult(True, "ok")
