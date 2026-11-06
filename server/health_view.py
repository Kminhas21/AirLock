"""What /health shows to whom (hardening of DECISIONS D11: /health used to be unauthenticated AND showed file paths).

PUBLIC view (default): the same keys, but registry / frozen-model PATHS are reduced to the file name and the last per-session
fallback text keeps only "<mode> -> <used>: <ExceptionType>" (the message can carry file paths and parsed content).
DETAIL view (full paths and message): only when the caller proves it may see it:
  * SENTINEL_WS_TOKEN is set  -> the request carries that token (``?token=`` or ``Authorization: Bearer``);
  * SENTINEL_WS_TOKEN is unset -> only when the operator opted in with SENTINEL_HEALTH_DETAIL=1 (local development).
Pure: no FastAPI imports.
"""
from __future__ import annotations

import copy
import hmac
import os
from pathlib import PurePath
from typing import Mapping


def detail_allowed(query_token: str | None, authorization: str | None, env: Mapping[str, str] = os.environ) -> bool:
    expected = env.get("SENTINEL_WS_TOKEN", "")
    if not expected:
        return env.get("SENTINEL_HEALTH_DETAIL", "").strip() == "1"
    supplied = query_token or ""
    if not supplied and authorization and authorization[:7].lower() == "bearer ":
        supplied = authorization[7:].strip()
    return hmac.compare_digest(supplied.encode(), expected.encode())


def _name(path: object) -> object:
    return PurePath(str(path)).name if isinstance(path, str) and path else path


def _fallback_head(text: object) -> object:
    """'<mode> -> <used>: <ExcType>: <message>' -> '<mode> -> <used>: <ExcType>'."""
    if not isinstance(text, str):
        return text
    head, sep, rest = text.partition(": ")
    if not sep:
        return text
    exc = rest.split(": ", 1)[0]
    return f"{head}: {exc}"


def public_view(info: dict) -> dict:
    out = copy.deepcopy(info)
    for key in ("registry", "frozen_model"):
        if isinstance(out.get(key), dict) and "path" in out[key]:
            out[key]["path"] = _name(out[key]["path"])
    if "last_session_fallback" in out:
        out["last_session_fallback"] = _fallback_head(out["last_session_fallback"])
    return out


def policy_view(path: str, policy: object, detail: bool) -> dict:
    """/health `policy` entry (only present when SENTINEL_POLICY is set). ``policy`` is a loaded Policy or None (unusable).
    Public: {digest, rules, usable}; detail adds the path."""
    out = {"digest": policy.digest() if policy is not None else None,
           "rules": len(policy.rules) if policy is not None else 0, "usable": policy is not None}
    if detail:
        out = {"path": path, **out}
    return out
