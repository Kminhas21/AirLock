"""Symlink-resolved argument forms sent by the proxy (proxy_call.resolved, B4 in DECISIONS D29).

The proxy runs on the same host as the downstream server and replaces each path-like string argument that goes through a symlink with its
real target (os.path.realpath). It sends one map per interpretation of the call (one per base directory a relative path may be resolved
against): ``{"path": "/real/.env"}`` for a top-level string, ``{"paths": {"1": "/real/x"}}`` for entry 1 of a top-level list. The hub
evaluates the policy on the args as written AND on every resolved copy and keeps the stricter verdict, so a resolution can only make a
decision stricter. Anything malformed (or ``resolved_incomplete: true``) is ignored as data and floors an ``allow`` at ``ask``. Never raises.
"""
from __future__ import annotations

from typing import Any

try:
    import policy as _policy
except ImportError:                                       # imported as server.resolved_args
    from server import policy as _policy

MAX_MAPS = 8              # interpretations per call
MAX_ENTRIES = 64          # replaced values per interpretation (top-level strings + list entries)
MAX_VALUE = 4096          # characters of one resolved path


def _ok_path(v: Any) -> bool:
    return isinstance(v, str) and 0 < len(v) <= MAX_VALUE and "\x00" not in v


def _check_map(m: Any, args: dict) -> bool:
    if not isinstance(m, dict) or not m:
        return False
    n = 0
    for k, v in m.items():
        if not isinstance(k, str) or k not in args:
            return False
        cur = args[k]
        if isinstance(v, str):
            if not isinstance(cur, str) or not _ok_path(v):
                return False
            n += 1
        elif isinstance(v, dict):
            if not isinstance(cur, list) or not v:
                return False
            for i, rv in v.items():
                if not (isinstance(i, str) and i.isascii() and i.isdigit() and len(i) <= 4) or int(i) >= len(cur):
                    return False
                if not isinstance(cur[int(i)], str) or not _ok_path(rv):
                    return False
                n += 1
        else:
            return False
        if n > MAX_ENTRIES:
            return False
    return True


def parse(value: Any, args: Any, incomplete: Any = False) -> tuple[list, bool]:
    """-> (interpretations, invalid). Absent (None) -> ([], False): today's behaviour. Present but malformed in ANY part -> ([], True).
    ``incomplete`` (the proxy hit a bound or an error while resolving) -> invalid as well."""
    try:
        bad = incomplete is not False and incomplete is not None
        if value is None:
            return [], bad
        if not isinstance(args, dict) or not isinstance(value, list) or len(value) > MAX_MAPS:
            return [], True
        if not all(_check_map(m, args) for m in value):
            return [], True
        return [dict(m) for m in value], bad
    except Exception:
        return [], True


def substitute(args: dict, m: dict) -> dict:
    """A copy of ``args`` with the resolved values of one interpretation put in place (``m`` must have passed ``parse``)."""
    out = dict(args)
    for k, v in m.items():
        if isinstance(v, str):
            out[k] = v
        else:
            lst = list(out[k])
            for i, rv in v.items():
                lst[int(i)] = rv
            out[k] = lst
    return out


def evaluate(policy, server, tool, args, variants: list, invalid: bool, **kw):
    """The stricter of the policy's decisions on the written args and on every resolved copy; an allow becomes ask when the resolution
    was malformed or incomplete. Never raises (an error -> ask)."""
    try:
        d = policy.evaluate(server, tool, args, **kw)
        for m in variants:
            d = _policy.stricter(d, policy.evaluate(server, tool, substitute(args, m), **kw))
        if invalid and d.verdict == "allow":
            d = _policy.Decision("ask", None, d.matched, "resolved_invalid", False)     # held by the resolution, not by the allow rule
        return d
    except Exception:
        return _policy.Decision("ask", None, (), "engine_error", False)
