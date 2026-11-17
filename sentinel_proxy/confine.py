"""Kernel confinement of auto-allowed path calls (DECISIONS D31). Replaces path prediction.

The hub judges only the WRITTEN arguments. When a policy rule with a `confine` map ({argument: "read" | "list"}) auto-allows a call, the
proxy runs it in a fresh worker whose Landlock rules grant exactly the objects the agent NAMED: each value is walked beneath its base with
openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) inside the worker, right before the ruleset is applied (sandbox.open_grant). A wrong guess
about the server's path semantics (`..` after a link, a Unicode respelling, another base, a swap after the check) is then an EACCES, not
a leak.

Here: which servers can be confined, the grants of a call, the narrowed spec, the worker-status check, and `precheck`, which runs the SAME
walk in the proxy over every path-slot value as a hint: a value with a symlink, an escape, `~`, or too many values / bases makes the call
`confinable: false`, so the hub asks a human instead of auto-allowing a call that would fail. A missing name is not a hint. `links` (where a
symlinked value leads, os.path.realpath: the kernel's order, `..` after a link follows the link) and `lexical` (the same value with `..`
resolved first, as Node does, only where that differs) are shown on the card only: nothing evaluates them.
"""
from __future__ import annotations

import errno
import os
from typing import Any

from sentinel_proxy import sandbox

PATH_SLOTS = frozenset({"path", "paths", "source", "destination", "directory", "file"})     # = server/policy.py PATH_SLOTS
MAX_VALUES = 64          # confined values per call (more: the precheck says false; the worker gets the first 64)
MAX_BASES = 4            # directories a relative value may be walked from (more: no grant, precheck false)
FORCE_ENV = "SENTINEL_CONFINE_PRECHECK"     # test knob: "force_true" makes every precheck say confinable (the kernel still decides)


def server_confinable(sc: Any) -> tuple[bool, str]:
    """(confinable, why not). Needs a sandbox with `runtime` (what the worker may run), Landlock and openat2 on this host."""
    if not sc.sandbox:
        return False, "not sandboxed"
    if not sc.sandbox.get("runtime"):
        return False, "no sandbox.runtime"
    if why := sandbox.runtime_problem(sc.sandbox):          # fail closed even if a config skipped validation
        return False, why
    if sandbox.landlock_abi() < 1:
        return False, "Landlock unavailable"
    if not sandbox.openat2_ok():
        return False, "openat2 unavailable"
    return True, ""


def bases_for(sc: Any) -> list[str]:
    """Where the server maps a relative name: its absolute directory arguments (the filesystem server's allowed directories), else its
    working directory. Operator config, opened normally (a symlinked base is fine)."""
    dirs = [a for a in sc.args if isinstance(a, str) and a.startswith("/") and os.path.isdir(a)]
    return list(dict.fromkeys(dirs)) or [sc.cwd or os.getcwd()]


def _values(args: dict, keys) -> list[tuple[str, str, str]]:
    """[(label, key, value)] for the string values of `keys`: a top-level string, or the string entries of a top-level list."""
    out = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            out.append((k, k, v))
        elif isinstance(v, list):
            out += [(f"{k}.{i}", k, x) for i, x in enumerate(v) if isinstance(x, str)]
    return out


def has_path_values(args: Any) -> bool:
    return isinstance(args, dict) and bool(_values(args, sorted(PATH_SLOTS & set(args))))


def _walks(value: str, bases: list[str]) -> list[tuple[str, str]] | None:
    """[(base, value)] to walk, or None (never confinable: `~`, more than MAX_BASES for a relative value)."""
    if not value or value.startswith("~"):
        return None
    if value.startswith("/"):
        return [("/", value)]
    return None if len(bases) > MAX_BASES else [(b, value) for b in bases]


def grant_specs(args: Any, confine: dict, sc: Any) -> list[list[str]]:
    """[[base, value, right]] for a confined worker: one per (value, base). The worker opens each; one it cannot open gets no grant."""
    if not isinstance(args, dict):
        return []
    bases, out = bases_for(sc), []
    for _label, key, value in _values(args, [k for k in confine if k in args])[:MAX_VALUES]:
        out += [[b, v, confine[key]] for b, v in _walks(value, bases) or []]
    return out


def precheck(args: Any, sc: Any) -> tuple[bool, dict, dict]:
    """-> (confinable, links, lexical). Dry run of the worker's walk over every path-slot value (fds closed at once). Never raises."""
    try:
        if not isinstance(args, dict):
            return False, {}, {}
        values = _values(args, sorted(PATH_SLOTS & set(args)))
        ok, links, lexical, bases = len(values) <= MAX_VALUES, {}, {}, bases_for(sc)
        for label, _key, value in values[:MAX_VALUES]:
            walks = _walks(value, bases)
            if walks is None or "\x00" in value:             # the walk would truncate the name at the NUL (C string)
                ok = False
                continue
            for base, v in walks:
                try:
                    os.close(sandbox.open_beneath(base, v))
                except ValueError:                                  # NUL in the value
                    ok = False
                except OSError as e:
                    if e.errno == errno.ELOOP:                          # a symlink somewhere: the worker would get no grant
                        ok = False
                        if len(links) < MAX_VALUES and label not in links:
                            full = os.path.join(base, v)
                            links[label] = os.path.realpath(full)
                            lex = os.path.realpath(os.path.normpath(full))       # `..` resolved before the links, as Node does
                            if lex != links[label]:
                                lexical[label] = lex
                    elif e.errno != errno.ENOENT and e.errno != errno.ENOTDIR:   # EXDEV (escapes the base), EACCES, ...
                        ok = False
        return ok or os.environ.get(FORCE_ENV) == "force_true", links, lexical
    except Exception:
        return False, {}, {}


def confined_spec(spec: dict, grants: list) -> dict:
    """The server's sandbox with its data directories REPLACED by the exact grants: system set + runtime + private HOME + grants."""
    out = dict(spec)
    out.update(read=[], write=[], require=True, grants=grants)
    return out


def status_ok(st: Any) -> bool:
    """The worker's trampoline status proves the confinement: a confined worker, Landlock filesystem applied, no layer missing."""
    return (isinstance(st, dict) and st.get("confined") is True and "landlock_fs" in (st.get("layers") or [])
            and not st.get("missing"))
