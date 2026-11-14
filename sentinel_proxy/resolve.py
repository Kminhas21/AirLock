"""Symlink resolution of path-like argument values (B4, DECISIONS D29).

The hub's sensitive-path rules test the TEXT the agent wrote; a link `notes.txt -> .env` passes them. The proxy runs on the same host and
filesystem as the downstream server, so it resolves path-like string arguments (top level, and entries of top-level lists) and reports
the values whose real path differs from the written one. The hub evaluates the policy on every form and keeps the stricter verdict.

Which values: every string in a path slot (`path`, `paths`, `source`, `destination`, `directory`, `file`: the keys the starter's ask rules
read), and in any other key a string that looks like a path (starts with '/' or '~', or contains a '/'), for policies that read other
key names (`file_path`, `outputPath`, ...). A bare word in another key (`query`, `content`) is never looked up.

Two resolution orders are computed and both are sent when they differ: the Node order (`path.resolve()` removes '..' LEXICALLY, then
`fs.realpath`: what the reference filesystem server and Desktop Commander do) and the kernel order (`realpath` follows a link before
'..': what `open()` does). `A/lnk/../b` with `lnk -> A/sub/deep` and `b -> .env` names `.env` for Node and `A/sub/b` for the kernel.
Relative values are resolved against every base directory the downstream may use (its working directory and the absolute directories in
its command line, which is where the reference filesystem server resolves them).

`incomplete` (the hub then holds what the policy would allow) is set when a bound is hit, a lookup fails, `~` is used but the server gets
its own HOME, more than MAX_BASES bases exist for a relative value, or a path-slot value is missing, in the Node order, in ANY directory the server
maps names in (a kernel-order path or another allowed dir that has the name is a decoy the server never reads): the filesystem server maps a missing name onto an existing
Unicode-equivalent entry (NFC/NFD, U+00A0 for a space), which realpath here cannot see.

Output (proxy_call.resolved): a list of interpretations, one per (base, order) that changes something, e.g.
``[{"path": "/w/.env"}]`` or ``[{"paths": {"1": "/home/u/.ssh/id_rsa"}}]``. Never raises.
"""
from __future__ import annotations

import os
from typing import Any

PATH_SLOTS = frozenset({"path", "paths", "source", "destination", "directory", "file"})
MAX_BASES = 4         # bases a relative value can be resolved against (x 2 orders = the hub's 8 interpretations); more => incomplete
MAX_ENTRIES = 64      # replaced values per interpretation (the hub accepts at most this many)
MAX_LIST = 64         # entries of one list looked at (more path-like entries => incomplete)
MAX_LOOKUPS = 512     # realpath calls per call (more => incomplete)
MAX_VALUE = 4096      # longer strings are not paths (PATH_MAX); in a slot, or when it looks like a path => incomplete


def bases_for(sc: Any) -> list[str]:
    """The downstream's working directory (its `cwd`, else the proxy's, which it inherits) plus absolute directories in its arguments."""
    out: list[str] = []
    try:
        cands = [sc.cwd or os.getcwd()] + [a for a in sc.args if isinstance(a, str) and a.startswith("/")]
        for c in cands:
            if c not in out and os.path.isdir(c):
                out.append(c)              # no cap: the server tries EVERY allowed directory (too many => relative values incomplete)
    except Exception:
        pass
    return out


def map_bases_for(sc: Any) -> list[str]:
    """The directories the server maps names in (filesystem server: its allowed directories = the absolute directory arguments), else
    its working directory. The M1 check (a missing name the server may map onto a Unicode-equivalent entry) is judged against these."""
    try:
        dirs = [a for a in sc.args if isinstance(a, str) and a.startswith("/") and os.path.isdir(a)]
        return list(dict.fromkeys(dirs)) or [sc.cwd or os.getcwd()]
    except Exception:
        return []


def home_known(sc: Any) -> bool:
    """`~` means the proxy's home only if the server inherits it: not when its env sets HOME, not in a sandbox (private HOME)."""
    try:
        return "HOME" not in (sc.env or {}) and not sc.sandbox
    except Exception:
        return False


class _Budget:
    def __init__(self):
        self.left = MAX_LOOKUPS
        self.incomplete = False


def _looks_like_path(v: str) -> bool:
    return v.startswith(("/", "~")) or "/" in v


def _inside(lexical: str, bases: list[str]) -> bool:
    """Inside a base directory other than '/': where a server such as the filesystem server maps names (its allowed directories)."""
    return any(b != "/" and (lexical == b or lexical.startswith(b.rstrip("/") + "/")) for b in bases)


def _forms(joined: str, budget: _Budget) -> tuple[str | None, str | None, bool]:
    """-> (Node-order real path or None, kernel-order real path or None, missing). None = same as the written path, normalised.
    missing: the path the SERVER reads (Node order: lexical '..') does not exist; a kernel-order path that exists is a decoy."""
    if budget.left < 2:
        budget.incomplete = True
        return None, None, False
    budget.left -= 2
    try:
        lexical = os.path.normpath(joined)
        node = os.path.realpath(lexical)
        kernel = os.path.realpath(joined)
        missing = not os.path.lexists(lexical)
        return (node if node != lexical else None), (kernel if kernel != lexical else None), missing
    except Exception:
        budget.incomplete = True
        return None, None, False


def _resolve_one(v: Any, slot: bool, bases: list[str], home: bool, budget: _Budget, map_bases: list[str]) -> list[str | None]:
    """-> one resolved value (or None) per interpretation (base x order); a value that is not looked at -> []."""
    if not isinstance(v, str) or not v or "\x00" in v or "://" in v:
        return []
    if not slot and not _looks_like_path(v):
        return []
    if len(v) > MAX_VALUE:
        budget.incomplete = True
        return []
    if v == "~" or v.startswith("~/"):
        if not home:
            budget.incomplete = True
            return []
        v = os.path.expanduser(v)
    width = max(1, len(bases))
    if not v.startswith("/") and len(bases) > MAX_BASES:
        budget.incomplete = True                           # more interpretations than the hub accepts: hold, never drop a base
        return []
    joined = [(None, v)] if v.startswith("/") else [(b, os.path.join(b, v)) for b in bases]
    per_base = []
    for b, j in joined:
        node, kernel, missing = _forms(j, budget)
        per_base.append((node, kernel))
        # M1: a path-slot name missing (Node order) in ANY directory the server maps names in may be mapped there onto an equivalent
        # name we cannot see (filesystem 1.0.0: NFC/NFD, U+00A0 for a space). ANY, not all: the server resolves a relative name against
        # its FIRST allowed dir, so another dir that has the name is a decoy. Missing outside those dirs (the cwd guess, another
        # filesystem such as `docker run`) says nothing.
        if slot and missing and (b is None or b in map_bases) and _inside(os.path.normpath(j), map_bases):
            budget.incomplete = True
    if v.startswith("/"):
        per_base = per_base * width
    return [r for pair in per_base for r in pair]


def resolve_args(args: Any, bases: list[str], home_known: bool = True, map_bases: list[str] | None = None) -> tuple[list[dict], bool]:
    """-> (interpretations, incomplete). ``map_bases``: where the server maps names (default: every base). Never raises."""
    try:
        if not isinstance(args, dict):
            return [], False
        if map_bases is None:
            map_bases = bases
        budget = _Budget()
        width = 2 * max(1, len(bases))
        maps: list[dict] = [{} for _ in range(width)]
        counts = [0] * width

        def put(i: int, key: str, idx: int | None, real: str) -> None:
            if counts[i] >= MAX_ENTRIES:
                budget.incomplete = True
                return
            counts[i] += 1
            if idx is None:
                maps[i][key] = real
            else:
                maps[i].setdefault(key, {})[str(idx)] = real

        for k, v in args.items():
            slot = k in PATH_SLOTS
            if isinstance(v, list):
                if any(isinstance(x, str) and (slot or _looks_like_path(x)) for x in v[MAX_LIST:]):
                    budget.incomplete = True
                for j, item in enumerate(v[:MAX_LIST]):
                    for i, r in enumerate(_resolve_one(item, slot, bases, home_known, budget, map_bases)):
                        if r is not None:
                            put(i, k, j, r)
            else:
                for i, r in enumerate(_resolve_one(v, slot, bases, home_known, budget, map_bases)):
                    if r is not None:
                        put(i, k, None, r)
        out: list[dict] = []
        for m in maps:
            if m and m not in out:
                out.append(m)
        if len(out) > 2 * MAX_BASES:                       # cannot happen (absolute values give 2 distinct maps at most); never send more
            return out[:2 * MAX_BASES], True
        return out, budget.incomplete
    except Exception:
        return [], True
