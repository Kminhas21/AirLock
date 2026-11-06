"""Standing-rule writer for the operator UI (docs/plans/OPERATOR-UI.md, ticket OP3).  Pure: no FastAPI.

    rule = build_rule("deny", "tool_under", "fs", "write_file", {"path": "/project/a/b.txt"})
    info = append_rule("/etc/sentinel/policy.json", rule)     # {"rule_id", "digest_before", "digest_after"}

`build_rule` raises ValueError whose message is a reason from the closed set ``cannot_build | scope_not_allowed``.
`append_rule` raises `PolicyWriteError` whose ``.reason`` is ``invalid_policy | write_failed | not_found``.

Safety properties of append_rule: the original file is never modified in place (tmp file in the same directory, mode 0600,
fsync, os.replace, fsync of the directory), `<path>.bak` holds the previous bytes, a failure before the replace leaves the
original byte-identical, concurrent writers are serialised (in-process lock + flock on `<path>.lock`), and the WHOLE result
is validated with policy.py before anything is written.  Server and tool names are escaped so they match literally (a tool
called `write_*` yields the pattern `write_[*]`).  Resulting files are re-formatted (indent 2, ASCII-only JSON) and get mode 0600.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import stat
import threading
import unicodedata
from typing import Any

import policy as P

try:                                                       # POSIX only; the in-process lock still applies elsewhere
    import fcntl
except ImportError:                                        # pragma: no cover
    fcntl = None

log = logging.getLogger("sentinel.policy_writer")

CANNOT_BUILD = "cannot_build"
SCOPE_NOT_ALLOWED = "scope_not_allowed"
VERDICTS = ("allow", "deny", "ask")
SCOPES = ("exact", "tool_under", "tool")
PATH_KEYS = ("path", "file", "filename", "dir", "directory", "target")      # priority order
MAX_EXACT_ARGS = P.MAX_ARG_CONDS
MAX_NOTE = P.MAX_NOTE
_BAD_CATS = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}

_LOCK = threading.Lock()


class PolicyWriteError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


# ---------------------------------------------------------------------------
# build_rule
# ---------------------------------------------------------------------------

def _clean_text(s: Any) -> bool:
    return isinstance(s, str) and not any(unicodedata.category(c) in _BAD_CATS for c in s)


def _literal_glob(name: str) -> str:
    """fnmatch pattern that matches exactly `name`."""
    return "".join({"[": "[[]", "*": "[*]", "?": "[?]"}.get(c, c) for c in name)


def _name(v: Any) -> str:
    if not isinstance(v, str) or not v or len(v) > P.MAX_PATTERN or not _clean_text(v):
        raise ValueError(CANNOT_BUILD)
    return _literal_glob(v)


def _identity(rule: dict) -> str:
    """What makes two rules 'the same': verdict + conditions (not the id, not the note)."""
    return json.dumps({"verdict": rule.get("verdict"), "when": rule.get("when", {})}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _exact_args(args: Any) -> list:
    if not isinstance(args, dict) or not 0 < len(args) <= MAX_EXACT_ARGS:
        raise ValueError(CANNOT_BUILD)
    conds = []
    for k in sorted(args, key=lambda x: (not isinstance(x, str), str(x))):
        v = args[k]
        if not isinstance(k, str) or not k or "." in k or len(k) > 100 or not _clean_text(k):
            raise ValueError(CANNOT_BUILD)
        if isinstance(v, bool) or (isinstance(v, int) and v.bit_length() <= 63):
            pass
        elif isinstance(v, str) and len(v) <= P.MAX_VALUE_STR:
            pass
        else:                                              # float / NaN / None / list / dict / huge int / huge string
            raise ValueError(CANNOT_BUILD)
        conds.append({"path": k, "op": "equals", "value": v})
    return conds


def _parent_dir(value: str) -> str:
    if "\x00" in value or len(value) > P.MAX_VALUE_STR or not value.startswith("/") or value.startswith("//"):
        raise ValueError(CANNOT_BUILD)
    if ".." in value.split("/"):
        raise ValueError(CANNOT_BUILD)
    parent = posixpath.dirname(posixpath.normpath(value))
    if parent in ("", "/", "."):
        raise ValueError(CANNOT_BUILD)
    return parent


def _under_args(args: Any) -> list:
    if not isinstance(args, dict):
        raise ValueError(CANNOT_BUILD)
    for key in PATH_KEYS:
        v = args.get(key)
        if isinstance(v, str) and v.startswith("/"):
            return [{"path": key, "op": "under", "value": _parent_dir(v)}]
    raise ValueError(CANNOT_BUILD)


def build_rule(verdict, scope, server, tool, args, *, note="") -> dict:
    if not isinstance(verdict, str) or verdict not in VERDICTS or not isinstance(scope, str) or scope not in SCOPES:
        raise ValueError(CANNOT_BUILD)
    if verdict == "allow" and scope not in ("exact", "tool_under"):
        raise ValueError(SCOPE_NOT_ALLOWED)
    if note is None:
        note = ""
    if not isinstance(note, str) or len(note) > MAX_NOTE or not _clean_text(note):
        raise ValueError(CANNOT_BUILD)
    when: dict = {"server": _name(server), "tool": _name(tool)}
    if scope == "exact":
        when["args"] = _exact_args(args)
    elif scope == "tool_under":
        when["args"] = _under_args(args)
    rule = {"verdict": verdict, "when": when}
    rule_id = f"ui-{verdict}-{hashlib.sha256(_identity(rule).encode('ascii')).hexdigest()[:8]}"
    out = {"id": rule_id, "verdict": verdict}
    if note:
        out["note"] = note
    out["when"] = when
    try:
        P.Policy({"version": P.VERSION, "rules": [out]})            # the REAL validator decides what is acceptable
    except P.PolicyError:
        raise ValueError(CANNOT_BUILD) from None
    return out


# ---------------------------------------------------------------------------
# append_rule
# ---------------------------------------------------------------------------

def _fail(reason: str, detail: str = "") -> PolicyWriteError:
    return PolicyWriteError(reason, detail)


def _path(p: Any) -> str:
    """str path only - NEVER hand a non-path (an int is a file descriptor!) to os.open()/os.stat()."""
    if isinstance(p, bool) or not isinstance(p, (str, os.PathLike)):
        raise _fail("write_failed", "path must be str or PathLike")
    try:
        s = os.fspath(p)
    except TypeError:
        raise _fail("write_failed", "path must be str or PathLike") from None
    if not isinstance(s, str) or not s or "\x00" in s:
        raise _fail("write_failed", "invalid path")
    return s


def _read_regular(path: str) -> bytes:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise _fail("not_found", path) from None
    except OSError as e:
        raise _fail("write_failed", f"cannot stat: {e}") from None
    if stat.S_ISLNK(st.st_mode):
        raise _fail("write_failed", "refusing to follow a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise _fail("write_failed", "not a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise _fail("not_found", path) from None
    except OSError as e:
        raise _fail("write_failed", f"cannot open: {e}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _fail("write_failed", "not a regular file")
        chunks, total = [], 0
        while total <= P.MAX_FILE_BYTES:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
            total += len(b)
    except PolicyWriteError:
        raise
    except OSError as e:
        raise _fail("write_failed", f"cannot read: {e}") from None
    finally:
        os.close(fd)
    if total > P.MAX_FILE_BYTES:
        raise _fail("invalid_policy", "policy file too large")
    return b"".join(chunks)


def _write_tmp(tmp: str, data: bytes) -> None:
    try:
        os.unlink(tmp)                                      # a stale tmp (or a planted symlink) from an earlier crash
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(directory: str) -> None:
    try:
        dfd = os.open(directory or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError as e:                                    # the replace already happened; durability of the entry is best effort
        log.warning("policy_writer: fsync of directory %s failed: %s", directory, e)


def _rules_of(data: Any) -> list:
    r = data.get("rules") if isinstance(data, dict) else None
    return r if isinstance(r, list) else []


def append_rule(path, rule) -> dict:
    p = _path(path)
    try:
        return _append(p, rule)
    except PolicyWriteError:
        raise
    except OSError as e:
        raise _fail("write_failed", str(e)) from None
    except Exception as e:                                  # never leak anything else to the hub
        raise _fail("write_failed", type(e).__name__) from None


def _append(p: str, rule: Any) -> dict:
    try:
        rule = json.loads(json.dumps(rule, allow_nan=False))        # plain-JSON deep copy; rejects NaN / non-JSON values
    except (TypeError, ValueError, RecursionError):
        raise _fail("invalid_policy", "rule is not plain JSON") from None
    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
        raise _fail("invalid_policy", "rule must be an object with an id")
    with _LOCK:
        lock_fd = None
        try:
            if fcntl is not None:
                try:
                    lock_fd = os.open(p + ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except OSError as e:
                    raise _fail("write_failed", f"cannot lock: {e}") from None
            return _locked_append(p, rule)
        finally:
            if lock_fd is not None:
                try:
                    os.close(lock_fd)                       # also releases the flock
                except OSError:
                    pass


def _locked_append(p: str, rule: dict) -> dict:
    old = _read_regular(p)
    try:
        data = P._parse_bytes(old, p)
        before = P.Policy(data)
    except P.PolicyError as e:
        raise _fail("invalid_policy", "; ".join(e.messages[:3])) from None
    digest_before = before.digest()
    ident = _identity(rule)
    for r in _rules_of(data):
        if isinstance(r, dict) and isinstance(r.get("id"), str):
            try:
                same = _identity(r) == ident
            except (TypeError, ValueError):
                same = False
            if same:
                return {"rule_id": r["id"], "digest_before": digest_before, "digest_after": digest_before}
    new = dict(data)
    new["rules"] = list(_rules_of(data)) + [rule]
    try:
        after = P.Policy(new)
    except P.PolicyError as e:
        raise _fail("invalid_policy", "; ".join(e.messages[:3])) from None
    text = (json.dumps(new, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(text) > P.MAX_FILE_BYTES:
        raise _fail("invalid_policy", "resulting policy file would be too large")
    try:                                                    # what will be on disk must load and have the digest we report
        if P.Policy(P._parse_bytes(text, p)).digest() != after.digest():
            raise _fail("invalid_policy", "round trip changed the policy")
    except P.PolicyError as e:
        raise _fail("invalid_policy", "; ".join(e.messages[:3])) from None

    tmp, bak, bak_tmp = p + ".tmp", p + ".bak", p + ".bak.tmp"
    directory = os.path.dirname(os.path.abspath(p))
    replaced = False
    try:
        _write_tmp(tmp, text)
        _write_tmp(bak_tmp, old)
        os.replace(bak_tmp, bak)
        os.replace(tmp, p)
        replaced = True
    except OSError as e:
        raise _fail("write_failed", str(e)) from None
    finally:
        if not replaced:
            for leftover in (tmp, bak_tmp):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
    _fsync_dir(directory)
    return {"rule_id": rule["id"], "digest_before": digest_before, "digest_after": after.digest()}
