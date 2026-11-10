"""Declarative allow / deny / ask policy engine (docs/plans/POLICY-ENGINE.md, ticket PE1).

Pure functions and data only (no FastAPI).  Fail closed everywhere: a condition that cannot be evaluated is FALSE for
positive operators and TRUE for negative ones (``not_*``), a rule that raises turns the verdict into ``ask`` unless a
``deny`` rule matched, and no input (tool name, server name, args) can raise out of ``Policy.evaluate`` or take
unbounded time.  Nothing from the call ever becomes a pattern, a regex or code; patterns come from the policy file only.

    policy = load_policy("policy.json")             # raises PolicyError with ALL messages
    d = policy.evaluate("fs", "read_file", {"path": "/project/a"})
    d.verdict   # allow | deny | ask
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import posixpath
import re
import stat
import threading
import unicodedata
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Mapping

VERSION = 1
VERDICTS = ("allow", "deny", "ask")
_STRENGTH = {"deny": 3, "ask": 2, "allow": 1}           # winning class order
DESTINATIONS = ("internal", "external", "relay", "none", "any")
POSITIVE_OPS = ("equals", "in", "glob", "under", "contains", "exists", "max_len", "icontains_any")
NEGATIVE_OPS = ("not_equals", "not_in", "not_glob", "not_under", "not_exists")
OPS = POSITIVE_OPS + NEGATIVE_OPS
_NEG_OF = {"not_equals": "equals", "not_in": "in", "not_glob": "glob", "not_under": "under", "not_exists": "exists"}

# Bounds (documented in the plan unless marked "engine").
MAX_RULES = 500
MAX_ARG_CONDS = 20
MAX_ID = 60
MAX_NOTE = 200
MAX_DEPTH = 12                  # args nesting that is looked into; also the max segments of an args[].path
MAX_ITEMS = 2000                # list index that is looked into
MAX_STR = 20000                 # longer args strings are "truncated": never matched by value, only exist / not exist
MAX_PATTERN = 200               # engine: longest glob pattern accepted from a policy file
MAX_PATTERNS = 50               # engine: entries of a server / tool list
MAX_VALUE_STR = 1000            # engine: longest non-pattern string value (equals, in, contains, under)
MAX_VALUE_LIST = 1000           # engine: entries of an `in` / `not_in` value
MAX_ICASE_ITEMS = 64            # engine: icontains_any looks at a string or at most this many list elements ...
MAX_ICASE_STR = 4096            # ... of at most this many characters each; anything bigger counts as a match (fail closed)
MAX_FILE_BYTES = 1_000_000      # engine: policy file size

_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,60}")
_TOP_KEYS = {"version", "default", "rules"}
_RULE_KEYS = {"id", "verdict", "note", "when"}
_WHEN_KEYS = {"server", "tool", "args", "destination", "party", "alert", "secrets"}
_ARG_KEYS = {"path", "op", "value"}
_BAD_NAME_CATS = {"Cc", "Cf", "Cs", "Zl", "Zp"}          # control, format (bidi, ZW), surrogate, line/para separators


class PolicyError(Exception):
    """Invalid policy.  ``messages`` holds EVERY validation error found."""

    def __init__(self, messages):
        if isinstance(messages, str):
            messages = [messages]
        self.messages: list[str] = list(messages)
        super().__init__("; ".join(self.messages) if self.messages else "invalid policy")


class PolicyUnreadable(PolicyError):
    """The policy file could not be read or is not JSON / UTF-8 (the CLI exits 2 for this, 1 for other PolicyErrors)."""


@dataclass(frozen=True)
class Decision:
    verdict: str                  # allow | deny | ask
    rule_id: str | None           # deciding rule; None for the default / a rule error without an ask rule
    matched: tuple                # ids of ALL matching rules, in file order
    reason: str                   # rule:<id> | default | alert | rule_error:<id> | engine_error
    escalated: bool = False       # allow -> ask because an alert is present


@dataclass(frozen=True)
class ArgCond:
    path: tuple
    op: str
    value: Any


@dataclass(frozen=True)
class Rule:
    id: str
    verdict: str
    note: str | None
    when: dict                    # normalised copy of the `when` object as given
    server: tuple | None
    tool: tuple | None
    args: tuple
    destination: str | None
    party: tuple | None
    alert: bool | None
    specificity: int
    secrets: bool | None = None   # the call receives just-in-time credentials (proxy `secrets_used` non-empty)


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------

def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_scalar(v) -> bool:
    if v is None or isinstance(v, (str, bool)) or _is_int(v):
        return True
    return isinstance(v, float) and math.isfinite(v)


def _pattern_list(v, where: str, errs: list) -> tuple | None:
    items = [v] if isinstance(v, str) else v
    if not isinstance(items, list) or not items:
        errs.append(f"{where}: must be a non-empty string or list of strings")
        return None
    if len(items) > MAX_PATTERNS:
        errs.append(f"{where}: at most {MAX_PATTERNS} patterns")
        return None
    out, ok = [], True
    for i, p in enumerate(items):
        if not isinstance(p, str) or not p:
            errs.append(f"{where}[{i}]: must be a non-empty string")
            ok = False
        elif len(p) > MAX_PATTERN:
            errs.append(f"{where}[{i}]: pattern longer than {MAX_PATTERN} characters")
            ok = False
        elif "\x00" in p:
            errs.append(f"{where}[{i}]: NUL byte in pattern")
            ok = False
        else:
            out.append(p)
    return tuple(out) if ok else None


def _norm_value_path(p: str) -> str:
    return posixpath.normpath(p)


def _check_arg(a, where: str, errs: list) -> ArgCond | None:
    if not isinstance(a, dict):
        errs.append(f"{where}: must be an object")
        return None
    n0 = len(errs)
    for k in a:
        if k not in _ARG_KEYS:
            errs.append(f"{where}: unknown key {_show(k)}")
    path, op = a.get("path"), a.get("op")
    segs: tuple = ()
    if not isinstance(path, str) or not path:
        errs.append(f"{where}.path: must be a non-empty dotted string")
    else:
        parts = path.split(".")
        if any(not s for s in parts):
            errs.append(f"{where}.path: empty segment in {_show(path)}")
        elif len(parts) > MAX_DEPTH:
            errs.append(f"{where}.path: more than {MAX_DEPTH} segments")
        else:
            segs = tuple(parts)
    if not isinstance(op, str) or op not in OPS:
        errs.append(f"{where}.op: unknown operator {_show(op)} (allowed: {', '.join(OPS)})")
        return None
    has_value = "value" in a
    val = a.get("value")
    out: Any = None
    if op in ("exists", "not_exists"):
        if has_value:
            errs.append(f"{where}.value: not allowed for {op}")
    elif not has_value:
        errs.append(f"{where}.value: required for {op}")
    elif op in ("equals", "not_equals"):
        if not _is_scalar(val):
            errs.append(f"{where}.value: must be a string, finite number, boolean or null")
        elif isinstance(val, str) and len(val) > MAX_VALUE_STR:
            errs.append(f"{where}.value: string longer than {MAX_VALUE_STR} characters")
        else:
            out = val
    elif op in ("in", "not_in"):
        if not isinstance(val, list) or not val:
            errs.append(f"{where}.value: must be a non-empty list")
        elif len(val) > MAX_VALUE_LIST:
            errs.append(f"{where}.value: at most {MAX_VALUE_LIST} entries")
        elif not all(_is_scalar(x) and not (isinstance(x, str) and len(x) > MAX_VALUE_STR) for x in val):
            errs.append(f"{where}.value: entries must be strings (<= {MAX_VALUE_STR}), finite numbers, booleans or null")
        else:
            out = tuple(val)
    elif op in ("glob", "not_glob"):
        pl = _pattern_list(val, f"{where}.value", errs) if isinstance(val, str) else None
        if not isinstance(val, str):
            errs.append(f"{where}.value: must be a glob string")
        out = pl[0] if pl else None
    elif op in ("under", "not_under"):
        if not isinstance(val, str) or not val:
            errs.append(f"{where}.value: must be a non-empty string")
        elif "\x00" in val:
            errs.append(f"{where}.value: NUL byte in path")
        elif len(val) > MAX_VALUE_STR:
            errs.append(f"{where}.value: path longer than {MAX_VALUE_STR} characters")
        elif not val.startswith("/"):
            errs.append(f"{where}.value: must be an absolute path (start with '/')")
        else:
            out = _norm_value_path(val)
    elif op == "contains":
        if not isinstance(val, str) or not val:
            errs.append(f"{where}.value: must be a non-empty string")
        elif len(val) > MAX_VALUE_STR:
            errs.append(f"{where}.value: string longer than {MAX_VALUE_STR} characters")
        else:
            out = val
    elif op == "icontains_any":
        if not isinstance(val, list) or not val or len(val) > MAX_ICASE_ITEMS:
            errs.append(f"{where}.value: must be a list of 1 to {MAX_ICASE_ITEMS} strings")
        elif not all(isinstance(x, str) and 0 < len(x) <= MAX_VALUE_STR and "\x00" not in x for x in val):
            errs.append(f"{where}.value: entries must be non-empty strings (<= {MAX_VALUE_STR}) without NUL")
        else:
            out = tuple(x.casefold() for x in val)
    elif op == "max_len":
        if not _is_int(val) or val < 0:
            errs.append(f"{where}.value: must be a non-negative integer")
        else:
            out = val
    if len(errs) > n0 or not segs:
        return None
    return ArgCond(segs, op, out)


def _show(v) -> str:
    s = repr(v)
    return s if len(s) <= 80 else s[:77] + "..."


def _check_when(w, where: str, errs: list):
    """-> (server, tool, args, destination, party, alert, specificity, secrets) or None."""
    if w is None:
        return None, None, (), None, None, None, 0, None
    if not isinstance(w, dict):
        errs.append(f"{where}: must be an object")
        return None
    n0 = len(errs)
    for k in w:
        if k not in _WHEN_KEYS:
            errs.append(f"{where}: unknown key {_show(k)}")
    server = tool = party = None
    args: tuple = ()
    dest = alert = None
    spec = 0
    if "server" in w:
        server = _pattern_list(w["server"], f"{where}.server", errs)
        spec += 1
    if "tool" in w:
        tool = _pattern_list(w["tool"], f"{where}.tool", errs)
        spec += 1
    if "args" in w:
        al = w["args"]
        if not isinstance(al, list):
            errs.append(f"{where}.args: must be a list")
        elif len(al) > MAX_ARG_CONDS:
            errs.append(f"{where}.args: at most {MAX_ARG_CONDS} conditions")
        else:
            conds = [_check_arg(a, f"{where}.args[{i}]", errs) for i, a in enumerate(al)]
            args = tuple(c for c in conds if c is not None)
            spec += len(al)
    if "destination" in w:
        dest = w["destination"]
        if not isinstance(dest, str) or dest not in DESTINATIONS:
            errs.append(f"{where}.destination: must be one of {', '.join(DESTINATIONS)}")
            dest = None
        spec += 1
    if "party" in w:
        pv = w["party"]
        items = [pv] if isinstance(pv, str) else pv
        if not isinstance(items, list) or not items or len(items) > MAX_PATTERNS or \
                not all(isinstance(x, str) and 0 < len(x) <= 100 and "\x00" not in x for x in items):
            errs.append(f"{where}.party: must be a non-empty string or list of strings (<= 100 chars each)")
        else:
            party = tuple(items)
        spec += 1
    if "alert" in w:
        if not isinstance(w["alert"], bool):
            errs.append(f"{where}.alert: must be true or false")
        else:
            alert = w["alert"]
        spec += 1
    secrets = None
    if "secrets" in w:
        if not isinstance(w["secrets"], bool):
            errs.append(f"{where}.secrets: must be true or false")
        else:
            secrets = w["secrets"]
        spec += 1
    if len(errs) > n0:
        return None
    return server, tool, args, dest, party, alert, spec, secrets


def _build(data: Any) -> tuple[list, str, list]:
    """-> (rules, default, errors)."""
    errs: list[str] = []
    if not isinstance(data, dict):
        return [], "ask", ["policy must be a JSON object"]
    for k in data:
        if k not in _TOP_KEYS:
            errs.append(f"unknown top-level key {_show(k)}")
    ver = data.get("version")
    if "version" not in data:
        errs.append("version: required (must be 1)")
    elif not _is_int(ver) or ver != VERSION:
        errs.append(f"version: must be {VERSION}, got {_show(ver)}")
    default = data.get("default", "ask")
    if not isinstance(default, str) or default not in VERDICTS:
        errs.append(f"default: must be one of {', '.join(VERDICTS)}, got {_show(default)}")
        default = "ask"
    raw_rules = data.get("rules", [])
    rules: list[Rule] = []
    if not isinstance(raw_rules, list):
        errs.append("rules: must be a list")
        return rules, default, errs
    if len(raw_rules) > MAX_RULES:
        errs.append(f"rules: at most {MAX_RULES} rules (got {len(raw_rules)})")
        return rules, default, errs
    seen: set = set()
    for i, r in enumerate(raw_rules):
        where = f"rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{where}: must be an object")
            continue
        n0 = len(errs)
        rid = r.get("id")
        if isinstance(rid, str) and _ID_RE.fullmatch(rid):
            where = f"rules[{i}] ({rid})"
            if rid in seen:
                errs.append(f"{where}: duplicate id")
            seen.add(rid)
        else:
            errs.append(f"{where}.id: must match [A-Za-z0-9._-]{{1,{MAX_ID}}}, got {_show(rid)}")
        for k in r:
            if k not in _RULE_KEYS:
                errs.append(f"{where}: unknown key {_show(k)}")
        verdict = r.get("verdict")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            errs.append(f"{where}.verdict: must be one of {', '.join(VERDICTS)}, got {_show(verdict)}")
        note = r.get("note")
        if "note" in r and (not isinstance(note, str) or len(note) > MAX_NOTE):
            errs.append(f"{where}.note: must be a string of at most {MAX_NOTE} characters")
        w = _check_when(r.get("when"), f"{where}.when", errs)
        if len(errs) > n0 or w is None:
            continue
        server, tool, args, dest, party, alert, spec, secrets = w
        rules.append(Rule(rid, verdict, note, copy.deepcopy(r.get("when") or {}), server, tool, args, dest, party, alert, spec,
                          secrets))
    return rules, default, errs


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_const(name):
    raise ValueError(f"non-finite number {name}")


def _parse_bytes(raw: bytes, label: str) -> Any:
    """bytes -> JSON value; raises PolicyUnreadable."""
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dups, parse_constant=_no_const)
    except (ValueError, RecursionError) as e:                # UnicodeDecodeError / JSONDecodeError are ValueErrors
        raise PolicyUnreadable([f"{label}: cannot parse as JSON ({type(e).__name__}: {e})"]) from None


def _read_file(path) -> bytes:
    """Read a regular file of at most MAX_FILE_BYTES; raises PolicyUnreadable."""
    # An int is a FILE DESCRIPTOR to os.stat / open(): open(5) would read AND CLOSE fd 5, which belongs to somebody else (found when a test
    # killed the event loop's selector). Only real paths are ever opened.
    if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):
        raise PolicyUnreadable([f"policy path must be a string or a path, not {type(path).__name__}"])
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise PolicyUnreadable([f"{path}: not a regular file"])
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except PolicyUnreadable:
        raise
    except (OSError, ValueError, TypeError) as e:
        raise PolicyUnreadable([f"cannot read {path}: {e}"]) from None
    if len(raw) > MAX_FILE_BYTES:
        raise PolicyUnreadable([f"{path}: larger than {MAX_FILE_BYTES} bytes"])
    return raw


# ---------------------------------------------------------------------------
# Matching primitives
# ---------------------------------------------------------------------------

class _Missing:
    def __repr__(self):
        return "<missing>"


class _Trunc:
    def __repr__(self):
        return "<truncated>"


_MISSING = _Missing()
_TRUNC = _Trunc()


def _lookup(args: Any, segs: tuple):
    cur = args
    for s in segs[:MAX_DEPTH]:
        if isinstance(cur, Mapping):
            if s not in cur:
                return _MISSING
            cur = cur[s]
        elif isinstance(cur, (list, tuple)):
            if not (s.isascii() and s.isdigit() and len(s) <= 4):
                return _MISSING
            idx = int(s)
            if idx >= MAX_ITEMS or idx >= len(cur):
                return _MISSING
            cur = cur[idx]
        else:
            return _MISSING
    if isinstance(cur, str) and len(cur) > MAX_STR:
        return _TRUNC
    return cur


def _same(a, b) -> bool:
    """Strict JSON equality: bool, number and string never equal each other."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return False


def _under(v, prefix: str):
    if not isinstance(v, str) or "\x00" in v or not v.startswith("/"):
        return None                                       # not a string / NUL / relative: cannot say
    n = posixpath.normpath(v)
    if prefix == "/":
        return n.startswith("/")
    return n == prefix or n.startswith(prefix + "/")


_SLASHES = re.compile(r"/{2,}")


def _spellings(text: str):
    """The text as written plus its path-normalised forms (backslash -> '/', runs of '/' collapsed, '/./' removed, '..' resolved),
    all casefolded: `.git//config`, `/etc/./passwd`, `.git\\config` must not hide a needle."""
    f = text.casefold()
    yield f
    n = f.replace("\\", "/")
    for _ in range(16):                                   # bounded: each pass at least halves a '/./' run
        m = _SLASHES.sub("/", n).replace("/./", "/")
        if m == n:
            break
        n = m
    yield n
    yield posixpath.normpath(n)


def _icontains_any(v, needles: tuple):
    """True if the string (or ANY entry of the list) contains ANY needle, ignoring case and path spelling. Cannot be examined (a string
    over MAX_ICASE_STR, a list over MAX_ICASE_ITEMS, a list entry that is not a string) counts as a match: the operator exists for `ask`
    rules, and a padded or oddly typed argument must not slip past one. A missing / non-string, non-list argument is false."""
    if v is _TRUNC:
        return True
    if isinstance(v, str):
        items = (v,)
    elif isinstance(v, (list, tuple)):
        if len(v) > MAX_ICASE_ITEMS:
            return True
        items = v
    else:
        return None
    for it in items:
        if not isinstance(it, str) or len(it) > MAX_ICASE_STR:
            return True
        if any(n in f for f in _spellings(it) for n in needles):
            return True
    return False


def _positive(op: str, val, v):
    """Positive form of an op on a present value -> True / False / None (cannot be evaluated)."""
    if op == "exists":
        return True
    if op == "max_len":
        if v is _TRUNC:
            return False
        if isinstance(v, (str, list, tuple)):
            return len(v) <= val
        return None
    if op == "icontains_any":
        return _icontains_any(v, val)
    if v is _TRUNC:
        return None
    if op == "equals":
        return None if isinstance(v, (list, tuple, Mapping)) else _same(v, val)
    if op == "in":
        return None if isinstance(v, (list, tuple, Mapping)) else any(_same(v, x) for x in val)
    if op == "glob":
        return fnmatchcase(v, val) if isinstance(v, str) else None
    if op == "under":
        return _under(v, val)
    if op == "contains":
        return (val in v) if isinstance(v, str) else None
    return None


def _arg_holds(c: ArgCond, args: Any) -> bool:
    v = _lookup(args, c.path)
    if c.op == "exists":
        return v is not _MISSING
    if c.op == "not_exists":
        return v is _MISSING
    neg = c.op in _NEG_OF
    if v is _MISSING:
        return neg                                        # unknown: false for positive ops, true for negative ones
    r = _positive(_NEG_OF.get(c.op, c.op), c.value, v)
    if r is None:
        return neg
    return (not r) if neg else r


def _clean_name(s: Any) -> bool:
    if not isinstance(s, str) or len(s) > MAX_STR:
        return False
    for ch in s:
        if unicodedata.category(ch) in _BAD_NAME_CATS:
            return False
    return True


def _name_matches(name_ok: bool, name: Any, patterns: tuple, verdict: str) -> bool:
    if not name_ok:
        return verdict != "allow"          # unevaluable name: FALSE in allow rules, TRUE in deny / ask rules
    return any(fnmatchcase(name, p) for p in patterns)


class _Ctx:
    __slots__ = ("server", "tool", "args", "registry", "alerts", "secrets", "server_ok", "tool_ok", "_res", "_res_err")

    def __init__(self, server, tool, args, registry, alerts, secrets=False):
        self.server, self.tool, self.args, self.registry, self.alerts = server, tool, args, registry, alerts
        self.secrets = secrets
        self.server_ok = _clean_name(server)
        self.tool_ok = _clean_name(tool)
        self._res = None
        self._res_err = None

    def resolution(self):
        if self._res_err is not None:
            raise self._res_err
        if self._res is None:
            try:
                reg = self.registry
                if reg is None:
                    reg = _default_registry()
                self._res = reg.resolve(self.tool, self.args)
            except Exception as e:                        # re-raised for every rule that needs it
                self._res_err = e
                raise
        return self._res


_DEFAULT_REG = None
_DEFAULT_REG_LOCK = threading.Lock()


def _default_registry():
    global _DEFAULT_REG
    with _DEFAULT_REG_LOCK:
        if _DEFAULT_REG is None:
            try:
                from registry import default_registry
            except ImportError:                            # imported as server.policy
                from server.registry import default_registry
            _DEFAULT_REG = default_registry()
        return _DEFAULT_REG


_OUTSIDE = ("external", "relay", "unknown")


def _dest_holds(want: str, res) -> bool:
    kinds = [rt.resolution.kind for rt in res.tokens]
    if want == "any":
        return True
    if want == "none":
        return not kinds
    if want == "internal":
        return bool(kinds) and all(k == "internal" for k in kinds) and not res.reaches
    if want == "external":
        return bool(res.reaches) or any(k in _OUTSIDE for k in kinds)
    if want == "relay":
        return any(rt.resolution.kind == "relay" and rt.resolution.entry_id not in ("default", "unknown")
                   for rt in res.tokens)
    return False


def _parties(res) -> set:
    out = set(res.reaches)
    for rt in res.tokens:
        if rt.resolution.kind in _OUTSIDE and rt.resolution.party:
            out.add(rt.resolution.party)
    return out


def _rule_matches(rule: Rule, ctx: _Ctx) -> bool:
    """True if ALL conditions of the rule hold.  May raise (the caller turns that into a rule error)."""
    if rule.server is not None and not _name_matches(ctx.server_ok, ctx.server, rule.server, rule.verdict):
        return False
    if rule.tool is not None and not _name_matches(ctx.tool_ok, ctx.tool, rule.tool, rule.verdict):
        return False
    if rule.alert is not None and rule.alert != ctx.alerts:
        return False
    if rule.secrets is not None and rule.secrets != ctx.secrets:
        return False
    for c in rule.args:
        if not _arg_holds(c, ctx.args):
            return False
    if rule.destination is not None and rule.destination != "any":
        if not _dest_holds(rule.destination, ctx.resolution()):
            return False
    if rule.party is not None:
        got = _parties(ctx.resolution())
        if not any(p in got for p in rule.party):
            return False
    return True


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def _canon_when(rule: Rule) -> str:
    def lst(t):
        return None if t is None else sorted(set(t))
    args = sorted(json.dumps([".".join(c.path), c.op, list(c.value) if isinstance(c.value, tuple) else c.value],
                             sort_keys=True, default=str) for c in rule.args)
    return json.dumps({"s": lst(rule.server), "t": lst(rule.tool), "a": args, "d": rule.destination,
                       "p": lst(rule.party), "al": rule.alert, "se": rule.secrets}, sort_keys=True)


class Policy:
    def __init__(self, data: Any):
        rules, default, errs = _build(data)
        if errs:
            raise PolicyError(errs)
        self._data = {"version": VERSION, "default": default, "rules": copy.deepcopy(data.get("rules", []))}
        self.rules: tuple[Rule, ...] = tuple(rules)
        self.default: str = default

    def to_dict(self) -> dict:
        return copy.deepcopy(self._data)

    def digest(self) -> str:
        blob = json.dumps(self._data, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    # ---- lint ---------------------------------------------------------------
    def lint(self) -> list[str]:
        warns: list[str] = []
        if self.default == "allow":
            warns.append("default is 'allow': every call no rule matches is allowed (prefer 'ask' or 'deny')")
        for r in self.rules:
            if r.verdict == "allow":
                neg = sorted({c.op for c in r.args if c.op in _NEG_OF})
                if any(c.op == "icontains_any" for c in r.args):
                    warns.append(f"rule {r.id}: allow rule uses icontains_any, which is TRUE for an argument too big to examine "
                                 f"(meant for ask / deny rules)")
                if neg:
                    warns.append(f"rule {r.id}: allow rule uses negative operator(s) {', '.join(neg)}, which are TRUE when "
                                 f"the argument is missing or has the wrong type (it would allow on unknowns)")
        for r in self.rules:
            if r.verdict == "allow" and r.secrets is True and r.server is None and r.tool is None and not r.args \
                    and r.destination in (None, "any") and r.party is None and r.alert is None:
                warns.append(f"rule {r.id}: allow rule with secrets: true and no other narrowing condition would allow "
                             f"EVERY call that receives credentials")
        by_when: dict[str, list[Rule]] = {}
        for r in self.rules:
            by_when.setdefault(_canon_when(r), []).append(r)
        for group in by_when.values():
            for i, a in enumerate(group):
                for b in group[i + 1:]:
                    if a.verdict == b.verdict:
                        warns.append(f"rules {a.id} and {b.id} have identical conditions and the same verdict (duplicate)")
                    else:
                        lo, hi = (a, b) if _STRENGTH[a.verdict] < _STRENGTH[b.verdict] else (b, a)
                        warns.append(f"rule {lo.id} ({lo.verdict}) is shadowed by rule {hi.id} ({hi.verdict}) with identical "
                                     f"conditions: it can never decide")
        return warns

    # ---- evaluation -----------------------------------------------------------
    def evaluate(self, server, tool, args, *, registry=None, alerts_present=False, secrets_used=False) -> Decision:
        try:
            return self._evaluate(server, tool, args, registry, bool(alerts_present), bool(secrets_used))
        except Exception:                                  # never raise out of the engine; fail closed
            return Decision("ask", None, (), "engine_error", False)

    def _evaluate(self, server, tool, args, registry, alerts, secrets=False) -> Decision:
        ctx = _Ctx(server, tool, args, registry, alerts, secrets)
        matched: list[Rule] = []
        errors: list[str] = []
        for r in self.rules:
            try:
                if _rule_matches(r, ctx):
                    matched.append(r)
            except Exception:
                errors.append(r.id)
        ids = tuple(r.id for r in matched)

        def best(verdict):
            top = None
            for r in matched:
                if r.verdict == verdict and (top is None or r.specificity > top.specificity):
                    top = r
            return top

        deny = best("deny")
        if deny is not None:
            return Decision("deny", deny.id, ids, f"rule:{deny.id}", False)
        ask = best("ask")
        if errors:
            return Decision("ask", ask.id if ask else None, ids, f"rule_error:{errors[0]}", False)
        if ask is not None:
            return Decision("ask", ask.id, ids, f"rule:{ask.id}", False)
        allow = best("allow")
        if allow is not None:
            verdict, rid, reason = "allow", allow.id, f"rule:{allow.id}"
        else:
            verdict, rid, reason = self.default, None, "default"
        if alerts and verdict == "allow":
            return Decision("ask", rid, ids, "alert", True)
        if secrets and verdict == "allow" and (allow is None or allow.secrets is None):
            # credentials are being granted: only a rule that says `secrets: true` may allow that
            return Decision("ask", rid, ids, "secrets", True)
        return Decision(verdict, rid, ids, reason, False)


BUILTIN_PREFIX = "builtin:"
_BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")
_BUILTIN_NAMES = ("starter",)


def is_builtin(value) -> bool:
    return isinstance(value, str) and value.strip().startswith(BUILTIN_PREFIX)


def resolve_policy_path(value):
    """A SENTINEL_POLICY value -> the file to read.  ``builtin:<name>`` -> the shipped file; anything else is returned
    unchanged; an unknown ``builtin:`` name -> None (the caller treats that like a broken policy: hold everything)."""
    if not is_builtin(value):
        return value
    name = value.strip()[len(BUILTIN_PREFIX):]
    return os.path.join(_BUILTIN_DIR, name + ".json") if name in _BUILTIN_NAMES else None


def _unknown_builtin(value) -> str:
    return f"unknown built-in policy {value.strip()!r} (available: {', '.join(BUILTIN_PREFIX + n for n in _BUILTIN_NAMES)})"


def load_policy(src) -> Policy:
    """Load from a dict, a Policy, or a path (str / PathLike) to a JSON file (or ``builtin:<name>``).  Raises PolicyError with
    all messages (PolicyUnreadable, a subclass, when the file cannot be read or parsed)."""
    if isinstance(src, Policy):
        return Policy(src.to_dict())
    if isinstance(src, dict):
        return Policy(src)
    if isinstance(src, (str, os.PathLike)):
        if is_builtin(src):
            real = resolve_policy_path(src)
            if real is None:
                raise PolicyUnreadable([_unknown_builtin(src)])
            src = real
        return Policy(_parse_bytes(_read_file(src), str(src)))
    raise PolicyError([f"cannot load a policy from {type(src).__name__}"])


# ---------------------------------------------------------------------------
# Content-hash cached loader (same idea as proposal_monitor.load_registry)
# ---------------------------------------------------------------------------

_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 64


def load_policy_file(path) -> tuple["Policy | None", str]:
    """-> (Policy, "") or (None, reason).  The bytes are read once, hashed (sha256) and parsed; the result (also a failure)
    is cached by content hash, so an edit applies at the next call even if size and mtime did not change.  Never raises."""
    try:
        key = str(path)
        real = resolve_policy_path(path)
        if real is None:
            return None, _unknown_builtin(path)
        try:
            raw = _read_file(real)
        except PolicyUnreadable as e:
            return None, e.messages[0] if e.messages else "unreadable"
        sig = hashlib.sha256(raw).hexdigest()
        with _cache_lock:
            hit = _cache.get(key)
            if hit is not None and hit[0] == sig:
                return hit[1], hit[2]
        pol, reason = None, ""
        try:
            pol = Policy(_parse_bytes(raw, key))
        except PolicyError as e:
            first = e.messages[0] if e.messages else "invalid"
            reason = f"policy {key} rejected ({len(e.messages)} error(s); first: {first})"
        with _cache_lock:
            if len(_cache) >= _CACHE_MAX:
                _cache.clear()
            _cache[key] = (sig, pol, reason)
        return pol, reason
    except Exception as e:                                 # never raise
        return None, f"policy {path!s} cannot be loaded ({type(e).__name__})"


def _reset_policy_cache() -> None:
    """Test hook."""
    with _cache_lock:
        _cache.clear()
