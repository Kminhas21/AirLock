"""
Destination registry: who actually receives an action.

A registry is the deployment's own statement of where destinations really lead ("alias X forwards to Acme
staff"). This module

  * loads / validates / digests a registry (JSON, see docs/registry.md and eval/SPEC_REGISTRY.md),
  * scans a proposed tool call for destination tokens (`destinations`), shell and SQL included,
  * resolves tokens to (kind, party, entry id) with explicit precedence rules (`Registry.resolve_token`),
  * resolves a whole proposal to the set of external parties it reaches (`Registry.resolve`),
  * provides the evaluation helpers `degrade`, `corrupt`, `merge`, `default_registry`.

Nothing here raises on odd tool arguments: non-dict args, None, nested structures, unbalanced shell quotes and
garbage SQL all degrade to "no tokens" (or fewer tokens).  Pure standard library, deterministic.

Decisions the spec left open are listed in docs/registry.md ("Decisions and limitations") and in the comments
next to the code that implements them.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, NamedTuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = 1
KINDS = ("internal", "external", "relay")
MATCH_KEYS = ("email", "email_glob", "domain", "host", "url_prefix", "channel", "channel_glob",
              "path_prefix", "path_glob", "db_table", "repo", "queue", "any_glob")
TOKEN_KINDS = ("email", "url", "host", "channel", "handle", "path", "db_table", "repo", "queue", "assignee", "remote")

# Built-in defaults.  Keys a registry omits fall back to these; an explicit empty list switches a default off.
BUILTIN_DEFAULTS: dict[str, Any] = {
    "internal_domains": ["team.com"],
    "internal_path_prefixes": ["/project"],
    "internal_channel_globs": ["#internal-*"],
    "internal_handles": ["@alice", "@bob", "@charlie", "@diana"],   # extension: the team handles named in tools.py
    "internal_repo_owners": ["team"],                                # extension: the mock environment's repo is team/taskflow
    "unknown": "external",
}
_LIST_DEFAULTS = ("internal_domains", "internal_path_prefixes", "internal_channel_globs", "internal_handles",
                  "internal_repo_owners")
_LOOPBACK = {"localhost", "0.0.0.0", "::1"}

MAX_TEXT = 200_000        # characters of any single string that are examined
MAX_DEPTH = 12            # nesting depth of args that is examined
MAX_ITEMS = 2000          # list elements / dict items examined per container
MAX_SEGMENTS = 5000

# ---------------------------------------------------------------------------
# Small value types
# ---------------------------------------------------------------------------


class Token(NamedTuple):
    kind: str     # one of TOKEN_KINDS
    value: str    # canonical (lower-cased where matching is case-insensitive) value


class TokenResolution(NamedTuple):
    kind: str                 # 'internal' | 'external' | 'relay' | 'unknown'
    party: str | None         # slug; None for internal
    entry_id: str             # registry entry id | 'default' | 'unknown'


class ResolvedToken(NamedTuple):
    token: Token
    resolution: TokenResolution


@dataclass(frozen=True)
class Resolution:
    reaches: frozenset
    tokens: list
    registered: bool


# ---------------------------------------------------------------------------
# Slugs and parties
# ---------------------------------------------------------------------------

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SLD = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "nom"}
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def slug(s: Any) -> str:
    """Lower-case identifier made of [a-z0-9._-]; '#'/'@' prefixes dropped; 'unknown' if nothing is left."""
    t = str(s).strip().lower().lstrip("#@")
    t = re.sub(r"[^a-z0-9._-]+", "-", t).strip("-._")
    return t or "unknown"


def registrable_domain(host: str) -> str:
    """Heuristic registrable domain (no public-suffix list): last two labels, or three under a 2-letter ccTLD
    with a generic second level (foo.co.uk).  IPs, single labels and bracketed IPv6 are returned as they are."""
    h = str(host).strip().lower().strip("[]").rstrip(".")
    if not h:
        return "unknown"
    if ":" in h or _IPV4.match(h):
        return h
    labels = [x for x in h.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels) or "unknown"
    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _path_root(p: str) -> str:
    if p.startswith("~"):
        return "home"
    parts = [c for c in p.split("/") if c]
    return slug(parts[0]) if parts else "root"


def _unknown_party(tk: str, nv: str) -> str:
    if tk == "email":
        return registrable_domain(nv.rsplit("@", 1)[-1])
    if tk in ("url", "host"):
        return registrable_domain(_url_host(nv) if tk == "url" else nv)
    if tk == "path":
        return _path_root(nv)
    if tk == "repo":
        return slug(nv.split("/", 1)[0])
    return slug(nv)


# ---------------------------------------------------------------------------
# URL / host / path / identifier canonicalisation (shared by scanning and matching)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"^(?:(?P<scheme>[a-z][a-z0-9+.\-]*)://)?(?:[^/@?#\s]*@)?"
    r"(?P<host>\[[0-9a-f:.]+\]|[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*\.?)"
    r"(?::(?P<port>\d{1,5}))?(?P<rest>[/?#]\S*)?$", re.I)
_EMAIL_RE = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9._%+'\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_EMAIL_FULL = re.compile(r"^[A-Za-z0-9._%+'\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
_TEXT_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s<>\"'`)\]}]+")


def _hostlike(h: str) -> bool:
    h = h.lower().rstrip(".")
    if h == "localhost" or _IPV4.match(h):
        return True
    return "." in h and bool(re.fullmatch(r"[a-z]{2,}", h.rsplit(".", 1)[-1]))


def _parse_url(s: str, schemeless_ok: bool = True) -> dict | None:
    s = s.strip()
    if not s or len(s) > 4096:
        return None
    m = _URL_RE.match(s)
    if not m:
        return None
    scheme = (m.group("scheme") or "").lower()
    host = m.group("host").lower().rstrip(".")
    if not host:
        return None
    if not scheme and not (schemeless_ok and _hostlike(host.strip("[]"))):
        return None
    rest = m.group("rest") or ""
    path = re.split(r"[?#]", rest, maxsplit=1)[0]
    port = m.group("port")
    canon = f"{scheme or 'http'}://{host}{':' + port if port else ''}{path}"
    return {"scheme": scheme or "http", "host": host.strip("[]"), "port": port, "path": path,
            "canon": canon, "key": (host.strip("[]") + path).lower()}


def _url_host(value: str) -> str:
    p = _parse_url(value)
    return p["host"] if p else value.lower()


def _url_key(value: str) -> str:
    p = _parse_url(value)
    return p["key"] if p else value.lower()


_NO_PATH = re.compile(r"^/dev/(?:null|zero|stdin|stdout|stderr|tty|full|random|urandom|fd/.*|pts/.*)$")


def _norm_path(s: str) -> str | None:
    """Absolute or ~ path, normalised ('..' resolved, duplicate slashes collapsed); None if not such a path."""
    s = s.strip()
    if not s or len(s) > 4096 or "\x00" in s or not (s.startswith("/") or s.startswith("~")):
        return None
    s = re.sub(r"^/{2,}", "/", s)
    n = posixpath.normpath(s)
    if not (n.startswith("/") or n.startswith("~")):
        return None
    if _NO_PATH.match(n):
        return None
    return n


def _canon_table(raw: str) -> str | None:
    parts = re.findall(r'"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][\w$]*)', raw)
    names = [next(x for x in p if x).strip().lower() for p in parts]
    if not names or len(names) > 4:
        return None
    return ".".join(names[-2:])


def _canon_repo(s: str) -> str | None:
    s = s.strip().lower()
    s = re.sub(r"\.git$", "", s)
    m = re.fullmatch(r"([\w.\-]+)/([\w.\-]+)", s)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _canon_channel(s: str) -> str:
    s = s.strip().lower()
    return s if s[:1] in ("#", "@") else "#" + s


def _canon(tk: str, value: Any) -> str:
    """Canonical form of a token value, so resolve_token('email', 'A@B.com') == resolve_token('email', 'a@b.com')."""
    v = str(value).strip()
    if tk == "email" or tk == "host" or tk == "queue" or tk == "assignee" or tk == "remote":
        return v.lower().rstrip(".") if tk == "host" else v.lower()
    if tk == "url":
        p = _parse_url(v)
        return p["canon"] if p else v.lower()
    if tk in ("channel", "handle"):
        return _canon_channel(v) if tk == "channel" else ("@" + v.lower().lstrip("@"))
    if tk == "path":
        return _norm_path(v) or v
    if tk == "db_table":
        return _canon_table(v) or v.lower()
    if tk == "repo":
        return _canon_repo(v) or v.lower()
    return v.lower()


# ---------------------------------------------------------------------------
# Registry entries
# ---------------------------------------------------------------------------

_GLOB_KEYS = {"email_glob", "channel_glob", "path_glob", "any_glob"}
_APPLIES = {
    "email": {"email"}, "email_glob": {"email"},
    "domain": {"email", "url", "host"}, "host": {"url", "host", "remote"},
    "url_prefix": {"url"},
    "channel": {"channel", "handle"}, "channel_glob": {"channel", "handle"},
    "path_prefix": {"path"}, "path_glob": {"path"},
    "db_table": {"db_table"}, "repo": {"repo"}, "queue": {"queue", "assignee"},
    "any_glob": set(TOKEN_KINDS),
}
_KIND_RANK = {"relay": 3, "external": 2, "internal": 1}


def _literal_prefix_len(pat: str) -> int:
    m = re.search(r"[*?\[]", pat)
    return m.start() if m else len(pat)


def _norm_match(key: str, val: Any) -> tuple[str | None, str | None]:
    """(normalised value, error message)."""
    if not isinstance(val, str) or not val.strip():
        return None, f"match value for '{key}' must be a non-empty string"
    v = val.strip().lower()
    if key == "email":
        if not _EMAIL_FULL.match(v):
            return None, f"email value {val!r} must look like user@host.tld (use email_glob for patterns)"
        return v, None
    if key in ("domain", "host"):
        v = v.lstrip("@").rstrip(".")
        if (not v or re.search(r"[\s/@*?\[\]:]", v)) and not (key == "host" and re.fullmatch(r"[0-9a-f:.\[\]]+", v)):
            return None, f"{key} value {val!r} must be a bare host name (no scheme, path, port or wildcard)"
        return v.strip("[]"), None
    if key == "url_prefix":
        p = _parse_url(v, schemeless_ok=True)
        if not p:
            return None, f"url_prefix value {val!r} must start with a host (e.g. https://hooks.example.com/forward)"
        return p["key"], None
    if key == "channel":
        if re.search(r"\s", v) or v.lstrip("#@") == "":
            return None, f"channel value {val!r} must be like #name or @handle"
        return _canon_channel(v), None
    if key == "channel_glob":
        if v[:1] not in ("#", "@", "*", "?"):
            return None, f"channel_glob value {val!r} must start with #, @ or a wildcard"
        return v, None
    if key == "path_prefix":
        n = _norm_path(v)
        if n is None:
            return None, f"path_prefix value {val!r} must be an absolute path (or start with ~)"
        return n, None
    if key == "path_glob":
        if v[:1] not in ("/", "~", "*"):
            return None, f"path_glob value {val!r} must start with /, ~ or *"
        return v, None
    if key == "db_table":
        t = _canon_table(v) if re.fullmatch(r"""[\w$"`\[\]\s.]+""", v) else None
        if t is None or len([x for x in re.split(r"\.", v) if x]) > 2:
            return None, f"db_table value {val!r} must be 'table' or 'schema.table'"
        return t, None
    if key == "repo":
        r = _canon_repo(v)
        if r is None:
            return None, f"repo value {val!r} must be owner/name"
        return r, None
    return v, None   # queue, any_glob


@dataclass(frozen=True)
class Entry:
    id: str | None
    kind: str | None
    party: str | None
    match: dict
    note: str
    raw: Any = field(repr=False, compare=False, default=None)
    key: str | None = None
    nv: str | None = None
    errors: tuple = ()
    warns: tuple = ()
    label: str = ""

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def decision(self) -> tuple:
        return (self.kind, self.party if self.kind != "internal" else None)

    def static_spec(self) -> tuple:
        if self.key in ("email", "channel", "repo", "queue", "db_table"):
            return (4, len(self.nv))
        if self.key in ("domain", "host"):
            return (2, len(self.nv))
        if self.key == "any_glob":
            return (1, _literal_prefix_len(self.nv))
        if self.key in ("url_prefix", "path_prefix"):
            return (3, len(self.nv))
        return (3, _literal_prefix_len(self.nv))


def _parse_entry(i: int, raw: Any) -> Entry:
    label = f"entries[{i}]"
    if not isinstance(raw, dict):
        return Entry(None, None, None, {}, "", raw, errors=(f"{label}: entry must be an object",), label=label)
    rid = raw.get("id")
    errs: list[str] = []
    warns: list[str] = []
    if isinstance(rid, str) and rid.strip():
        eid = rid.strip()
        label = f"entry '{eid}'"
    else:
        eid = None
        errs.append(f"{label}: missing or empty 'id'")
    kind = raw.get("kind")
    if kind not in KINDS:
        errs.append(f"{label}: unknown kind {kind!r} (expected one of {', '.join(KINDS)})")
        kind = None
    party = raw.get("party")
    if kind in ("external", "relay"):
        if not isinstance(party, str) or not party.strip():
            errs.append(f"{label}: party is required for kind '{kind}'")
            party = None
        else:
            party = party.strip()
            if not _SLUG_RE.match(party):
                errs.append(f"{label}: party {party!r} must be a lowercase slug ([a-z0-9._-], starting with a letter or digit)")
                party = None
    elif kind == "internal":
        if party not in (None, ""):
            warns.append(f"{label}: party {party!r} is ignored for internal entries")
        party = None
    else:
        party = party if isinstance(party, str) else None
    note = raw.get("note")
    note = note if isinstance(note, str) else ""
    m = raw.get("match")
    key = nv = None
    mdict: dict = {}
    if not isinstance(m, dict):
        errs.append(f"{label}: 'match' must be an object with exactly one key")
    else:
        mdict = dict(m)
        if len(m) != 1:
            errs.append(f"{label}: match must have exactly one key (found {len(m)}: {', '.join(map(str, m)) or 'none'})")
        else:
            (k, v), = m.items()
            if k not in MATCH_KEYS:
                errs.append(f"{label}: unknown match key {k!r} (expected one of {', '.join(MATCH_KEYS)})")
            else:
                nv, e = _norm_match(k, v)
                if e:
                    errs.append(f"{label}: {e}")
                    nv = None
                else:
                    key = k
    return Entry(eid, kind, party, mdict, note, raw, key if not errs else None, nv if not errs else None,
                 tuple(errs), tuple(warns), label)


# ---------------------------------------------------------------------------
# Defaults normalisation
# ---------------------------------------------------------------------------

def _norm_defaults(raw: Any) -> tuple[dict, list[str]]:
    errs: list[str] = []
    out: dict[str, Any] = {k: (list(v) if isinstance(v, list) else v) for k, v in BUILTIN_DEFAULTS.items()}
    if raw is None:
        return out, errs
    if not isinstance(raw, dict):
        return out, ["defaults must be an object"]
    for k in _LIST_DEFAULTS:
        if k in raw:
            v = raw[k]
            if isinstance(v, list) and all(isinstance(x, str) for x in v):
                out[k] = [x.strip() for x in v if x.strip()]
            else:
                errs.append(f"defaults.{k} must be a list of strings")
    if "unknown" in raw:
        if raw["unknown"] in ("external", "internal"):
            out["unknown"] = raw["unknown"]
        else:
            errs.append("defaults.unknown must be 'external' or 'internal'")
    for k in raw:
        if k not in BUILTIN_DEFAULTS:
            errs.append(f"\x00warn defaults has unknown key {k!r}")
    # normalise
    out["internal_domains"] = [d.lower().lstrip("@.").rstrip(".") for d in out["internal_domains"]]
    out["internal_path_prefixes"] = [(_norm_path(p) or p) for p in out["internal_path_prefixes"]]
    out["internal_channel_globs"] = [g.lower() for g in out["internal_channel_globs"]]
    out["internal_handles"] = [_canon_channel(h) if h[:1] == "@" else "@" + h.lower().lstrip("@") for h in out["internal_handles"]]
    out["internal_handles"] = [h.lower() for h in out["internal_handles"]]
    out["internal_repo_owners"] = [o.lower() for o in out["internal_repo_owners"]]
    return out, errs


def _in_domains(host: str, domains: Iterable[str]) -> bool:
    h = host.lower().strip("[]").rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains if d)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class Registry:
    def __init__(self, raw: dict):
        self._raw = copy.deepcopy(raw)
        ents = self._raw.get("entries")
        self._entries_ok = isinstance(ents, list)
        self.entries: tuple[Entry, ...] = tuple(_parse_entry(i, e) for i, e in enumerate(ents)) if self._entries_ok else ()
        self.defaults, derrs = _norm_defaults(self._raw.get("defaults"))
        self._default_errs = [e for e in derrs if not e.startswith("\x00warn ")]
        self._default_warns = [e[len("\x00warn "):] for e in derrs if e.startswith("\x00warn ")]
        self._by_key: dict[str, list[Entry]] = {}
        for e in self.entries:
            if e.valid:
                self._by_key.setdefault(e.key, []).append(e)

    # ---- construction -----------------------------------------------------
    @classmethod
    def load(cls, src) -> "Registry":
        """Load from a dict, a Registry, or a path (str / os.PathLike) to a JSON file.  Tolerant: structural
        problems are reported by validate(), not raised.  Raises ValueError for non-JSON / non-object input and
        FileNotFoundError for a missing file."""
        if isinstance(src, Registry):
            return cls(src.to_dict())
        if isinstance(src, dict):
            return cls(src)
        if isinstance(src, (str, os.PathLike)):
            with open(src, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError(f"{src}: registry must be a JSON object")
            return cls(data)
        raise ValueError(f"cannot load a registry from {type(src).__name__}")

    def to_dict(self) -> dict:
        return copy.deepcopy(self._raw)

    # ---- validation -------------------------------------------------------
    def validate(self) -> list[str]:
        """Schema errors (empty list == valid).  Warnings are available from warnings()."""
        errs: list[str] = []
        if self._raw.get("version") != VERSION:
            errs.append(f"version must be {VERSION} (found {self._raw.get('version')!r})")
        if "defaults" in self._raw and not isinstance(self._raw["defaults"], dict):
            errs.append("defaults must be an object")
        else:
            errs.extend(self._default_errs)
        if not self._entries_ok:
            errs.append("entries must be a list")
        seen: dict[str, int] = {}
        for e in self.entries:
            errs.extend(e.errors)
            if e.id is not None:
                seen[e.id] = seen.get(e.id, 0) + 1
        for i, n in seen.items():
            if n > 1:
                errs.append(f"duplicate id {i!r} used by {n} entries")
        errs.extend(self._conflicts())
        return errs

    def warnings(self) -> list[str]:
        out: list[str] = []
        for k in self._raw:
            if k not in ("version", "defaults", "entries"):
                out.append(f"unknown top-level key {k!r} is ignored")
        out.extend(f"{w}" for w in self._default_warns)
        for e in self.entries:
            out.extend(e.warns)
        valid = [e for e in self.entries if e.valid]
        for i, a in enumerate(valid):
            for b in valid[i + 1:]:
                if a.key == b.key and a.nv == b.nv and a.decision == b.decision:
                    out.append(f"duplicate: entries '{a.id}' and '{b.id}' both say {a.key}={a.nv} with the same decision")
        return out

    def _conflicts(self) -> list[str]:
        out = []
        valid = [e for e in self.entries if e.valid]
        for i, a in enumerate(valid):
            for b in valid[i + 1:]:
                if a.decision == b.decision or not (_APPLIES[a.key] & _APPLIES[b.key]):
                    continue
                if a.static_spec() != b.static_spec():
                    continue
                if a.key in _GLOB_KEYS or b.key in _GLOB_KEYS:
                    overlap = fnmatch.fnmatchcase(a.nv, b.nv) or fnmatch.fnmatchcase(b.nv, a.nv)
                else:
                    overlap = a.nv == b.nv
                if overlap:
                    out.append(
                        f"conflict: entries '{a.id}' ({_fmt_decision(a)}, {a.key}={a.nv}) and '{b.id}' "
                        f"({_fmt_decision(b)}, {b.key}={b.nv}) match the same destinations with equal specificity "
                        f"but disagree")
        return out

    # ---- resolution -------------------------------------------------------
    def _candidates(self, tk: str, nv: str) -> list[tuple[tuple, Entry]]:
        forms: list[str] = [nv]
        host = domain = ukey = None
        if tk == "email":
            domain = nv.rsplit("@", 1)[-1]
        elif tk == "url":
            host, ukey = _url_host(nv), _url_key(nv)
            domain = host
            forms = [nv, ukey]
        elif tk == "host":
            host = domain = nv
        elif tk == "remote":
            host = nv
        found: list[tuple[tuple, Entry]] = []
        for key, ents in self._by_key.items():
            if tk not in _APPLIES[key]:
                continue
            for e in ents:
                spec = None
                v = e.nv
                if key == "email":
                    ok = nv == v
                    spec = (4, len(v)) if ok else None
                elif key == "email_glob":
                    spec = (3, _literal_prefix_len(v)) if fnmatch.fnmatchcase(nv, v) else None
                elif key == "domain":
                    spec = (2, len(v)) if domain and (domain == v or domain.endswith("." + v)) else None
                elif key == "host":
                    spec = (2, len(v)) if host is not None and host == v else None
                elif key == "url_prefix":
                    spec = (3, len(v)) if ukey is not None and (ukey.startswith(v) or (ukey + "/").startswith(v)) else None
                elif key in ("channel", "queue", "repo"):
                    spec = (4, len(v)) if nv == v else None
                elif key == "channel_glob":
                    spec = (3, _literal_prefix_len(v)) if fnmatch.fnmatchcase(nv, v) else None
                elif key == "path_prefix":
                    p = nv.lower()
                    spec = (3, len(v)) if (p == v or p.startswith(v.rstrip("/") + "/")) else None
                elif key == "path_glob":
                    spec = (3, _literal_prefix_len(v)) if fnmatch.fnmatchcase(nv.lower(), v) else None
                elif key == "db_table":
                    if nv == v:
                        spec = (4, 2)
                    elif "." not in v and nv.rsplit(".", 1)[-1] == v:
                        spec = (4, 1)
                elif key == "any_glob":
                    if any(fnmatch.fnmatchcase(f.lower(), v) for f in forms):
                        spec = (1, _literal_prefix_len(v))
                if spec is not None:
                    found.append((spec, e))
        return found

    def _default_resolution(self, tk: str, nv: str) -> TokenResolution | None:
        d = self.defaults
        internal = TokenResolution("internal", None, "default")
        if tk == "email":
            return internal if _in_domains(nv.rsplit("@", 1)[-1], d["internal_domains"]) else None
        if tk in ("url", "host"):
            h = _url_host(nv) if tk == "url" else nv
            if h in _LOOPBACK or h.startswith("127.") or _in_domains(h, d["internal_domains"]):
                return internal
            return None
        if tk in ("channel", "handle"):
            if nv in d["internal_handles"] or any(fnmatch.fnmatchcase(nv, g) for g in d["internal_channel_globs"]):
                return internal
            return None
        if tk == "path":
            p = nv
            for pre in d["internal_path_prefixes"]:
                pre = pre.lower().rstrip("/")
                if p.lower() == pre or p.lower().startswith(pre + "/") or pre == "":
                    return internal
            return None
        if tk == "repo":
            return internal if nv.split("/", 1)[0] in d["internal_repo_owners"] else None
        if tk in ("db_table", "queue", "assignee"):
            return internal      # in-deployment namespaces: internal unless an entry says otherwise
        return None

    def resolve_token(self, token_kind: str, value: Any) -> TokenResolution:
        """Resolve one destination token.  Precedence: the most specific matching entry wins (exact > glob/prefix
        by longer literal prefix > domain/host > any_glob); an entry beats the defaults; defaults beat unknown.
        Equal-specificity disagreements (a lint error) resolve deterministically to the most restrictive entry
        (relay > external > internal), then lowest party, then lowest id.  Never raises."""
        tk = token_kind if isinstance(token_kind, str) else "?"
        nv = _canon(tk, value)
        cands = self._candidates(tk, nv)
        if cands:
            cands.sort(key=lambda c: (-c[0][0], -c[0][1], -_KIND_RANK[c[1].kind], c[1].party or "", c[1].id))
            e = cands[0][1]
            return TokenResolution(e.kind, e.party, e.id)
        r = self._default_resolution(tk, nv)
        if r is not None:
            return r
        return TokenResolution("unknown", _unknown_party(tk, nv), "unknown")

    def resolve(self, tool: Any, args: Any, scan_text: bool = False) -> Resolution:
        toks = destinations(tool, args, scan_text=scan_text)
        resolved = [ResolvedToken(t, self.resolve_token(t.kind, t.value)) for t in toks]
        reaches = set()
        registered = False
        ext_unknown = self.defaults.get("unknown") == "external"
        for rt in resolved:
            r = rt.resolution
            if r.entry_id not in ("default", "unknown"):
                registered = True
            if r.kind in ("external", "relay") and r.party:
                reaches.add(r.party)
            elif r.kind == "unknown" and ext_unknown and r.party:
                reaches.add(r.party)
        return Resolution(frozenset(reaches), resolved, registered)

    # ---- digest -----------------------------------------------------------
    def digest(self) -> str:
        """Stable 16-hex digest of the semantics (defaults + entries); independent of entry order, JSON key
        order, notes and whitespace/case in match values.  Intended for /health."""
        ents = []
        for e in self.entries:
            if e.valid:
                ents.append([e.id, e.kind, e.party, e.key, e.nv])
            else:
                ents.append([e.id, "invalid", json.dumps(e.raw, sort_keys=True, default=str)])
        ents.sort(key=lambda x: json.dumps(x, default=str))
        d = {k: (sorted(v) if isinstance(v, list) else v) for k, v in self.defaults.items()}
        blob = json.dumps({"v": self._raw.get("version"), "defaults": d, "entries": ents}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _fmt_decision(e: Entry) -> str:
    return e.kind if e.kind == "internal" else f"{e.kind}:{e.party}"


# ---------------------------------------------------------------------------
# default_registry / degrade / corrupt / merge
# ---------------------------------------------------------------------------

def default_registry() -> Registry:
    """The defaults only (no entries): what v1 traces and 'no registry configured' use."""
    d = {k: (list(v) if isinstance(v, list) else v) for k, v in BUILTIN_DEFAULTS.items()}
    return Registry({"version": VERSION, "defaults": d, "entries": []})


def _rank(salt: str, seed: int, ident: str, index: int) -> str:
    return hashlib.sha256(f"{salt}|{seed}|{ident}|{index}".encode()).hexdigest()


def _pick(items: list[tuple[int, str]], fraction: float, seed: int, salt: str) -> set[int]:
    """Indices of round(fraction*len) items chosen by a hash ranking (stable across Python versions)."""
    if not isinstance(fraction, (int, float)) or isinstance(fraction, bool) or not (0.0 <= fraction <= 1.0):
        raise ValueError(f"fraction must be in [0, 1], got {fraction!r}")
    k = int(fraction * len(items) + 0.5)
    ranked = sorted(items, key=lambda it: _rank(salt, seed, it[1], it[0]))
    return {i for i, _ in ranked[:k]}


def degrade(registry: Registry, fraction: float, seed: int) -> Registry:
    """Drop round(fraction * n) of the entries (a deterministic function of seed and entry id); defaults kept."""
    d = registry.to_dict()
    raws = d.get("entries") if isinstance(d.get("entries"), list) else []
    items = [(i, e.id or f"#{i}") for i, e in enumerate(registry.entries)]
    drop = _pick(items, fraction, seed, "degrade")
    d["entries"] = [r for i, r in enumerate(raws) if i not in drop]
    return Registry(d)


def corrupt(registry: Registry, fraction: float, seed: int) -> Registry:
    """Give round(fraction * n_valid) entries the wrong kind and/or party (deterministic).  The match keys are
    untouched, so the result stays lint-clean.  Every chosen entry really changes."""
    d = registry.to_dict()
    raws = d.get("entries") if isinstance(d.get("entries"), list) else []
    valid = [(i, e.id) for i, e in enumerate(registry.entries) if e.valid]
    chosen = _pick(valid, fraction, seed, "corrupt")
    parties = sorted({e.party for e in registry.entries if e.valid and e.party})
    for i in sorted(chosen):
        e = registry.entries[i]
        h = int(_rank("mutate", seed, e.id, i), 16)

        def wrong_party(cur):
            others = [p for p in parties if p != cur]
            return others[h % len(others)] if others else f"wrong-{h % 1000:03d}"

        r = raws[i]
        if e.kind == "internal":
            r["kind"], r["party"] = "external", wrong_party(None)
        elif e.kind == "external":
            m = h % 3
            if m == 0:
                r["kind"], r["party"] = "internal", None
            elif m == 1:
                r["kind"] = "relay"
            else:
                r["party"] = wrong_party(e.party)
        else:  # relay
            m = h % 3
            if m == 0:
                r["kind"], r["party"] = "internal", None
            elif m == 1:
                r["kind"] = "external"
            else:
                r["party"] = wrong_party(e.party)
    return Registry(d)


@dataclass(frozen=True)
class Conflict:
    key: str
    value: str
    kept: tuple          # (source index, entry id, decision string)
    dropped: tuple

    def __str__(self) -> str:
        return (f"{self.key}={self.value}: kept {self.kept[1]!r} from registry #{self.kept[0]} ({self.kept[2]}), "
                f"dropped {self.dropped[1]!r} from registry #{self.dropped[0]} ({self.dropped[2]})")


def merge(registries: Iterable) -> tuple[Registry, list[Conflict]]:
    """Combine registries (Registry objects, dicts or paths).  Entries saying the same thing about the same match
    are deduplicated; entries with the same match but a different decision are reported as Conflict and the
    one from the EARLIER registry wins.  Colliding ids are renamed 'id@<source index>'.  Defaults: list keys are
    the union of the lists the registries state explicitly; 'unknown' is 'external' if any registry says so.
    Cross-key equal-specificity conflicts are not detected here: run validate() on the result."""
    regs = [Registry.load(r) for r in registries]
    entries: list[Any] = []
    seen: dict[tuple, tuple] = {}
    ids: set[str] = set()
    conflicts: list[Conflict] = []
    dlists: dict[str, list[str]] = {}
    unknowns: list[str] = []
    for si, reg in enumerate(regs):
        raw_def = reg._raw.get("defaults")
        if isinstance(raw_def, dict):
            for k in _LIST_DEFAULTS:
                if isinstance(raw_def.get(k), list):
                    lst = dlists.setdefault(k, [])
                    lst.extend(x for x in raw_def[k] if isinstance(x, str) and x not in lst)
            if raw_def.get("unknown") in ("external", "internal"):
                unknowns.append(raw_def["unknown"])
        raws = reg._raw.get("entries") if reg._entries_ok else []
        for e, raw in zip(reg.entries, raws):
            if e.valid:
                k = (e.key, e.nv)
                if k in seen:
                    prev = seen[k]
                    if prev[2] == e.decision:
                        continue
                    conflicts.append(Conflict(e.key, e.nv, (prev[0], prev[1], _fmt_decision_t(prev[2])),
                                              (si, e.id, _fmt_decision_t(e.decision))))
                    continue
                seen[k] = (si, e.id, e.decision)
            r = copy.deepcopy(raw)
            eid = e.id
            if isinstance(r, dict) and eid is not None:
                new = eid
                n = 0
                while new in ids:
                    new = f"{eid}@{si}" if n == 0 else f"{eid}@{si}.{n}"
                    n += 1
                ids.add(new)
                r["id"] = new
            entries.append(r)
    out: dict[str, Any] = {"version": VERSION, "entries": entries}
    if dlists or unknowns:
        dd: dict[str, Any] = dict(dlists)
        if unknowns:
            dd["unknown"] = "external" if "external" in unknowns else "internal"
        out["defaults"] = dd
    return Registry(out), conflicts


def _fmt_decision_t(dec: tuple) -> str:
    return dec[0] if dec[0] == "internal" else f"{dec[0]}:{dec[1]}"


# ---------------------------------------------------------------------------
# Token scanning
# ---------------------------------------------------------------------------

class _Out:
    """Ordered, de-duplicating token collector."""
    __slots__ = ("items", "seen")

    def __init__(self):
        self.items: list[Token] = []
        self.seen: set[Token] = set()

    def add(self, kind: str, value: str) -> None:
        if not value:
            return
        t = Token(kind, value)
        if t not in self.seen:
            self.seen.add(t)
            self.items.append(t)

    def add_email(self, e: str) -> None:
        self.add("email", e.lower())

    def add_url(self, s: str, schemeless_ok: bool = True) -> bool:
        s = s.strip()
        if re.match(r"^file://", s, re.I):
            p = _norm_path(re.sub(r"^file://[^/]*", "", s, flags=re.I))
            if p:
                self.add("path", p)
            return bool(p)
        p = _parse_url(s, schemeless_ok)
        if p:
            self.add("url", p["canon"])
            return True
        return False

    def add_host(self, h: str) -> None:
        h = h.strip().strip("[]").lower().rstrip(".")
        if h and re.fullmatch(r"[a-z0-9_\-.:]+", h):
            self.add("host", h)

    def add_path(self, s: str) -> bool:
        s = s.strip()
        m = re.match(r"^/dev/(?:tcp|udp)/([^/]+)/", s)
        if m:
            self.add_host(m.group(1))
            return True
        p = _norm_path(s)
        if p:
            self.add("path", p)
            return True
        return False


# ---- key-name driven handlers ------------------------------------------------

def _h_email(s, out):
    for m in _EMAIL_RE.finditer(s):
        out.add_email(m.group(0))


def _h_channel(s, out):
    for piece in re.split(r"[\s,;]+", s):
        piece = piece.strip("<>()[]'\".")
        if not piece:
            continue
        if _EMAIL_FULL.match(piece):
            out.add_email(piece)
        elif piece[0] == "#" and len(piece) > 1:
            out.add("channel", piece.lower())
        elif piece[0] == "@" and len(piece) > 1:
            out.add("handle", piece.lower())
        elif re.fullmatch(r"[\w.\-]+", piece):
            out.add("channel", "#" + piece.lower())


def _h_url(s, out):
    s = s.strip()
    if _EMAIL_FULL.match(s):
        out.add_email(s)
    else:
        out.add_url(s)


def _h_host(s, out):
    p = _parse_url(s.strip())
    if p:
        out.add_host(p["host"])


def _h_path(s, out):
    out.add_path(s)


def _h_queue(s, out):
    v = s.strip().lower()
    if v and len(v) <= 256:
        out.add("queue", v)


_TASK_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]*-\d+$")


def _h_task_id(s, out):
    """A task key like MSYNC-41 is a destination: the task itself and its project (MSYNC) may be shared externally."""
    v = s.strip()
    if _TASK_KEY.match(v):
        out.add("queue", v.lower())
        out.add("queue", v.rsplit("-", 1)[0].lower())


def _h_assignee(s, out):
    v = s.strip()
    if not v or len(v) > 256:
        return
    if _EMAIL_FULL.match(v):
        out.add_email(v)
    elif v.startswith("@") and len(v) > 1:
        out.add("handle", v.lower())
    else:
        out.add("assignee", v.lower())


def _h_table(s, out):
    if re.fullmatch(r"""[\w$"`\[\]\s.]+""", s.strip()):
        t = _canon_table(s)
        if t:
            out.add("db_table", t)


_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "www.github.com", "www.gitlab.com"}


def _h_repo(s, out):
    s = s.strip()
    if not s:
        return
    r = _canon_repo(s)
    if r:
        out.add("repo", r)
        return
    m = _REMOTE_RE.match(s)
    if "://" in s or s.lower().startswith(tuple(h + "/" for h in _GIT_HOSTS)):
        if out.add_url(s):
            p = _parse_url(s)
            if p and p["host"] in _GIT_HOSTS:
                segs = [x for x in p["path"].split("/") if x]
                if len(segs) >= 2:
                    rr = _canon_repo(f"{segs[0]}/{segs[1]}")
                    if rr:
                        out.add("repo", rr)
        return
    if m and m.group("user"):
        out.add_host(m.group("host"))
        segs = [x for x in m.group("path").split("/") if x]
        if len(segs) >= 2 and m.group("host").lower() in _GIT_HOSTS:
            rr = _canon_repo(f"{segs[-2]}/{segs[-1]}")
            if rr:
                out.add("repo", rr)


def _h_sql(s, out, depth=0):
    _sql(s, out, depth)


_KEY_HANDLERS = {}
for _k in ("to", "cc", "bcc", "recipient", "recipients", "email", "emails", "reply_to"):
    _KEY_HANDLERS[_k] = _h_email
for _k in ("channel", "channels"):
    _KEY_HANDLERS[_k] = _h_channel
for _k in ("url", "urls", "endpoint", "webhook", "webhook_url", "callback_url", "callback", "uri", "href", "link", "target_url"):
    _KEY_HANDLERS[_k] = _h_url
for _k in ("host", "hostname", "server"):
    _KEY_HANDLERS[_k] = _h_host
for _k in ("path", "dest", "destination", "output", "output_path", "outfile", "file_path"):
    _KEY_HANDLERS[_k] = _h_path
for _k in ("queue", "board", "project", "topic"):
    _KEY_HANDLERS[_k] = _h_queue
for _k in ("assignee", "assignees"):
    _KEY_HANDLERS[_k] = _h_assignee
_KEY_HANDLERS["task_id"] = _h_task_id
_KEY_HANDLERS["id"] = _h_task_id  # only task-key-shaped values count (numeric ids are ignored)
_KEY_HANDLERS["table"] = _h_table
for _k in ("repo", "repository"):
    _KEY_HANDLERS[_k] = _h_repo
_KEY_HANDLERS["sql"] = _h_sql

# Free-text parameters of the known tools: content, not destinations (scanned only with scan_text=True).
_TOOL_FREE = {
    "write_file": {"content"},
    "send_email": {"subject", "body"},
    "send_slack_message": {"message"},
    "post_to_webhook": {"payload"},
    "update_task": {"status", "title", "priority"},
    "create_task": {"title", "priority"},
    "create_github_issue": {"title", "body", "labels"},
    "query_database": set(),
    "run_shell_command": set(),
}
# Destination parameters scanned first, in this order.
_TOOL_PRIMARY = {
    "write_file": ("path",),
    "send_email": ("to",),
    "send_slack_message": ("channel",),
    "post_to_webhook": ("url",),
    "query_database": ("query",),
    "run_shell_command": ("command",),
    "create_github_issue": ("repo", "repository"),
}
_NO_DEST_TOOLS = {"read_file", "list_directory", "search_files", "delete_file"}


# ---- generic text scanning ---------------------------------------------------

_CHAN_RE = re.compile(r"(?<![\w&/#@])#([A-Za-z][\w\-]*)")
_HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z](?:[\w.\-]*\w)?)")
_PATH_RE = re.compile(r"(?<![\w.:/~@%+\-])(~?(?:/[\w.~+%\-@]+)+/?)")


def _scan_text(s: str, out: _Out) -> None:
    """Emails, URLs, #channels, @handles and absolute paths of a free string, in order of appearance."""
    s = s[:MAX_TEXT]
    found: list[tuple[int, str, str]] = []
    chars = list(s)
    for m in _TEXT_URL_RE.finditer(s):
        u = m.group(0).rstrip(".,;:!?")
        found.append((m.start(), "url", u))
        for i in range(m.start(), m.end()):
            chars[i] = " "
    s2 = "".join(chars)
    chars = list(s2)
    for m in _EMAIL_RE.finditer(s2):
        found.append((m.start(), "email", m.group(0)))
        for i in range(m.start(), m.end()):
            chars[i] = " "
    s3 = "".join(chars)
    for m in _CHAN_RE.finditer(s3):
        found.append((m.start(), "channel", "#" + m.group(1).lower()))
    for m in _HANDLE_RE.finditer(s3):
        found.append((m.start(), "handle", "@" + m.group(1).lower()))
    for m in _PATH_RE.finditer(s3):
        found.append((m.start(), "path", m.group(1).rstrip(".,;:")))
    found.sort(key=lambda x: x[0])
    for _, kind, v in found:
        if kind == "url":
            out.add_url(v, schemeless_ok=False)
        elif kind == "email":
            out.add_email(v)
        elif kind == "path":
            out.add_path(v)
        else:
            out.add(kind, v)


# ---- value walker ------------------------------------------------------------

def _walk(key: str, value: Any, out: _Out, depth: int, special: dict | None = None, scan_text: bool = False) -> None:
    if depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        h = (special or {}).get(key) or _KEY_HANDLERS.get(key.lower())
        if h is not None:
            h(value[:MAX_TEXT], out)
        else:
            _scan_text(value, out)
    elif isinstance(value, dict):
        for n, (k, v) in enumerate(value.items()):
            if n >= MAX_ITEMS:
                break
            _walk(str(k), v, out, depth + 1, None, scan_text)
    elif isinstance(value, (list, tuple)):
        for n, v in enumerate(value):
            if n >= MAX_ITEMS:
                break
            _walk(key, v, out, depth + 1, special, scan_text)


# ---------------------------------------------------------------------------
# Shell parsing
# ---------------------------------------------------------------------------

def _lex(cmd: str) -> list[tuple[list[str], list[tuple[str, str]]]]:
    """Split a shell command line into segments of (words, redirects[(op, target)]).  Lenient: quotes are honoured,
    unbalanced quotes run to the end, command separators ; & && | || newline ( ) ` $( split segments."""
    segs: list[tuple[list[str], list[tuple[str, str]]]] = []
    words: list[str] = []
    redirs: list[tuple[str, str]] = []
    cur: list[str] = []
    has = False
    pending: str | None = None
    i, n = 0, len(cmd)

    def end_word():
        nonlocal cur, has, pending
        if has or cur:
            w = "".join(cur)
            if pending is not None:
                redirs.append((pending, w))
                pending = None
            else:
                words.append(w)
        cur, has = [], False

    def end_seg():
        nonlocal words, redirs, pending
        end_word()
        pending = None
        if words or redirs:
            segs.append((words, redirs))
        words, redirs = [], []

    while i < n and len(segs) < MAX_SEGMENTS:
        c = cmd[i]
        if c == "\\":
            if i + 1 < n:
                if cmd[i + 1] != "\n":
                    cur.append(cmd[i + 1])
                    has = True
                i += 2
            else:
                i += 1
        elif c == "'":
            j = cmd.find("'", i + 1)
            j = n if j < 0 else j
            cur.append(cmd[i + 1:j])
            has = True
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and cmd[j] != '"':
                if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in '\\"$`\n':
                    if cmd[j + 1] != "\n":
                        cur.append(cmd[j + 1])
                    j += 2
                else:
                    cur.append(cmd[j])
                    j += 1
            has = True
            i = j + 1
        elif c in " \t\r":
            end_word()
            i += 1
        elif c in ";\n`()":
            end_seg()
            i += 1
        elif c == "$" and i + 1 < n and cmd[i + 1] == "(":
            end_seg()
            i += 2
        elif c == "&":
            if i + 1 < n and cmd[i + 1] == ">":
                op = "&>>" if cmd[i + 2:i + 3] == ">" else "&>"
                if "".join(cur).isdigit() and not has:
                    pass
                end_word()
                pending = op
                i += len(op)
            else:
                end_seg()
                i += 2 if cmd[i + 1:i + 2] == "&" else 1
        elif c == "|":
            end_seg()
            i += 2 if cmd[i + 1:i + 2] in ("|", "&") else 1
        elif c == ">":
            if cur and "".join(cur).isdigit() and not has:
                cur = []      # fd number of "2>file"
            else:
                end_word()
            op = ">"
            if cmd[i + 1:i + 2] == ">":
                op = ">>"
            elif cmd[i + 1:i + 2] in ("|", "&"):
                op = ">" + cmd[i + 1]
            pending = op
            i += len(op)
        elif c == "<":
            if cur and "".join(cur).isdigit() and not has:
                cur = []
            else:
                end_word()
            op = "<"
            while cmd[i + len(op):i + len(op) + 1] == "<" and len(op) < 3:
                op += "<"
            pending = op
            i += len(op)
        else:
            cur.append(c)
            i += 1
    end_seg()
    return segs


_ASSIGN_RE = re.compile(r"^[A-Za-z_]\w*=")
_WRAPPERS = {
    "sudo": ({"u", "g", "h", "p", "C", "D", "R", "T", "U", "r", "t"}, 0), "doas": ({"u", "C"}, 0),
    "env": ({"u", "C", "S"}, 0), "nohup": (set(), 0), "time": (set(), 0), "command": (set(), 0),
    "exec": ({"a"}, 0), "builtin": (set(), 0), "setsid": (set(), 0), "stdbuf": ({"i", "o", "e"}, 0),
    "nice": ({"n"}, 0), "ionice": ({"c", "n", "p", "t"}, 0), "timeout": ({"s", "k"}, 1),
    "xargs": ({"I", "n", "P", "L", "d", "E", "s", "a", "J"}, 0), "watch": ({"n"}, 0),
}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}


def _unwrap(words: list[str]) -> list[str]:
    i = 0
    while i < len(words):
        w = words[i]
        if _ASSIGN_RE.match(w):
            i += 1
            continue
        spec = _WRAPPERS.get(posixpath.basename(w).lower())
        if spec is None:
            break
        valset, skip = spec
        i += 1
        while i < len(words) and words[i].startswith("-") and len(words[i]) > 1:
            f = words[i]
            i += 1
            if f == "--":
                break
            if f.startswith("--"):
                continue
            for j, c in enumerate(f[1:], 1):
                if c in valset:
                    if j == len(f) - 1:
                        i += 1
                    break
        i += skip
    return words[i:]


def _parse_opts(args: list[str], short_val: Iterable[str] = (), long_val: Iterable[str] = ()):
    short_val, long_val = set(short_val), set(long_val)
    pos: list[str] = []
    opts: list[tuple[str, str | None]] = []
    i, end = 0, False
    while i < len(args):
        a = args[i]
        if end or len(a) < 2 or not a.startswith("-"):
            pos.append(a)
            i += 1
            continue
        if a == "--":
            end = True
            i += 1
            continue
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if eq:
                opts.append((name, val))
            elif name in long_val and i + 1 < len(args):
                opts.append((name, args[i + 1]))
                i += 1
            else:
                opts.append((name, None))
            i += 1
            continue
        j = 1
        while j < len(a):
            c = a[j]
            if c in short_val:
                rest = a[j + 1:]
                if rest:
                    opts.append((c, rest))
                elif i + 1 < len(args):
                    opts.append((c, args[i + 1]))
                    i += 1
                else:
                    opts.append((c, None))
                break
            opts.append((c, None))
            j += 1
        i += 1
    return pos, opts


_REMOTE_RE = re.compile(r"^(?:(?P<user>[^@/:\s]+)@)?(?P<host>\[[0-9a-fA-F:.]+\]|[A-Za-z0-9_][A-Za-z0-9_.\-]*)::?(?P<path>.*)$", re.S)
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


def _remote_spec(w: str):
    if _SCHEME_RE.match(w):
        return None
    m = _REMOTE_RE.match(w)
    if m and len(m.group("host")) > 1:
        return m
    return None


def _xfer_dest(w: str, out: _Out) -> None:
    if _SCHEME_RE.match(w):
        out.add_url(w, schemeless_ok=False)
        return
    m = _remote_spec(w)
    if m:
        out.add_host(m.group("host"))
        return
    out.add_path(w)


def _target_host(w: str, out: _Out) -> None:
    """[user@]host[:port|:path] or a URL (ssh, sftp, telnet, ftp)."""
    if _SCHEME_RE.match(w):
        out.add_url(w, schemeless_ok=False)
        return
    w = w.rsplit("@", 1)[-1]
    m = re.match(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9_][A-Za-z0-9_.\-]*)(?::.*)?$", w)
    if m:
        out.add_host(m.group(1))


_CURL_SV = "XHdouAeFTbcxmwKErYyzCDUQP"
_CURL_LV = {"request", "header", "data", "data-raw", "data-binary", "data-urlencode", "data-ascii", "form", "form-string",
            "output", "user", "user-agent", "referer", "cookie", "cookie-jar", "proxy", "max-time", "connect-timeout",
            "write-out", "config", "cert", "key", "cacert", "upload-file", "range", "retry", "limit-rate", "resolve",
            "json", "oauth2-bearer", "aws-sigv4", "dump-header", "proxy-user", "url"}
_WGET_SV = "OoPeUitTwBlQaARDIXH".replace("H", "")
_WGET_LV = {"header", "post-data", "post-file", "output-document", "output-file", "user", "password", "directory-prefix",
            "user-agent", "referer", "tries", "timeout", "wait", "limit-rate", "bind-address", "certificate",
            "ca-certificate", "load-cookies", "save-cookies", "body-data", "body-file", "method", "http-user",
            "http-password", "input-file", "base", "execute"}
_RSYNC_LV = {"exclude", "include", "exclude-from", "include-from", "rsh", "port", "log-file", "files-from", "filter",
             "backup-dir", "partial-dir", "temp-dir", "bwlimit", "timeout", "chmod", "chown", "compare-dest",
             "copy-dest", "link-dest", "rsync-path", "address", "max-size", "min-size", "suffix"}
_URL_SCAN_CMDS = {"node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "aws", "gsutil", "gcloud", "az", "rclone",
                  "s3cmd", "mc", "lftp", "http", "https", "httpie", "xh", "docker"}
_MAIL_CMDS = {"mail", "mailx", "s-nail", "mutt", "sendmail", "msmtp", "heirloom-mailx"}


def _shell(cmd: str, out: _Out, depth: int = 0) -> None:
    if depth > 3 or not isinstance(cmd, str):
        return
    for words, redirs in _lex(cmd[:MAX_TEXT]):
        _segment(_unwrap(words), out, depth)
        for op, target in redirs:
            if op.startswith(">") or op.startswith("&>"):
                if target.startswith("&") or target.isdigit() or target == "-":
                    continue
                out.add_path(target)


def _segment(words: list[str], out: _Out, depth: int) -> None:
    if not words:
        return
    name = posixpath.basename(words[0]).lower()
    args = words[1:]
    if name in _SHELLS:
        for idx, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and idx + 1 < len(args):
                _shell(args[idx + 1], out, depth + 1)
                return
        return
    if name == "eval":
        _shell(" ".join(args), out, depth + 1)
        return
    if name == "scp":
        pos, _ = _parse_opts(args, "PioFclJSD")
        if pos:
            _xfer_dest(pos[-1], out)
    elif name == "rsync":
        pos, _ = _parse_opts(args, "efTBM", _RSYNC_LV)
        if pos:
            _xfer_dest(pos[-1], out)
    elif name in ("ssh", "sftp", "telnet", "ftp", "lftp"):
        sv = {"ssh": "pilOoFJLRDbcemQSWwBEI", "sftp": "PiosFbBcDlRSsJ"}.get(name, "")
        pos, opts = _parse_opts(args, sv)
        if pos:
            _target_host(pos[0], out)
    elif name in ("nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"):
        pos, opts = _parse_opts(args, "pswiIOqTXxecmMPVW")
        if any(f == "l" or f == "listen" for f, _ in opts):
            return
        if pos and (_hostlike(pos[0]) or re.search(r"[A-Za-z]", pos[0])) and not pos[0].isdigit():
            _target_host(pos[0], out)
    elif name == "curl":
        pos, opts = _parse_opts(args, _CURL_SV, _CURL_LV)
        for f, v in opts:
            if f == "url" and v:
                out.add_url(v)
        for p in pos:
            out.add_url(p)
    elif name == "wget":
        pos, opts = _parse_opts(args, _WGET_SV, _WGET_LV)
        for p in pos:
            out.add_url(p)
    elif name == "git":
        _git(args, out)
    elif name in ("cp", "mv", "install"):
        pos, opts = _parse_opts(args, "tSmog", {"target-directory", "suffix", "mode", "owner", "group"})
        tdir = next((v for f, v in opts if f in ("t", "target-directory") and v), None)
        if tdir:
            out.add_path(tdir)
        elif len(pos) >= 2:
            out.add_path(pos[-1])
    elif name == "tee":
        pos, _ = _parse_opts(args)
        for p in pos:
            out.add_path(p)
    elif name == "dd":
        for a in args:
            if a.startswith("of="):
                out.add_path(a[3:])
    elif name in _MAIL_CMDS:
        for a in args:
            a = re.sub(r"^--?(?:to|cc|bcc)=", "", a)
            if _EMAIL_FULL.match(a):
                out.add_email(a)
    elif name in ("psql", "mysql", "mariadb"):
        if name == "psql":
            pos, opts = _parse_opts(args, "hpUdcfovFRPTL", {"host", "command", "output", "username", "dbname", "file", "port"})
            sqlf, hostf = ("c", "command"), ("h", "host")
        else:
            pos, opts = _parse_opts(args, "hPuDeS", {"host", "execute", "user", "database", "port", "socket"})
            sqlf, hostf = ("e", "execute"), ("h", "host")
        for f, v in opts:
            if not v:
                continue
            if f in hostf and not v.startswith("/"):
                out.add_host(v)
            elif f in sqlf:
                _sql(v, out, 1)
            elif name == "psql" and f in ("o", "output"):
                out.add_path(v)
        for p in pos:
            if _SCHEME_RE.match(p):
                out.add_url(p, schemeless_ok=False)
    elif name in ("sqlite3", "sqlite"):
        pos, _ = _parse_opts(args)
        for p in pos[1:]:
            _sql(p, out, 1)
    elif name.startswith("python") or name in _URL_SCAN_CMDS:
        for w in args:
            for m in _TEXT_URL_RE.finditer(w[:MAX_TEXT]):
                out.add_url(m.group(0).rstrip(".,;:!?"), schemeless_ok=False)


def _git(args: list[str], out: _Out) -> None:
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            break
    if i >= len(args) or args[i] != "push":
        return
    pos, opts = _parse_opts(args[i + 1:], "o", {"push-option", "repo", "receive-pack", "exec"})
    remote = next((v for f, v in opts if f == "repo" and v), None)
    if remote is None:
        remote = pos[0] if pos else "origin"
    if _SCHEME_RE.match(remote):
        out.add_url(remote, schemeless_ok=False)
        return
    m = _remote_spec(remote)
    if m and (m.group("user") or "." in m.group("host")):
        out.add_host(m.group("host"))
        return
    if remote.startswith(("/", "~")):
        out.add_path(remote)
        return
    if remote.startswith(".") or "/" in remote:
        return
    out.add("remote", remote.lower())


# ---------------------------------------------------------------------------
# SQL parsing (writes only)
# ---------------------------------------------------------------------------

def _sql_mask(sql: str) -> tuple[str, list[str]]:
    """Remove comments, replace string literals by '#<i>' placeholders (kept in the returned list)."""
    out: list[str] = []
    lits: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c == "'":
            j = i + 1
            buf = []
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                if sql[j] == "\\" and j + 1 < n:
                    buf.append(sql[j + 1])
                    j += 2
                    continue
                buf.append(sql[j])
                j += 1
            lits.append("".join(buf))
            out.append(f"'#{len(lits) - 1}'")
            i = j + 1
        elif c == "$" and re.match(r"\$(?:[A-Za-z_]\w*)?\$", sql[i:i + 40]):
            tag = re.match(r"\$(?:[A-Za-z_]\w*)?\$", sql[i:i + 40]).group(0)
            j = sql.find(tag, i + len(tag))
            body = sql[i + len(tag):] if j < 0 else sql[i + len(tag):j]
            lits.append(body)
            out.append(f"'#{len(lits) - 1}'")
            i = n if j < 0 else j + len(tag)
        elif c in '"`':
            j = sql.find(c, i + 1)
            j = n - 1 if j < 0 else j
            out.append(sql[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out), lits


_ID = r'(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][\w$]*)'
_QN = rf"(?:{_ID}(?:\s*\.\s*{_ID}){{0,3}})"
_F = re.I | re.S
_SQL_PATTERNS = [
    re.compile(rf"\bINSERT\s+(?:OR\s+\w+\s+|IGNORE\s+|LOW_PRIORITY\s+|DELAYED\s+|HIGH_PRIORITY\s+)*INTO\s+(?:TABLE\s+)?(?P<n>{_QN})", _F),
    re.compile(rf"\bREPLACE\s+(?:LOW_PRIORITY\s+|DELAYED\s+)?INTO\s+(?:TABLE\s+)?(?P<n>{_QN})", _F),
    re.compile(rf"\bMERGE\s+INTO\s+(?P<n>{_QN})", _F),
    re.compile(rf"\bUPDATE\s+(?:ONLY\s+|OR\s+\w+\s+|LOW_PRIORITY\s+|IGNORE\s+)*(?P<n>{_QN})(?:\s+(?:AS\s+)?{_ID})?\s+SET\b", _F),
    re.compile(rf"\bDELETE\s+FROM\s+(?:ONLY\s+)?(?P<n>{_QN})", _F),
    re.compile(rf"\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(?P<n>{_QN})", _F),
    re.compile(rf"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+|UNLOGGED\s+|VIRTUAL\s+)?"
               rf"(?:TABLE|VIEW|MATERIALIZED\s+VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<n>{_QN})", _F),
    re.compile(rf"\bSELECT\b(?:(?!\bFROM\b|\bINTO\b).)*?\bINTO\s+(?:(?:TEMP|TEMPORARY|UNLOGGED|TABLE)\s+)?(?!OUTFILE\b|DUMPFILE\b)(?P<n>{_QN})", _F),
    re.compile(rf"\bLOAD\s+DATA\b.*?\bINTO\s+TABLE\s+(?P<n>{_QN})", _F),
]
_SQL_STOP = {"select", "values", "table", "set", "where", "from", "into", "default", "if", "only", "as", "with", "(", "temp",
             "temporary", "unlogged", "not", "exists"}
_SQL_OUTFILE = re.compile(r"\bINTO\s+(?:OUTFILE|DUMPFILE)\s+'#(?P<li>\d+)'", _F)
_SQL_COPY = re.compile(rf"\bCOPY\b(?P<body>.*?)\b(?P<dir>TO|FROM)\b\s*(?P<prog>PROGRAM\s+)?(?:'#(?P<li>\d+)'|(?P<std>STDOUT|STDIN))", _F)


def _sql(sql: Any, out: _Out, depth: int = 0) -> None:
    """Add the tables / files written by the statements of `sql` (reads add nothing)."""
    if not isinstance(sql, str) or depth > 3:
        return
    masked, lits = _sql_mask(sql[:MAX_TEXT])
    for stmt in masked.split(";"):
        if not stmt.strip():
            continue
        found: list[tuple[int, str, str]] = []
        for pat in _SQL_PATTERNS:
            for m in pat.finditer(stmt):
                t = _canon_table(m.group("n"))
                if t and t.split(".")[-1] not in _SQL_STOP:
                    found.append((m.start("n"), "db_table", t))
        for m in _SQL_OUTFILE.finditer(stmt):
            found.append((m.start(), "path", lits[int(m.group("li"))]))
        m = _SQL_COPY.search(stmt)
        if m:
            body = m.group("body").strip()
            if m.group("dir").upper() == "FROM":
                if not body.startswith("("):
                    qm = re.match(_QN, body)
                    t = _canon_table(qm.group(0)) if qm else None
                    if t:
                        found.append((m.start(), "db_table", t))
            elif m.group("li") is not None:
                lit = lits[int(m.group("li"))]
                found.append((m.start(), "program" if m.group("prog") else "path", lit))
        found.sort(key=lambda x: x[0])
        for _, kind, v in found:
            if kind == "db_table":
                out.add("db_table", v)
            elif kind == "path":
                out.add_path(v)
            else:
                _shell(v, out, depth + 1)


# ---------------------------------------------------------------------------
# Public: destinations
# ---------------------------------------------------------------------------

def destinations(tool: Any, args: Any, scan_text: bool = False) -> list[Token]:
    """Destination tokens of a proposed call: where its effect would be delivered.

    Per tool: read_file / list_directory / search_files / delete_file produce nothing (nothing leaves);
    write_file -> path; send_email -> to (+ cc/bcc/extras); send_slack_message -> channel/handle/email;
    post_to_webhook -> url; query_database -> tables/files WRITTEN by the SQL (SELECT-only: nothing);
    update_task / create_task -> assignee and queue-like fields; run_shell_command -> parsed command line;
    create_github_issue -> repo (implicitly team/taskflow when none is given).
    Parameters of known tools that carry free text (body, content, message, payload, subject, title, labels ...)
    are NOT scanned unless scan_text=True; every other string anywhere in args (and every string of an unknown
    tool) is scanned.  Order is the order of first appearance; duplicates are removed.  Never raises."""
    try:
        return _destinations(tool, args, scan_text)
    except RecursionError:     # pragma: no cover - defensive
        return []


def _destinations(tool: Any, args: Any, scan_text: bool) -> list[Token]:
    out = _Out()
    if not isinstance(args, dict):
        return out.items
    t = tool if isinstance(tool, str) else None
    if t in _NO_DEST_TOOLS:
        return out.items
    free = set() if scan_text else _TOOL_FREE.get(t, set())
    primary = _TOOL_PRIMARY.get(t, ())
    if t == "create_github_issue":
        given = [args.get(k) for k in ("repo", "repository")]
        if not any(isinstance(g, str) and g.strip() for g in given):
            out.add("repo", "team/taskflow")
    special: dict[str, Any] = {}
    if t == "query_database":
        special["query"] = _h_sql
    elif t == "run_shell_command":
        special["command"] = lambda s, o: _shell(s, o)
    for k in primary:
        if k in args:
            _walk(k, args[k], out, 0, special, scan_text)
    for k, v in args.items():
        ks = str(k)
        if ks in primary or ks in free:
            continue
        if t == "query_database" and ks == "query":
            continue
        _walk(ks, v, out, 0, None, scan_text)
    return out.items
