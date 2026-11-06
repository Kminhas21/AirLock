"""Identity, tenancy and roles (docs/plans/IDENTITY.md, ticket ID1).  Pure: no FastAPI.

    store = IdentityStore.load("/etc/sentinel/identity.json")             # raises IdentityError(ALL messages)
    principal, reason = store.authenticate_ex("operator", credential, remote="203.0.113.7")
    can(principal, "decide", server="fs", tenant="acme")

Credentials: static tokens (only their SHA-256 digests live in the file; digests are compared with hmac.compare_digest over
fixed-length hex against EVERY candidate, without early exit) or, for operators, a JWT verified OFFLINE against a PEM public key
or a JWKS file (algorithm allowlist RS256/384/512, ES256/384/512, PS256; `none` and HS* are never accepted; `exp`, `iss`, `aud`
required).  Nothing here ever logs or returns credential material, and `authenticate*` never raise.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import threading
import time
import urllib.parse
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Mapping

try:
    import jwt as _jwt
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
except ImportError:                                       # pragma: no cover - JWT auth is then simply unavailable
    _jwt = None

log = logging.getLogger("sentinel.identity")

VERSION = 1
ROLES = ("viewer", "approver", "admin")
_ROLE_RANK = {"viewer": 1, "approver": 2, "admin": 3}
ACTIONS = ("view", "decide", "rules")
JWT_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256")
_EC_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}
REASONS = ("ok", "unauthorized", "throttled", "expired", "bad_signature", "bad_claims", "unsupported")

MAX_FILE_BYTES = 1_000_000
MAX_IDENTITIES = 10_000
MAX_TENANTS = 1000
MAX_CHANNELS = 20
MAX_LEVELS = 10
MAX_NOTIFY = 10
MAX_SERVER_GLOBS = 50
MAX_GLOB = 200
MAX_CREDENTIAL = 16384
MAX_KEY_FILE = 256 * 1024
MAX_JWKS_KEYS = 100
MAX_LEEWAY = 30
THROTTLE_FAILURES, THROTTLE_WINDOW_S, THROTTLE_BLOCK_S, THROTTLE_MAX_REMOTES = 5, 60, 60, 10_000
MIN_RSA_BITS = 2048

_ID_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_LOOPBACK = ("127.0.0.1", "::1", "localhost")
_TOP_KEYS = {"version", "tenants", "operators", "agents", "jwt"}
_TENANT_KEYS = {"name", "policy_file", "gate_timeout_s", "escalation", "channels"}
_CHANNEL_KEYS = {"type", "url", "format", "secret_env", "include_args", "allow_private"}
_OPERATOR_KEYS = {"id", "tenant", "role", "token_sha256", "jwt_sub", "servers"}
_AGENT_KEYS = {"id", "tenant", "token_sha256", "servers"}
_JWT_KEYS = {"issuer", "audience", "algorithms", "public_key_file", "jwks_file", "leeway_s"}


class IdentityError(Exception):
    def __init__(self, messages):
        if isinstance(messages, str):
            messages = [messages]
        self.messages: list = list(messages)
        super().__init__("; ".join(self.messages) if self.messages else "invalid identity file")


@dataclass(frozen=True)
class Principal:
    kind: str                       # operator | agent
    id: str
    tenant: str
    role: str                       # viewer | approver | admin | agent
    servers: "tuple | None"
    via: str                        # token | jwt | legacy


@dataclass(frozen=True)
class Level:
    after_s: float
    notify: tuple


@dataclass(frozen=True)
class Channel:
    name: str
    type: str
    url: str
    format: str = "json"
    secret_env: "str | None" = None
    include_args: bool = False
    allow_private: bool = False


@dataclass(frozen=True)
class TenantConfig:
    id: str
    name: str
    policy_file: "str | None"
    gate_timeout_s: "float | None"
    levels: tuple
    channels: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _Cred:
    id: str
    tenant: str
    role: str
    digest: "str | None"
    jwt_sub: "str | None"
    servers: "tuple | None"


@dataclass(frozen=True)
class _JwtConfig:
    issuer: str
    audience: str
    algorithms: tuple
    key_file: str
    kind: str                      # pem | jwks
    leeway_s: float


def hash_token(token) -> str:
    if isinstance(token, str):
        token = token.encode("utf-8", "surrogatepass")
    if not isinstance(token, (bytes, bytearray)):
        raise TypeError("token must be str or bytes")
    return hashlib.sha256(bytes(token)).hexdigest()


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _show(v) -> str:
    s = repr(v)
    return s if len(s) <= 60 else s[:57] + "..."


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _check_servers(v, where: str, errs: list):
    if not isinstance(v, list) or not v or len(v) > MAX_SERVER_GLOBS:
        errs.append(f"{where}: must be a non-empty list of at most {MAX_SERVER_GLOBS} glob strings (omit it for 'all servers')")
        return None
    out = []
    for i, g in enumerate(v):
        if not isinstance(g, str) or not g or len(g) > MAX_GLOB or "\x00" in g:
            errs.append(f"{where}[{i}]: must be a non-empty string of at most {MAX_GLOB} characters without NUL")
            return None
        out.append(g)
    return tuple(out)


def _check_id(v, where: str, errs: list):
    if not isinstance(v, str) or not _ID_RE.fullmatch(v):
        errs.append(f"{where}: must match [A-Za-z0-9._@-]{{1,64}}, got {_show(v)}")
        return None
    return v


def _check_url(url, where: str, errs: list) -> bool:
    if not isinstance(url, str) or not url or len(url) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in url):
        errs.append(f"{where}: must be a URL string without spaces or control characters (<= 2048)")
        return False
    try:
        u = urllib.parse.urlsplit(url)
        host, _ = u.hostname, u.port
    except ValueError:
        errs.append(f"{where}: not a valid URL")
        return False
    if not host or u.username is not None or u.password is not None:
        errs.append(f"{where}: needs a host and must not carry credentials")
        return False
    if u.scheme == "https" or (u.scheme == "http" and host in _LOOPBACK):
        return True
    errs.append(f"{where}: must be https (http is accepted only for loopback hosts)")
    return False


def _check_tenant(tid: str, t: Any, errs: list):
    where = f"tenants.{tid}"
    if not isinstance(t, dict):
        errs.append(f"{where}: must be an object")
        return None
    n0 = len(errs)
    for k in t:
        if k not in _TENANT_KEYS:
            errs.append(f"{where}: unknown key {_show(k)}")
    name = t.get("name", tid)
    if not isinstance(name, str) or not name or len(name) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        errs.append(f"{where}.name: must be a printable string of at most 100 characters")
    pf = t.get("policy_file")
    if "policy_file" in t and (not isinstance(pf, str) or not pf.startswith("/") or len(pf) > 4096 or "\x00" in pf):
        errs.append(f"{where}.policy_file: must be an absolute path")
    gt = t.get("gate_timeout_s")
    if "gate_timeout_s" in t and (not _is_num(gt) or not 1 <= gt <= 86400):
        errs.append(f"{where}.gate_timeout_s: must be a number between 1 and 86400")
    channels: dict = {}
    raw_ch = t.get("channels", {})
    if not isinstance(raw_ch, dict) or len(raw_ch) > MAX_CHANNELS:
        errs.append(f"{where}.channels: must be an object with at most {MAX_CHANNELS} channels")
        raw_ch = {}
    for cname, c in raw_ch.items():
        cw = f"{where}.channels.{cname}"
        if not isinstance(cname, str) or not _ID_RE.fullmatch(cname):
            errs.append(f"{cw}: channel names must match [A-Za-z0-9._@-]{{1,64}}")
            continue
        if not isinstance(c, dict):
            errs.append(f"{cw}: must be an object")
            continue
        m0 = len(errs)
        for k in c:
            if k not in _CHANNEL_KEYS:
                errs.append(f"{cw}: unknown key {_show(k)}")
        if c.get("type") != "webhook":
            errs.append(f"{cw}.type: must be 'webhook'")
        _check_url(c.get("url"), f"{cw}.url", errs)
        fmt = c.get("format", "json")
        if fmt not in ("json", "slack"):
            errs.append(f"{cw}.format: must be 'json' or 'slack'")
        se = c.get("secret_env")
        if "secret_env" in c and (not isinstance(se, str) or not _ENV_NAME.fullmatch(se)):
            errs.append(f"{cw}.secret_env: must be an environment variable NAME")
        for flag in ("include_args", "allow_private"):
            if flag in c and not isinstance(c[flag], bool):
                errs.append(f"{cw}.{flag}: must be true or false")
        if len(errs) == m0:
            channels[cname] = Channel(cname, "webhook", c["url"], fmt, se, bool(c.get("include_args", False)), bool(c.get("allow_private", False)))
    levels: list = []
    esc = t.get("escalation", {})
    if not isinstance(esc, dict):
        errs.append(f"{where}.escalation: must be an object")
        esc = {}
    for k in esc:
        if k != "levels":
            errs.append(f"{where}.escalation: unknown key {_show(k)}")
    raw_levels = esc.get("levels", [])
    if not isinstance(raw_levels, list) or len(raw_levels) > MAX_LEVELS:
        errs.append(f"{where}.escalation.levels: must be a list of at most {MAX_LEVELS} levels")
        raw_levels = []
    last = 0.0
    for i, lv in enumerate(raw_levels):
        lw = f"{where}.escalation.levels[{i}]"
        if not isinstance(lv, dict):
            errs.append(f"{lw}: must be an object")
            continue
        for k in lv:
            if k not in ("after_s", "notify"):
                errs.append(f"{lw}: unknown key {_show(k)}")
        after, notify = lv.get("after_s"), lv.get("notify")
        if not _is_num(after) or not 0 < after <= 86400:
            errs.append(f"{lw}.after_s: must be a number between 0 (exclusive) and 86400")
        elif after <= last:
            errs.append(f"{lw}.after_s: levels must be strictly increasing")
        else:
            last = after
        if not isinstance(notify, list) or not notify or len(notify) > MAX_NOTIFY or not all(isinstance(x, str) for x in notify):
            errs.append(f"{lw}.notify: must be a non-empty list of channel names (<= {MAX_NOTIFY})")
        else:
            for ch in notify:
                if ch not in raw_ch:
                    errs.append(f"{lw}.notify: unknown channel {_show(ch)}")
            levels.append(Level(float(after) if _is_num(after) else 0.0, tuple(notify)))
    if len(errs) > n0:
        return None
    return TenantConfig(tid, name, pf, float(gt) if gt is not None else None, tuple(levels), channels)


def _check_cred(raw: Any, i: int, kind: str, tenants: dict, seen_ids: set, seen_digests: dict, seen_subs: dict,
                has_jwt: bool, errs: list):
    where = f"{kind}s[{i}]"
    if not isinstance(raw, dict):
        errs.append(f"{where}: must be an object")
        return None
    n0 = len(errs)
    allowed = _OPERATOR_KEYS if kind == "operator" else _AGENT_KEYS
    for k in raw:
        if k not in allowed:
            errs.append(f"{where}: unknown key {_show(k)}")
    rid = _check_id(raw.get("id"), f"{where}.id", errs)
    if rid is not None:
        where = f"{kind}s[{i}] ({rid})"
        if rid in seen_ids:
            errs.append(f"{where}: duplicate id (operators and agents share one id space)")
        seen_ids.add(rid)
    tenant = raw.get("tenant")
    if not isinstance(tenant, str) or tenant not in tenants:
        errs.append(f"{where}.tenant: unknown tenant {_show(tenant)}")
    role = "agent"
    if kind == "operator":
        role = raw.get("role")
        if not isinstance(role, str) or role not in ROLES:
            errs.append(f"{where}.role: must be one of {', '.join(ROLES)}")
    digest = raw.get("token_sha256")
    if "token_sha256" in raw:
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest.lower() if isinstance(digest, str) else ""):
            errs.append(f"{where}.token_sha256: must be 64 hex characters (the SHA-256 of the token)")
            digest = None
        else:
            digest = digest.lower()
            if digest in seen_digests:
                errs.append(f"{where}.token_sha256: same token digest as {seen_digests[digest]}")
            seen_digests[digest] = rid or where
    sub = raw.get("jwt_sub")
    if "jwt_sub" in raw:
        if not isinstance(sub, str) or not sub or len(sub) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in sub):
            errs.append(f"{where}.jwt_sub: must be a printable string of at most 256 characters")
            sub = None
        else:
            if not has_jwt:
                errs.append(f"{where}.jwt_sub: the file has no 'jwt' section")
            if sub in seen_subs:
                errs.append(f"{where}.jwt_sub: same subject as {seen_subs[sub]}")
            seen_subs[sub] = rid or where
    if kind == "operator" and "token_sha256" not in raw and "jwt_sub" not in raw:
        errs.append(f"{where}: needs token_sha256 and/or jwt_sub")
    if kind == "agent" and "token_sha256" not in raw:
        errs.append(f"{where}.token_sha256: required (agents authenticate with a static token)")
    servers = None
    if "servers" in raw:
        servers = _check_servers(raw["servers"], f"{where}.servers", errs)
    if len(errs) > n0 or rid is None:
        return None
    return _Cred(rid, tenant, role, digest, sub, servers)


def _check_jwt(j: Any, errs: list):
    if not isinstance(j, dict):
        errs.append("jwt: must be an object")
        return None
    n0 = len(errs)
    for k in j:
        if k not in _JWT_KEYS:
            errs.append(f"jwt: unknown key {_show(k)}")
    for k in ("issuer", "audience"):
        v = j.get(k)
        if not isinstance(v, str) or not v or len(v) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in v):
            errs.append(f"jwt.{k}: required, a non-empty string (matched exactly)")
    algs = j.get("algorithms", ["RS256", "ES256"])
    if not isinstance(algs, list) or not algs or len(algs) > len(JWT_ALGORITHMS):
        errs.append("jwt.algorithms: must be a non-empty list")
        algs = []
    for a in algs:
        if not isinstance(a, str) or a not in JWT_ALGORITHMS:
            errs.append(f"jwt.algorithms: {_show(a)} is not allowed (allowed: {', '.join(JWT_ALGORITHMS)}; 'none' and HS* never)")
    pk, jk = j.get("public_key_file"), j.get("jwks_file")
    if (pk is None) == (jk is None):
        errs.append("jwt: exactly one of public_key_file or jwks_file is required")
    path = pk if pk is not None else jk
    if path is not None and (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096 or "\x00" in path):
        errs.append("jwt.public_key_file/jwks_file: must be an absolute path")
    leeway = j.get("leeway_s", 0)
    if not _is_num(leeway) or not 0 <= leeway <= MAX_LEEWAY:
        errs.append(f"jwt.leeway_s: must be a number between 0 and {MAX_LEEWAY}")
    if len(errs) > n0:
        return None
    return _JwtConfig(j["issuer"], j["audience"], tuple(dict.fromkeys(algs)), path, "pem" if pk is not None else "jwks", float(leeway))


def _build(data: Any):
    """-> (tenants, operators, agents, jwt_cfg, errors)."""
    errs: list = []
    if not isinstance(data, dict):
        return {}, [], [], None, ["identity file must be a JSON object"]
    for k in data:
        if k not in _TOP_KEYS:
            errs.append(f"unknown top-level key {_show(k)}")
    ver = data.get("version")
    if "version" not in data or isinstance(ver, bool) or ver != VERSION:
        errs.append(f"version: must be {VERSION}, got {_show(ver)}")
    tenants: dict = {}
    raw_t = data.get("tenants")
    if not isinstance(raw_t, dict) or not raw_t:
        errs.append("tenants: required, a non-empty object")
        raw_t = {}
    if len(raw_t) > MAX_TENANTS:
        errs.append(f"tenants: at most {MAX_TENANTS}")
        raw_t = {}
    for tid, t in raw_t.items():
        if not isinstance(tid, str) or not _ID_RE.fullmatch(tid):
            errs.append(f"tenants: invalid tenant id {_show(tid)}")
            continue
        cfg = _check_tenant(tid, t, errs)
        if cfg is not None:
            tenants[tid] = cfg
    jwt_cfg = None
    has_jwt = "jwt" in data
    if has_jwt:
        jwt_cfg = _check_jwt(data["jwt"], errs)
    ops_raw, ag_raw = data.get("operators", []), data.get("agents", [])
    for name, v in (("operators", ops_raw), ("agents", ag_raw)):
        if not isinstance(v, list):
            errs.append(f"{name}: must be a list")
    if not isinstance(ops_raw, list) or not isinstance(ag_raw, list):
        return tenants, [], [], jwt_cfg, errs
    if len(ops_raw) + len(ag_raw) > MAX_IDENTITIES:
        errs.append(f"at most {MAX_IDENTITIES} identities (got {len(ops_raw) + len(ag_raw)})")
        return tenants, [], [], jwt_cfg, errs
    seen_ids: set = set()
    seen_digests: dict = {}
    seen_subs: dict = {}
    # a tenant that failed validation must not produce a second, misleading 'unknown tenant' error
    known = {tid: True for tid in raw_t if isinstance(tid, str)}
    ops = [_check_cred(r, i, "operator", known, seen_ids, seen_digests, seen_subs, has_jwt, errs) for i, r in enumerate(ops_raw)]
    ags = [_check_cred(r, i, "agent", known, seen_ids, seen_digests, seen_subs, has_jwt, errs) for i, r in enumerate(ag_raw)]
    return tenants, [o for o in ops if o], [a for a in ags if a], jwt_cfg, errs


# ---------------------------------------------------------------------------
# throttle
# ---------------------------------------------------------------------------

class _Throttle:
    """5 failures per remote in 60 s => that remote is refused for 60 s.  Bounded memory (LRU, 10k remotes)."""

    def __init__(self, clock):
        self._clock = clock
        self._lock = threading.Lock()
        self._m: "OrderedDict[str, list]" = OrderedDict()           # key -> [deque(timestamps), blocked_until]

    def blocked(self, key: str) -> bool:
        with self._lock:
            e = self._m.get(key)
            return bool(e) and e[1] > self._clock()

    def failure(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            e = self._m.get(key)
            if e is None:
                e = self._m[key] = [deque(maxlen=THROTTLE_FAILURES), 0.0]
            self._m.move_to_end(key)
            if e[1] > now:
                return                                              # already blocked: do not extend
            ts = e[0]
            while ts and ts[0] <= now - THROTTLE_WINDOW_S:
                ts.popleft()
            ts.append(now)
            if len(ts) >= THROTTLE_FAILURES:
                e[1] = now + THROTTLE_BLOCK_S
                ts.clear()
            while len(self._m) > THROTTLE_MAX_REMOTES:
                self._m.popitem(last=False)

    def size(self) -> int:
        with self._lock:
            return len(self._m)


def _remote_key(remote: Any) -> str:
    if isinstance(remote, (tuple, list)) and remote:
        remote = remote[0]
    if remote is None:
        return "-"
    try:
        return str(remote)[:100]
    except Exception:
        return "-"


# ---------------------------------------------------------------------------
# JWT keys
# ---------------------------------------------------------------------------

def _key_ok(key: Any, alg: str) -> bool:
    if _jwt is None:
        return False
    if alg.startswith(("RS", "PS")):
        return isinstance(key, _rsa.RSAPublicKey) and key.key_size >= MIN_RSA_BITS
    if alg in _EC_CURVES:
        return isinstance(key, _ec.EllipticCurvePublicKey) and key.curve.name == _EC_CURVES[alg]
    return False


class _KeySource:
    """PEM public key or JWKS file; re-read at every use, re-parsed only when the content hash changes."""

    def __init__(self, path: str, kind: str):
        self.path, self.kind = path, kind
        self._lock = threading.Lock()
        self._sig: "str | None" = None
        self._keys: "dict | None" = None
        self.problem = ""

    def _load(self, raw: bytes):
        keys: dict = {}
        if self.kind == "pem":
            k = _ser.load_pem_public_key(raw)
            if isinstance(k, _rsa.RSAPublicKey) and k.key_size >= MIN_RSA_BITS or isinstance(k, _ec.EllipticCurvePublicKey):
                keys[None] = (k, None)
            else:
                raise ValueError("key must be RSA (>= 2048 bits) or EC")
            return keys
        doc = json.loads(raw.decode("utf-8"))
        lst = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(lst, list) or len(lst) > MAX_JWKS_KEYS:
            raise ValueError("JWKS must be an object with a 'keys' list")
        dup = set()
        for jwk in lst:
            if not isinstance(jwk, dict) or any(p in jwk for p in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
                continue                                           # private / symmetric material is never accepted
            kid, kty = jwk.get("kid"), jwk.get("kty")
            if not isinstance(kid, str) or not kid or jwk.get("use", "sig") != "sig":
                continue
            try:
                if kty == "RSA":
                    key = _jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
                elif kty == "EC":
                    key = _jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
                else:
                    continue
            except Exception:
                continue
            if isinstance(key, _rsa.RSAPublicKey) and key.key_size < MIN_RSA_BITS or not isinstance(key, (_rsa.RSAPublicKey, _ec.EllipticCurvePublicKey)):
                continue
            if kid in keys:
                dup.add(kid)
            keys[kid] = (key, jwk.get("alg") if isinstance(jwk.get("alg"), str) else None)
        for kid in dup:
            keys.pop(kid, None)                                    # ambiguous kid: refuse both
        if not keys:
            raise ValueError("no usable public RSA/EC key in the JWKS")
        return keys

    def get(self, kid: "str | None"):
        """-> ("ok", key, key_alg) | ("unavailable", None, None) | ("unknown_kid", None, None)."""
        with self._lock:
            try:
                with open(self.path, "rb") as fh:
                    raw = fh.read(MAX_KEY_FILE + 1)
                if len(raw) > MAX_KEY_FILE:
                    raise ValueError("key file too large")
                sig = hashlib.sha256(raw).hexdigest()
            except (OSError, ValueError) as e:
                self._sig, self._keys, self.problem = None, None, f"cannot read key file: {type(e).__name__}"
                return "unavailable", None, None
            if sig != self._sig:
                self._sig = sig
                try:
                    self._keys, self.problem = self._load(raw), ""
                except Exception as e:                             # noqa: BLE001 - corrupt key material: JWT auth is unavailable
                    self._keys, self.problem = None, f"unusable key file: {type(e).__name__}"
                    log.warning("identity: JWT key file %s is unusable (%s)", self.path, type(e).__name__)
            keys = self._keys
        if keys is None:
            return "unavailable", None, None
        if self.kind == "pem":
            k = keys[None]
            return "ok", k[0], k[1]
        if kid is None:
            if len(keys) == 1:
                k = next(iter(keys.values()))
                return "ok", k[0], k[1]
            return "unknown_kid", None, None
        k = keys.get(kid)
        return ("ok", k[0], k[1]) if k else ("unknown_kid", None, None)


def _looks_like_jwt(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3 and all(p for p in parts) and s.isascii()


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------

class IdentityStore:
    def __init__(self, data: Any, *, env: Mapping = os.environ, clock=time.time, _legacy_digest: "str | None" = None):
        self._clock = clock
        self._env = env
        self._legacy = _legacy_digest is not None
        self._throttle = _Throttle(clock)
        if self._legacy:
            self._tenants = {"default": TenantConfig("default", "default", None, None, (), {})}
            self._ops = [_Cred("operator", "default", "admin", _legacy_digest, None, None)]
            self._agents = [_Cred("agent", "default", "agent", _legacy_digest, None, None)]
            self._jwt_cfg = None
            self._data = {"legacy": True, "token_sha256_prefix": _legacy_digest[:8]}
            self._digest = hashlib.sha256(("legacy:" + _legacy_digest).encode()).hexdigest()[:16]
            self._keys = None
            self._by_sub = {}
            return
        tenants, ops, ags, jwt_cfg, errs = _build(data)
        if errs:
            raise IdentityError(errs)
        self._tenants = tenants
        self._ops, self._agents, self._jwt_cfg = ops, ags, jwt_cfg
        self._data = copy.deepcopy(data)
        blob = json.dumps(self._data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        self._digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
        self._by_sub = {o.jwt_sub: o for o in ops if o.jwt_sub}
        self._keys = _KeySource(jwt_cfg.key_file, jwt_cfg.kind) if jwt_cfg and _jwt is not None else None

    # ---- construction ---------------------------------------------------------
    @classmethod
    def load(cls, path, *, env=os.environ, clock=time.time) -> "IdentityStore":
        return cls(_read_json(path), env=env, clock=clock)

    @classmethod
    def legacy(cls, token: str, *, clock=time.time) -> "IdentityStore":
        """SENTINEL_WS_TOKEN mode: tenant 'default', operator 'operator' (admin, via 'legacy'), agent 'agent'; ONE token for both."""
        if not isinstance(token, str) or not token:
            raise IdentityError("legacy token must be a non-empty string")
        return cls(None, clock=clock, _legacy_digest=hash_token(token))

    # ---- queries ----------------------------------------------------------------
    def tenant(self, tenant_id) -> "TenantConfig | None":
        return self._tenants.get(tenant_id) if isinstance(tenant_id, str) else None

    def digest(self) -> str:
        return self._digest

    @property
    def is_legacy(self) -> bool:
        return self._legacy

    @property
    def tenants(self) -> dict:
        return dict(self._tenants)

    def jwt_available(self) -> bool:
        if self._keys is None:
            return False
        return self._keys.get(None)[0] != "unavailable"

    def lint(self) -> list:
        w: list = []
        if self._legacy:
            return ["legacy mode: one shared token, tenant 'default', everyone is admin"]
        for tid in self._tenants:
            members = [o for o in self._ops if o.tenant == tid]
            if not members:
                w.append(f"tenant {tid}: has no operators (nobody can see or decide its calls)")
            elif not any(o.role in ("approver", "admin") for o in members):
                w.append(f"tenant {tid}: has no approver or admin (nobody can decide its calls)")
            if not any(a.tenant == tid for a in self._agents):
                w.append(f"tenant {tid}: has no agents")
            cfg = self._tenants[tid]
            if cfg.policy_file and not os.path.exists(cfg.policy_file):
                w.append(f"tenant {tid}: policy_file {cfg.policy_file} does not exist")
            for ch in cfg.channels.values():
                if ch.secret_env and not self._env.get(ch.secret_env):
                    w.append(f"tenant {tid}: channel {ch.name}: environment variable {ch.secret_env} is not set (notifications unsigned)")
            if cfg.levels and cfg.gate_timeout_s is not None and cfg.levels[-1].after_s >= cfg.gate_timeout_s:
                w.append(f"tenant {tid}: the last escalation level ({cfg.levels[-1].after_s:g}s) is not before gate_timeout_s")
        for a in self._agents:
            if a.servers is None:
                w.append(f"agent {a.id}: no servers allowlist (may declare any server)")
        for o in self._ops:
            if o.role == "admin" and o.servers is not None:
                w.append(f"operator {o.id}: admin with a servers allowlist (applies to decide/rules only)")
        if self._jwt_cfg is not None:
            if not any(o.jwt_sub for o in self._ops):
                w.append("jwt section configured but no operator has a jwt_sub")
            if not os.path.exists(self._jwt_cfg.key_file):
                w.append(f"jwt key file {self._jwt_cfg.key_file} does not exist (JWT login unavailable)")
        return w

    # ---- authentication -----------------------------------------------------------
    def authenticate(self, kind, credential, *, remote=None) -> "Principal | None":
        return self.authenticate_ex(kind, credential, remote=remote)[0]

    def authenticate_ex(self, kind, credential, remote=None) -> tuple:
        """-> (Principal | None, reason) with reason in ok|unauthorized|throttled|expired|bad_signature|bad_claims|unsupported.
        Never raises; never logs or returns the credential."""
        try:
            if kind not in ("operator", "agent"):
                return None, "unsupported"
            key = _remote_key(remote)
            if self._throttle.blocked(key):
                return None, "throttled"
            p, reason = self._check(kind, credential)
            if p is not None and self._tenants.get(p.tenant) is None:
                p, reason = None, "unauthorized"                    # defence in depth: a principal always belongs to a known tenant
            if p is None:
                self._throttle.failure(key)
                return None, reason
            return p, "ok"
        except Exception:                                           # noqa: BLE001 - fail closed
            return None, "unauthorized"

    def _check(self, kind: str, credential: Any) -> tuple:
        if not isinstance(credential, str) or not credential or len(credential) > MAX_CREDENTIAL:
            return None, "unauthorized"
        digest = hash_token(credential)
        pool = self._ops if kind == "operator" else self._agents
        hit = None
        for rec in pool:                                            # every candidate is compared: no early exit
            if rec.digest is not None and hmac.compare_digest(rec.digest, digest):
                hit = rec
        if hit is not None:
            return self._principal(kind, hit, "legacy" if self._legacy else "token"), "ok"
        if kind == "operator" and _looks_like_jwt(credential):
            return self._check_jwt(credential)
        return None, "unauthorized"

    @staticmethod
    def _principal(kind: str, rec: _Cred, via: str) -> Principal:
        return Principal(kind, rec.id, rec.tenant, rec.role, rec.servers, via)

    def _check_jwt(self, token: str) -> tuple:
        cfg = self._jwt_cfg
        if cfg is None or self._keys is None or _jwt is None:
            return None, "unsupported"
        try:
            header = _jwt.get_unverified_header(token)
        except Exception:                                           # noqa: BLE001
            return None, "unauthorized"
        alg = header.get("alg") if isinstance(header, dict) else None
        if not isinstance(alg, str) or alg not in cfg.algorithms:    # BEFORE any key is touched (none, HS*, anything else)
            return None, "unsupported"
        kid = header.get("kid")
        status, key, key_alg = self._keys.get(kid if isinstance(kid, str) else None)
        if status == "unavailable":
            return None, "unsupported"
        if status != "ok" or not _key_ok(key, alg) or (key_alg is not None and key_alg != alg):
            return None, "bad_signature"
        try:
            claims = _jwt.decode(token, key, algorithms=[alg], issuer=cfg.issuer, audience=cfg.audience,
                                 options={"require": ["exp", "iss", "aud"], "verify_signature": True, "verify_exp": False,
                                          "verify_nbf": False, "verify_iat": False, "verify_iss": True, "verify_aud": True})
        except _jwt.InvalidSignatureError:
            return None, "bad_signature"
        except (_jwt.InvalidIssuerError, _jwt.InvalidAudienceError, _jwt.MissingRequiredClaimError):
            return None, "bad_claims"
        except _jwt.InvalidKeyError:
            return None, "bad_signature"
        except _jwt.InvalidAlgorithmError:
            return None, "unsupported"
        except _jwt.PyJWTError:
            return None, "unauthorized"
        now, leeway = float(self._clock()), cfg.leeway_s
        exp = claims.get("exp")
        if not _is_num(exp):
            return None, "bad_claims"
        if exp <= now - leeway:
            return None, "expired"
        nbf = claims.get("nbf")
        if nbf is not None and (not _is_num(nbf) or nbf > now + leeway):
            return None, "bad_claims"
        iat = claims.get("iat")
        if iat is not None and (not _is_num(iat) or iat > now + leeway):
            return None, "bad_claims"
        sub = claims.get("sub")
        rec = self._by_sub.get(sub) if isinstance(sub, str) else None
        if rec is None:
            return None, "unauthorized"
        return self._principal("operator", rec, "jwt"), "ok"


# ---------------------------------------------------------------------------
# permissions
# ---------------------------------------------------------------------------

def can(principal, action, *, server=None, tenant=None) -> bool:
    """view | decide | rules.  Roles: viewer < approver < admin.  The servers allowlist applies to decide/rules (fail closed when
    the server is unknown).  With `tenant`, the principal must belong to that tenant.  Agents can do none of these."""
    if not isinstance(principal, Principal) or principal.kind != "operator" or action not in ACTIONS:
        return False
    if tenant is not None and principal.tenant != tenant:
        return False
    rank = _ROLE_RANK.get(principal.role, 0)
    need = {"view": 1, "decide": 2, "rules": 3}[action]
    if rank < need:
        return False
    if action != "view" and principal.servers is not None:
        if not isinstance(server, str) or not any(fnmatchcase(server, g) for g in principal.servers):
            return False
    return True


# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------

def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_const(name):
    raise ValueError(f"non-finite number {name}")


def parse_identity_bytes(raw: bytes, label: str = "identity file") -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dups, parse_constant=_no_const)
    except (ValueError, RecursionError) as e:
        raise IdentityError(f"{label}: cannot parse as JSON ({type(e).__name__}: {e})") from None


def read_identity_bytes(path) -> bytes:
    """Read a regular file of at most MAX_FILE_BYTES (str / PathLike only: an int would be a file descriptor)."""
    if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):
        raise IdentityError("identity file path must be a str or PathLike")
    p = os.fspath(path)
    if not isinstance(p, str) or not p or "\x00" in p:
        raise IdentityError("invalid identity file path")
    try:
        if not stat.S_ISREG(os.stat(p).st_mode):
            raise IdentityError(f"{p}: not a regular file")
        with open(p, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except IdentityError:
        raise
    except OSError as e:
        raise IdentityError(f"cannot read {p}: {e}") from None
    if len(raw) > MAX_FILE_BYTES:
        raise IdentityError(f"{p}: larger than {MAX_FILE_BYTES} bytes")
    return raw


def _read_json(path) -> Any:
    return parse_identity_bytes(read_identity_bytes(path), str(path))


_cache: dict = {}
_cache_lock = threading.Lock()


def load_identity(env=None) -> tuple:
    """-> (IdentityStore, "") or (None, reason).  SENTINEL_IDENTITY_FILE (cached by CONTENT hash: a same-size edit reloads and a
    cached store keeps its throttle state) else the legacy store for SENTINEL_WS_TOKEN.  If the file is configured but unusable
    the result is (None, reason): the caller must refuse everyone, NOT fall back to legacy.  Never raises."""
    try:
        env = os.environ if env is None else env
        path = env.get("SENTINEL_IDENTITY_FILE")
        if path:
            try:
                raw = read_identity_bytes(path)
            except IdentityError as e:
                return None, e.messages[0]
            sig = hashlib.sha256(raw).hexdigest()
            key = ("file", str(path))
            with _cache_lock:
                hit = _cache.get(key)
                if hit is not None and hit[0] == sig:
                    return hit[1], hit[2]
            try:
                store, reason = IdentityStore(parse_identity_bytes(raw, str(path)), env=env), ""
            except IdentityError as e:
                store, reason = None, f"identity file {path} rejected ({len(e.messages)} error(s); first: {e.messages[0]})"
            with _cache_lock:
                if len(_cache) > 32:
                    _cache.clear()
                _cache[key] = (sig, store, reason)
            return store, reason
        token = env.get("SENTINEL_WS_TOKEN")
        if isinstance(token, str) and token:
            sig = hash_token(token)
            key = ("legacy",)
            with _cache_lock:
                hit = _cache.get(key)
                if hit is not None and hit[0] == sig:
                    return hit[1], ""
                store = IdentityStore.legacy(token)
                _cache[key] = (sig, store, "")
            return store, ""
        return None, "no identity file or legacy token configured"
    except Exception as e:                                          # noqa: BLE001
        return None, f"identity could not be loaded ({type(e).__name__})"


def _reset_cache() -> None:
    """Test hook."""
    with _cache_lock:
        _cache.clear()
