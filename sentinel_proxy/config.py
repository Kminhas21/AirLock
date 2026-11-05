"""Pure config loading / validation and routing logic (no I/O except reading the file)."""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

DEFAULT_BACKEND = "ws://127.0.0.1:8080/proxy/ws"
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_AUTO_RE = re.compile(r"^([A-Za-z0-9._-]{1,40}):(\*|[^:*\s][^:\s]*)$")
_TOP_KEYS = {"session_id", "backend", "servers", "auto_approve"}
_SERVER_KEYS = {"command", "args", "env", "cwd", "prefix", "trust_read_only_hint"}


class ConfigError(Exception):
    """Invalid configuration; message is user-facing (one problem per line)."""


@dataclass(frozen=True)
class ServerConfig:
    name: str
    command: str
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    prefix: str = ""
    trust_read_only_hint: bool = False


@dataclass(frozen=True)
class ProxyConfig:
    session_id: str
    backend: str
    servers: dict[str, ServerConfig]
    auto_approve: tuple[str, ...] = ()


def valid_session_id(value: Any) -> bool:
    return isinstance(value, str) and _ID_RE.fullmatch(value) is not None


def new_session_id() -> str:
    return "proxy-" + uuid.uuid4().hex[:6]


def valid_backend_url(value: Any) -> bool:
    return isinstance(value, str) and re.match(r"^wss?://[^\s/?#]+(/[^\s?#]*)?(\?[^\s#]*)?$", value) is not None


def with_token(url: str, token: str | None) -> str:
    """Append ?token= (url-quoted) when a token is set and the URL has none."""
    if not token:
        return url
    from urllib.parse import quote

    sep = "&" if "?" in url else "?"
    return f"{url}{sep}token={quote(token, safe='')}"


def strip_query(url: str) -> str:
    """URL without its query string (safe to log; the query may hold the token)."""
    return url.split("?", 1)[0]


def parse_config(raw: Any, *, session_id_override: str | None = None, backend_override: str | None = None) -> ProxyConfig:
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise ConfigError("config: top level must be a JSON object")
    for k in sorted(set(raw) - _TOP_KEYS):
        errors.append(f"config: unknown key {k!r}")

    sid = session_id_override if session_id_override is not None else raw.get("session_id")
    if sid is None:
        sid = new_session_id()
    elif not valid_session_id(sid):
        errors.append(f"session_id: {sid!r} must match ^[A-Za-z0-9._-]{{1,40}}$")

    backend = backend_override if backend_override is not None else raw.get("backend", DEFAULT_BACKEND)
    if not valid_backend_url(backend):
        errors.append("backend: must be a ws:// or wss:// URL")

    servers: dict[str, ServerConfig] = {}
    raw_servers = raw.get("servers")
    if not isinstance(raw_servers, dict) or not raw_servers:
        errors.append("servers: must be a non-empty object mapping name -> server config")
    else:
        for name, s in raw_servers.items():
            if not _ID_RE.fullmatch(name):
                errors.append(f"servers.{name}: server name must match ^[A-Za-z0-9._-]{{1,40}}$")
                continue
            sc = _parse_server(name, s, errors)
            if sc is not None:
                servers[name] = sc

    auto: list[str] = []
    raw_auto = raw.get("auto_approve", [])
    if not isinstance(raw_auto, list):
        errors.append("auto_approve: must be a list of 'server:tool' / 'server:*' strings")
    else:
        for e in raw_auto:
            m = _AUTO_RE.fullmatch(e) if isinstance(e, str) else None
            if m is None:
                errors.append(f"auto_approve: {e!r} must look like 'server:tool' or 'server:*'")
            elif isinstance(raw_servers, dict) and m.group(1) not in raw_servers:
                errors.append(f"auto_approve: {e!r} refers to unknown server {m.group(1)!r}")
            else:
                auto.append(e)

    if errors:
        raise ConfigError("\n".join(errors))
    return ProxyConfig(session_id=sid, backend=backend, servers=servers, auto_approve=tuple(auto))


def _parse_server(name: str, s: Any, errors: list[str]) -> ServerConfig | None:
    where = f"servers.{name}"
    if not isinstance(s, dict):
        errors.append(f"{where}: must be an object")
        return None
    n0 = len(errors)
    for k in sorted(set(s) - _SERVER_KEYS):
        errors.append(f"{where}: unknown key {k!r}")
    command = s.get("command")
    if not isinstance(command, str) or not command.strip():
        errors.append(f"{where}.command: required non-empty string")
    args = s.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        errors.append(f"{where}.args: must be a list of strings")
    env = s.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        errors.append(f"{where}.env: must be an object of string -> string")
    cwd = s.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd):
        errors.append(f"{where}.cwd: must be a non-empty string")
    prefix = s.get("prefix", "")
    if prefix is None:
        prefix = ""
    if not isinstance(prefix, str) or (prefix and not _PREFIX_RE.fullmatch(prefix)):
        errors.append(f"{where}.prefix: must match ^[A-Za-z0-9._-]{{1,40}}$")
    trust = s.get("trust_read_only_hint", False)
    if not isinstance(trust, bool):
        errors.append(f"{where}.trust_read_only_hint: must be true or false")
    if len(errors) > n0:
        return None
    return ServerConfig(name, command, tuple(args), dict(env), cwd, prefix, trust)


def load_config_file(path: str, **overrides: Any) -> ProxyConfig:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config {path!r}: {e.strerror or e}") from None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"config {path!r} is not valid JSON: {e}") from None
    return parse_config(raw, **overrides)


# ---------------------------------------------------------------- routing


def is_auto_listed(auto_approve: tuple[str, ...] | list[str], server: str, tool: str) -> bool:
    """Exact 'server:tool' or 'server:*' match on the ORIGINAL tool name."""
    return f"{server}:{tool}" in auto_approve or f"{server}:*" in auto_approve


def is_auto(cfg: ProxyConfig, server: str, tool: str, read_only_hint: bool | None) -> bool:
    if is_auto_listed(cfg.auto_approve, server, tool):
        return True
    sc = cfg.servers.get(server)
    return bool(sc is not None and sc.trust_read_only_hint and read_only_hint is True)


def exposed_name(prefix: str, tool: str) -> str:
    return f"{prefix}{tool}"


def build_name_map(tools_by_server: dict[str, tuple[str, list[str]]]) -> dict[str, tuple[str, str]]:
    """{server: (prefix, [tool names])} -> {exposed: (server, original)}. Collisions raise ConfigError."""
    out: dict[str, tuple[str, str]] = {}
    for server, (prefix, names) in tools_by_server.items():
        for t in names:
            ex = exposed_name(prefix, t)
            if ex in out:
                other = out[ex][0]
                raise ConfigError(
                    f"tool name collision: {ex!r} is exposed by both server {other!r} and server {server!r} "
                    "(set a distinct \"prefix\" on one of them)"
                )
            out[ex] = (server, t)
    return out


_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def summarize(text: str, limit: int = 300) -> str:
    return _CTRL.sub(" ", text).strip()[:limit]


def gate_timeout_s() -> float:
    try:
        return float(os.environ.get("SENTINEL_GATE_TIMEOUT_S", "300")) + 30.0
    except ValueError:
        return 330.0
