"""Webhook notifier for pending approvals (ticket ID2).

Channel shape (tenant config ``channels``, fixed contract):
  {"type": "webhook", "url": "https://...", "format": "json"|"slack", "secret_env": "ENVVAR"|null,
   "include_args": false, "allow_private": false, "allow_http_loopback": false}

Security properties
  * https only; http only to 127.0.0.1 / ::1 / localhost AND ``allow_http_loopback`` (tests).  No userinfo, no fragment.
  * SSRF: an IP literal in private / loopback / link-local / multicast / reserved / non-global ranges is refused at validation;
    a hostname is resolved at SEND time (``socket.getaddrinfo``) and refused if ANY answer is non-global, unless
    ``allow_private``.
  * DNS pinning (rebinding): the name is resolved exactly once per attempt, the answers are validated, and the request is sent
    to the FIRST validated IP: the URL host is replaced by that IP (so httpx/httpcore never resolve again) while the ``Host``
    header and the TLS SNI / certificate-verification name (httpcore's ``sni_hostname`` request extension) stay the original
    hostname.  Certificates are therefore verified against the hostname, and the connection cannot be redirected to another IP
    by a second DNS answer.  ``trust_env`` is off (no proxy env vars: a proxy would re-resolve the name).
  * redirects are never followed (a 3xx is a failure), 5 s timeout per attempt, at most 4 KB of a response is read, bodies
    are never logged, only the channel NAME is logged (never the URL, query, userinfo or secret).
  * signing: with ``secret_env`` set the body is signed (``X-Sentinel-Signature: sha256=<hmac-sha256 hex of the body>``,
    ``X-Sentinel-Timestamp``); when the variable is missing or empty the channel is unavailable and nothing is sent.
    The timestamp is also inside the signed JSON body (``timestamp``), so it can be checked for replay.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

import safe_text

log = logging.getLogger("sentinel.notify")
# httpx logs every request line (the FULL url, query included) at INFO and httpcore logs hosts at DEBUG: keep both quiet so
# a webhook url (which often carries a token in its path/query) never reaches a log.
for _n in ("httpx", "httpcore"):
    logging.getLogger(_n).setLevel(logging.WARNING)

MAX_URL = 2000
MAX_READ = 4096
ARGS_CAP = 300
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$ (letters, digits, . _ -)")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
_KEYS = {"type", "url", "format", "secret_env", "include_args", "allow_private", "allow_http_loopback"}
_FORMATS = ("json", "slack")


@dataclass(frozen=True)
class Channel:
    name: str
    type: str
    url: str
    format: str
    secret_env: "str | None" = None
    include_args: bool = False
    allow_private: bool = False
    allow_http_loopback: bool = False


@dataclass(frozen=True)
class NotifyResult:
    ok: bool
    status: "int | None"
    reason: str
    attempts: int


def _raise(messages):
    e = ValueError("; ".join(messages))
    e.messages = list(messages)
    raise e


def _blocked_ip(ip) -> bool:
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return (not ip.is_global) or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_unspecified


def _loopback_ip(ip) -> bool:
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def validate_channel(name, obj) -> Channel:
    """Strict parse of one channel config; raises ValueError carrying ALL messages (``.messages``)."""
    errors: list[str] = []
    if not isinstance(name, str) or not _NAME_RE.match(name):
        errors.append("channel name must match ^[A-Za-z0-9._-]{1,40}$ (letters, digits, . _ -)")
    if not isinstance(obj, dict):
        _raise(errors + ["channel must be an object"])
    where = f"channel {name!r}" if isinstance(name, str) else "channel"
    extra = sorted(str(k) for k in obj if k not in _KEYS)
    if extra:
        errors.append(f"{where}: unknown keys {extra}")
    if obj.get("type") != "webhook":
        errors.append(f"{where}.type: must be 'webhook'")
    fmt = obj.get("format")
    if fmt not in _FORMATS:
        errors.append(f"{where}.format: must be one of {list(_FORMATS)}")
    secret_env = obj.get("secret_env")
    if secret_env is not None and not (isinstance(secret_env, str) and _ENV_RE.match(secret_env)):
        errors.append(f"{where}.secret_env: must be null or an environment variable name")
    flags = {}
    for k in ("include_args", "allow_private", "allow_http_loopback"):
        v = obj.get(k, False)
        if not isinstance(v, bool):
            errors.append(f"{where}.{k}: must be true or false")
        flags[k] = v is True
    url = obj.get("url")
    if not isinstance(url, str) or not url:
        errors.append(f"{where}.url: required string")
    else:
        errors.extend(f"{where}.url: {m}" for m in _url_problems(url, flags["allow_private"], flags["allow_http_loopback"]))
    if errors:
        _raise(errors)
    return Channel(name, "webhook", url, fmt, secret_env, flags["include_args"], flags["allow_private"], flags["allow_http_loopback"])


def _url_problems(url: str, allow_private: bool, allow_loop: bool) -> "list[str]":
    if len(url) > MAX_URL:
        return [f"longer than {MAX_URL} characters"]
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        return ["must not contain spaces or control characters"]
    try:
        sp = urlsplit(url)
        host = sp.hostname
        _ = sp.port
    except ValueError:
        return ["not a valid URL"]
    out: list[str] = []
    if sp.scheme not in ("https", "http"):
        return ["scheme must be https"]
    if sp.username is not None or sp.password is not None or "@" in sp.netloc:
        out.append("must not contain userinfo (user:password@)")
    if sp.fragment or "#" in url:
        out.append("must not contain a fragment")
    if not host:
        return out + ["host is missing"]
    if sp.scheme == "http":
        if host not in _LOOPBACK_HOSTS:
            out.append("http is only allowed for 127.0.0.1, ::1 or localhost (use https)")
        elif not allow_loop:
            out.append("http to loopback needs allow_http_loopback: true")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and _blocked_ip(ip):
        loopback_ok = sp.scheme == "http" and allow_loop and _loopback_ip(ip)
        if not (allow_private or loopback_ok):
            out.append("destination is a private/loopback/link-local/multicast address (allow_private: true to permit)")
    return out


# ---- message building -------------------------------------------------------------------------------------------------

def _slack_escape(s: str) -> str:
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "¦")
    return s.replace("`", "'")


def _event_fields(event: dict) -> dict:
    c = safe_text.clean_field
    try:
        age = int(max(float(event.get("age_s") or 0), 0))
    except (TypeError, ValueError, OverflowError):
        age = 0
    try:
        level = int(event.get("level") or 0)
    except (TypeError, ValueError):
        level = 0
    return {
        "tenant": c(event.get("tenant"), safe_text.PARTY),
        "agent_id": c(event.get("agent_id"), safe_text.PARTY),
        "server": c(event.get("server"), safe_text.PARTY),
        "tool": c(event.get("tool"), safe_text.TOOL),
        "call_id": c(event.get("call_id"), safe_text.ID),
        "age_s": age,
        "level": level,
        "link": c(event.get("link"), 300),
    }


def build_message(channel: Channel, event: dict, *, now: "float | None" = None, env=None) -> "tuple[bytes, dict]":
    """Return ``(body_bytes, headers)``.  Does not read the secret value unless ``channel.secret_env`` is set; raises
    ``LookupError`` when it is set but the variable is missing/empty (callers treat that as 'secret_unavailable')."""
    f = _event_fields(event)
    ts = int(time.time() if now is None else now)
    args = None
    if channel.include_args and event.get("args_preview") is not None:
        args = safe_text.clean_field(event.get("args_preview"), ARGS_CAP)
    if channel.format == "slack":
        text = (
            f":warning: Approval pending (escalation level {f['level']}): `{_slack_escape(f['tool'])}` from agent "
            f"`{_slack_escape(f['agent_id'])}` via `{_slack_escape(f['server'])}` (tenant `{_slack_escape(f['tenant'])}`), "
            f"waiting {f['age_s']}s, call `{_slack_escape(f['call_id'])}`"
        )
        if args is not None:
            text += f", args `{_slack_escape(args)}`"
        if f["link"]:
            text += f" - {_slack_escape(f['link'])}"
        payload = {"text": text}
    else:
        payload = {"event": "sentinel.approval_pending", "version": 1, "timestamp": ts, **f}
        if args is not None:
            payload["args_preview"] = args
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    headers = {"Content-Type": "application/json", "User-Agent": "sentinel-notify/1"}
    if channel.secret_env:
        secret = (env if env is not None else os.environ).get(channel.secret_env)
        if not secret:
            raise LookupError("secret_unavailable")
        sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-Sentinel-Signature"] = "sha256=" + sig
        headers["X-Sentinel-Timestamp"] = str(ts)
    return body, headers


# ---- sending ----------------------------------------------------------------------------------------------------------

class _Fail(Exception):
    def __init__(self, reason, status=None, retry=False):
        self.reason, self.status, self.retry = reason, status, retry


class _Breaker:
    __slots__ = ("failures", "opened_at", "probing")

    def __init__(self):
        self.failures = 0
        self.opened_at = None
        self.probing = False


class Notifier:
    def __init__(self, *, clock=time.monotonic, sleep=asyncio.sleep, timeout_s: float = 5.0, max_inflight: int = 8,
                 busy_wait_s: float = 1.0, backoffs=(0.2, 0.6), failure_threshold: int = 5, open_s: float = 60.0, env=None):
        self._clock, self._sleep = clock, sleep
        self._timeout = timeout_s
        self._backoffs = tuple(backoffs)
        self._threshold, self._open_s = failure_threshold, open_s
        self._busy_wait = busy_wait_s
        self._sem = asyncio.Semaphore(max_inflight)
        self._env = env
        self._breakers: dict[str, _Breaker] = {}

    # circuit breaker ----------------------------------------------------------------------------------------------
    def _allow(self, name: str) -> bool:
        b = self._breakers.get(name)
        if b is None or b.opened_at is None:
            return True
        if self._clock() - b.opened_at < self._open_s:
            return False
        if b.probing:                       # half-open: exactly one probe at a time
            return False
        b.probing = True
        return True

    def _record(self, name: str, ok: bool) -> None:
        b = self._breakers.setdefault(name, _Breaker())
        b.probing = False
        if ok:
            b.failures, b.opened_at = 0, None
            return
        b.failures += 1
        if b.opened_at is not None or b.failures >= self._threshold:
            b.opened_at = self._clock()     # (re)open

    def circuit_state(self, name: str) -> str:
        b = self._breakers.get(name)
        if b is None or b.opened_at is None:
            return "closed"
        return "open" if self._clock() - b.opened_at < self._open_s else "half_open"

    # public -------------------------------------------------------------------------------------------------------
    async def send(self, channel: Channel, event: dict) -> NotifyResult:
        """Deliver one notification.  Never raises (except cancellation)."""
        try:
            return await self._send(channel, event)
        except Exception as e:                                           # pragma: no cover - defensive
            log.warning("notify channel=%s failed: unexpected %s", _name(channel), type(e).__name__)
            return NotifyResult(False, None, "invalid", 0)

    async def _send(self, channel, event) -> NotifyResult:
        if not isinstance(channel, Channel) or not isinstance(event, dict):
            return NotifyResult(False, None, "invalid", 0)
        name = channel.name
        try:
            body, headers = build_message(channel, event, env=self._env)
        except LookupError:
            log.warning("notify channel=%s unavailable: secret not set", name)
            return NotifyResult(False, None, "secret_unavailable", 0)
        if _url_problems(channel.url, channel.allow_private, channel.allow_http_loopback):
            return NotifyResult(False, None, "invalid", 0)
        if not self._allow(name):
            return NotifyResult(False, None, "circuit_open", 0)
        try:
            await asyncio.wait_for(self._sem.acquire(), self._busy_wait)
        except asyncio.TimeoutError:
            self._release_probe(name)
            return NotifyResult(False, None, "busy", 0)
        try:
            res = await self._attempts(channel, body, headers)
        finally:
            self._sem.release()
        if res.reason not in ("secret_unavailable", "invalid"):
            self._record(name, res.ok)
        else:
            self._release_probe(name)
        if not res.ok:
            log.warning("notify channel=%s failed reason=%s status=%s attempts=%d", name, res.reason, res.status, res.attempts)
        return res

    def _release_probe(self, name):
        b = self._breakers.get(name)
        if b is not None:
            b.probing = False

    async def _attempts(self, channel, body, headers) -> NotifyResult:
        attempts = 0
        last = _Fail("connect")
        for i in range(1 + len(self._backoffs)):
            if i:
                await self._sleep(self._backoffs[i - 1])
            attempts += 1
            try:
                status = await self._once(channel, body, headers)
                return NotifyResult(True, status, "ok", attempts)
            except _Fail as f:
                last = f
                if not f.retry:
                    break
        return NotifyResult(False, last.status, last.reason, attempts)

    async def _resolve(self, channel) -> "tuple[str, str | None, str]":
        """-> (ip to connect to, sni hostname or None, host-as-in-url).  Raises _Fail('dns'|'private_address')."""
        host = urlsplit(channel.url).hostname or ""
        try:
            ip = ipaddress.ip_address(host)
            literal = True
        except ValueError:
            ip, literal = None, False
        if literal:
            return str(ip), None, host
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
            addrs = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
        except (OSError, ValueError, UnicodeError):
            raise _Fail("dns", retry=True) from None
        if not addrs:
            raise _Fail("dns", retry=True)
        sp = urlsplit(channel.url)
        for a in addrs:                                   # ANY bad answer refuses (an attacker may mix public and private)
            if _blocked_ip(a):
                ok_loop = sp.scheme == "http" and channel.allow_http_loopback and _loopback_ip(a)
                if not (channel.allow_private or ok_loop):
                    raise _Fail("private_address")
        return str(addrs[0]), host, host

    async def _once(self, channel, body, headers) -> int:
        ip, sni, host = await self._resolve(channel)
        sp = urlsplit(channel.url)
        netloc_ip = f"[{ip}]" if ":" in ip else ip
        if sp.port:
            netloc_ip += f":{sp.port}"
        url = urlunsplit((sp.scheme, netloc_ip, sp.path or "/", sp.query, ""))
        hostport = f"[{host}]" if ":" in host else host
        if sp.port:
            hostport += f":{sp.port}"
        h = dict(headers)
        h["Host"] = hostport
        ext = {"sni_hostname": sni} if (sni and sp.scheme == "https") else {}
        try:
            async with asyncio.timeout(self._timeout):
                async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=self._timeout) as client:
                    async with client.stream("POST", url, content=body, headers=h, extensions=ext) as resp:
                        status = resp.status_code
                        got = 0
                        async for chunk in resp.aiter_raw():          # read and discard, at most MAX_READ bytes
                            got += len(chunk)
                            if got >= MAX_READ:
                                break
        except TimeoutError:
            raise _Fail("timeout", retry=True) from None
        except httpx.TimeoutException:
            raise _Fail("timeout", retry=True) from None
        except httpx.ConnectError as e:
            if _is_tls(e):
                raise _Fail("tls") from None
            raise _Fail("connect", retry=True) from None
        except httpx.TransportError as e:
            raise _Fail("tls" if _is_tls(e) else "connect", retry=not _is_tls(e)) from None
        except httpx.HTTPError:
            raise _Fail("connect", retry=True) from None
        if 200 <= status < 300:
            return status
        if 300 <= status < 400:
            raise _Fail("redirect", status)
        if status >= 500:
            raise _Fail("http_5xx", status, retry=True)
        if status == 429:
            raise _Fail("http_4xx", status, retry=True)
        if status >= 400:
            raise _Fail("http_4xx", status)
        raise _Fail("invalid", status)


def _is_tls(e: BaseException) -> bool:
    seen = 0
    while e is not None and seen < 5:
        if isinstance(e, ssl.SSLError):
            return True
        e = e.__cause__ or e.__context__
        seen += 1
    return False


def _name(channel) -> str:
    n = getattr(channel, "name", "?")
    return n if isinstance(n, str) and len(n) <= 40 else "?"
