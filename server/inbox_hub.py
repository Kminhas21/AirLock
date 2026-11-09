"""InboxHub: approval inbox for external (MCP proxy) sessions. See docs/plans/PROPOSAL-1-mcp-proxy.md (wire protocol).

Pure asyncio, no FastAPI imports. Peers are duck-typed: ``await peer.send_json(dict)`` and ``await peer.close(code)``.
Fail-closed: anything that is not the exact string "approve" from a human is a deny; a timeout, a proxy disconnect, a
duplicate or an invalid call is a deny. Frames are never trusted: nothing a peer sends can raise out of the hub, and
exception text is never sent to a peer (it goes to the log only).
"""
from __future__ import annotations

import asyncio
import collections
import fnmatch
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import escalation
import eventlog
import gate
import identity as identity_mod
import notify as notify_mod
import policy as policy_mod
import policy_writer
import proposal_monitor
import safe_text

logger = logging.getLogger(__name__)

_logged_policy_problems: set = set()


def _resolve_policy(path: str | None = None):
    """-> (policy_mode, Policy | None, registry | None). SENTINEL_POLICY unset => (False, None, None): legacy behaviour.
    Set but unusable => (True, None, ...): a BROKEN policy, every call is `ask`. Never raises."""
    path = (path or os.environ.get("SENTINEL_POLICY") or "").strip()        # a tenant's own policy file wins
    if not path:
        return False, None, None
    pol, reason = policy_mod.load_policy_file(path)
    if pol is None:
        if reason not in _logged_policy_problems:
            _logged_policy_problems.add(reason)
            logger.error("SENTINEL_POLICY is set but unusable (%s): EVERY proxied call will be held for the human", reason)
        return True, None, None
    registry = None
    reg_path = (os.environ.get("SENTINEL_REGISTRY") or "").strip()
    if reg_path:
        try:
            import proposal_monitor as _pm
            registry, why = _pm.load_registry(reg_path)
            if registry is None:
                logger.warning("policy: the destination registry is unusable (%s); evaluating without it", why)
        except Exception:
            logger.exception("policy: could not load the destination registry; evaluating without it")
    return True, pol, registry

MAX_FRAME_BYTES = 1_000_000
SESSION_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,40}")
MAX_SERVERS = 50
MAX_AUTO_APPROVE = 200
MAX_SHORT = 200            # server / tool / pattern strings
MAX_CALL_ID = 64
SUMMARY_LIMIT = 300
RING_SIZE = 50             # resolved calls remembered per session (in memory only)
HISTORY_SHOWN = 10
EARLIER_DENIED_SHOWN = 5
PREVIEW_LIMIT = 120
NOTE_LIMIT = 200
# resolutions that are nobody's decision about the call's content: not counted, never "earlier denied"
RULE_RATE_LIMIT = 20       # inbox_rule_request per RULE_RATE_WINDOW_S, hub wide
RULE_RATE_WINDOW_S = 60.0
NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
MAX_SECRET_NAMES = 20
BOUNDARY_LAYERS = frozenset({"env", "rlimit", "no_new_privs", "netns", "landlock_net", "landlock_fs"})
BOUNDARY_NETWORK = frozenset({"none", "loopback", "host"})
BOUNDARY_LIFECYCLE = frozenset({"session", "per_call"})
_BOUNDARY_KEYS = frozenset({"lifecycle", "layers", "missing", "network", "secrets"})
NOTIFY_TIMEOUT_S = 30.0    # hard bound on one notification send (the notifier has its own, shorter, timeouts)
AUTH_FRAME_TIMEOUT_S = 5.0
AUTH_AUDIT_WINDOW_S = 60.0
NOT_A_DECISION = frozenset({"cancelled", "disconnected", "restart", "log_unavailable"})


def _names(v: Any) -> list | None:
    """A list of <= 20 environment-variable NAMES (closed pattern), de-duplicated in order; anything else => None.
    Only names can pass the pattern, so a secret VALUE is never stored."""
    if not isinstance(v, list) or len(v) > MAX_SECRET_NAMES:
        return None
    out: list = []
    for x in v:
        if not isinstance(x, str) or not NAME_RE.fullmatch(x):
            return None
        if x not in out:
            out.append(x)
    return out


def validate_secrets_used(v: Any) -> list:
    """proxy_call.secrets_used: valid => the names, invalid or absent => [] (never fatal)."""
    names = _names(v)
    return names if names is not None else []


def validate_boundary(v: Any) -> dict | None:
    """proxy_hello.boundary: {server: {lifecycle, layers, missing, network, secrets}} with the closed shapes of
    docs/plans/ENFORCEMENT-BOUNDARY.md. ANY violation => None (treated as absent, never fatal)."""
    try:
        if not isinstance(v, dict) or len(v) > MAX_SERVERS:
            return None
        out: dict = {}
        for name, b in v.items():
            if not _is_str(name, MAX_SHORT, min_len=1) or not isinstance(b, dict) or not set(b) <= _BOUNDARY_KEYS:
                return None
            lifecycle, network = b.get("lifecycle"), b.get("network")
            if lifecycle is not None and (not isinstance(lifecycle, str) or lifecycle not in BOUNDARY_LIFECYCLE):
                return None
            if network is not None and (not isinstance(network, str) or network not in BOUNDARY_NETWORK):
                return None
            lists = {}
            for key in ("layers", "missing"):
                items = b.get(key, [])
                if not isinstance(items, list) or len(items) > len(BOUNDARY_LAYERS) or \
                        not all(isinstance(x, str) and x in BOUNDARY_LAYERS for x in items):
                    return None
                lists[key] = list(dict.fromkeys(items))
            secrets = _names(b.get("secrets", []))
            if secrets is None:
                return None
            out[name] = {"lifecycle": lifecycle, "layers": lists["layers"], "missing": lists["missing"],
                         "network": network, "secrets": secrets}
        return out
    except Exception:
        return None


def clean_note(v: Any) -> str | None:
    """Operator note: single line, control/bidi stripped, <= 200 chars; non-str or empty => None."""
    if not isinstance(v, str):
        return None
    out = safe_text.clean_field(v, NOTE_LIMIT)
    return out or None


def args_preview(args: Any) -> str:
    """One line <= 120 chars; secret-looking keys redacted by the event log's own sanitiser; control/bidi stripped."""
    try:
        return safe_text.clean_field(json.dumps(eventlog.sanitize_payload(args), ensure_ascii=False, default=str),
                                     PREVIEW_LIMIT)
    except Exception:
        return ""
HELLO_TIMEOUT_S = 10.0
UI_SEND_TIMEOUT_S = 5.0
PROXY_SEND_TIMEOUT_S = 5.0
MAX_SEEN = 10_000          # remembered call ids per session (older ones are forgotten)
MAX_INFLIGHT = 200         # concurrent calls per session; more get deny/invalid


def parse_frame(raw: Any) -> dict | None:
    """Text/bytes -> dict, or None (oversize, not JSON, not an object). Never raises."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            if len(raw) > MAX_FRAME_BYTES:
                return None
            raw = bytes(raw).decode("utf-8")
        if not isinstance(raw, str) or len(raw) > MAX_FRAME_BYTES:
            return None
        if len(raw.encode("utf-8", "replace")) > MAX_FRAME_BYTES:
            return None
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _is_str(v: Any, limit: int, *, min_len: int = 0) -> bool:
    return isinstance(v, str) and min_len <= len(v) <= limit


def _str_list(v: Any, max_items: int, max_len: int) -> bool:
    return isinstance(v, list) and len(v) <= max_items and all(_is_str(x, max_len) for x in v)


class _Peer:
    """Serialises and time-limits sends to one socket, and swallows (logs) failures."""

    def __init__(self, peer: Any, timeout: float):
        self.peer = peer
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self.dead = False
        self.principal = None            # identity mode: who this UI is (tenant filtering, RBAC)

    async def send(self, payload: dict) -> bool:
        """Serialised, time-limited send (the timeout covers waiting for the lock too). A failed or timed-out send
        CLOSES the socket: a UI reconnects and gets a fresh snapshot, a proxy fails closed."""
        if self.dead:
            return False

        async def locked() -> None:
            async with self._lock:
                if self.dead:                      # re-check: it may have died while we waited for the lock
                    raise ConnectionError("peer is dead")
                await self.peer.send_json(payload)

        try:
            await asyncio.wait_for(locked(), self._timeout)
            return True
        except Exception:
            logger.warning("inbox: send to a peer failed or timed out; closing it")
            await self.close()
            return False

    async def close(self, code: int = 1008) -> None:
        self.dead = True
        try:
            await asyncio.wait_for(self.peer.close(code), 2.0)
        except Exception:
            pass


@dataclass
class _Pending:
    session: "ProxySession"
    call_id: str
    server: str
    tool: str
    args: dict
    auto: bool
    alerts: list
    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: str | None = None
    reason: str | None = None
    rule_id: str | None = None
    policy_digest: str | None = None
    policy_mode: bool = False
    note: str | None = None
    secrets_used: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    history: list = field(default_factory=list)
    earlier_denied: list = field(default_factory=list)
    cancelled: bool = False       # resolved by the proxy's proxy_cancel (not a human decision)
    since: float = 0.0            # hub clock when the call became pending (age_s, escalation)
    escalation_level: int = 0
    operator: str | None = None   # principal id of the human who decided (identity mode)

    def claim(self, decision: str, reason: str) -> bool:
        """Once-only: the first claim wins (sync, so there is no await between check and set)."""
        if self.decision is not None:
            return False
        self.decision, self.reason = decision, reason
        self.event.set()
        return True


@dataclass
class ProxySession:
    session_id: str
    servers: list
    auto_approve: list
    conn: _Peer
    monitor: Any = None
    seen: set = field(default_factory=set)
    secrets: dict = field(default_factory=dict)        # call_id -> secret argument values (bounded), used only to scrub logged free text
    seen_order: Any = field(default_factory=collections.deque)
    pending: dict = field(default_factory=dict)
    tasks: set = field(default_factory=set)
    closed: bool = False
    policy_mode: bool = False
    policy: Any = None
    policy_registry: Any = None
    starting: set = field(default_factory=set)         # reserved, still inside the monitor (not yet pending)
    cancelled_early: set = field(default_factory=set)  # proxy_cancel arrived while in `starting`
    logged_hello: bool = False
    boundary: dict | None = None
    agent_id: str = "agent"
    tenant: str = "default"
    identity_mode: bool = False
    ring: Any = field(default_factory=lambda: collections.deque(maxlen=RING_SIZE))
    counts: dict = field(default_factory=lambda: {"approved": 0, "denied": 0, "auto": 0, "policy": 0})

    def record(self, call_id, server, tool, args, decision, reason, rule_id, note) -> None:
        self.ring.append({"call_id": call_id, "server": server, "tool": tool, "args": args,
                          "args_preview": args_preview(args), "decision": decision, "reason": reason,
                          "rule_id": rule_id, "note": note, "ts": time.time()})
        if reason in NOT_A_DECISION:
            return
        if reason == "auto":
            self.counts["auto"] += 1
        elif reason == "policy":
            self.counts["policy"] += 1
        elif decision == "approve":
            self.counts["approved"] += 1
        else:
            self.counts["denied"] += 1

    @staticmethod
    def _public(item: dict) -> dict:
        return {k: item[k] for k in ("call_id", "server", "tool", "args_preview", "decision", "reason", "rule_id", "note", "ts")}

    def views(self) -> tuple[dict, list, list]:
        """(session_summary, session_history, earlier_denied) as sent to the UI: newest first, never the full args."""
        newest = list(reversed(self.ring))
        history = [self._public(i) for i in newest[:HISTORY_SHOWN]]
        denied = [self._public(i) for i in newest
                  if i["decision"] == "deny" and i["reason"] not in NOT_A_DECISION][:EARLIER_DENIED_SHOWN]
        return dict(self.counts), history, denied

    @property
    def log_sid(self) -> str:
        """session_id as written to the event log: identity mode stores '<tenant>/<session_id>' so two tenants that share BOTH a
        session id and a call id cannot collide on the log's unique (session_id, call_id) indexes; the UI never sees the prefix."""
        return f"{self.tenant}/{self.session_id}" if self.identity_mode else self.session_id

    def reserve(self, call_id: str) -> bool:
        """Synchronous duplicate check + registration (no await in between). False: already seen."""
        if call_id in self.seen:
            return False
        self.seen.add(call_id)
        self.seen_order.append(call_id)
        while len(self.seen_order) > MAX_SEEN:
            self.seen.discard(self.seen_order.popleft())
        return True


class _SessionMap(dict):
    """Live sessions keyed by (tenant, session_id): two tenants may use the same session id at the same time. A bare string key
    means tenant 'default' (legacy mode: one implicit tenant, behaviour unchanged)."""

    @staticmethod
    def _k(key):
        return ("default", key) if isinstance(key, str) else key

    def __getitem__(self, key):
        return super().__getitem__(self._k(key))

    def __setitem__(self, key, value):
        super().__setitem__(self._k(key), value)

    def __delitem__(self, key):
        super().__delitem__(self._k(key))

    def __contains__(self, key):
        return super().__contains__(self._k(key))

    def get(self, key, default=None):
        return super().get(self._k(key), default)

    def pop(self, key, *default):
        return super().pop(self._k(key), *default)


class InboxHub:
    def __init__(self, gate_timeout: float | None = None, monitor_factory: Callable[[], Any] | None = None,
                 store: Any = None, identity: Any = None, notifier: Any = None, clock: Callable[[], float] | None = None,
                 sleep: Callable[..., Any] | None = None):
        self._timeout = float(gate.GATE_TIMEOUT_S if gate_timeout is None else gate_timeout)
        self.identity = identity           # identity.IdentityStore (identity mode) or None (legacy: SENTINEL_WS_TOKEN)
        self.identity_broken = False       # SENTINEL_IDENTITY_FILE set but unusable: refuse everyone
        self._notifier = notifier
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._auth_audit: dict = {}
        self._channels: dict = {}
        self._channel_problems: set = set()
        self._monitor_factory = monitor_factory
        self.sessions: _SessionMap = _SessionMap()
        self._uis: list[_Peer] = []
        self._bg: set = set()
        self._rule_times: collections.deque = collections.deque()
        self._rule_lock = asyncio.Lock()
        self.store = store                 # durable event log (eventlog.EventStore-like) or None: legacy behaviour
        self.log_unusable = False          # a log was configured but could not be opened: refuse every session
        self.log_path: str | None = None
        self.log_keyed = False
        self._log_events: int | None = None   # last known seq (cached for /health; never verify() there)
        if store is not None:
            self._log_events = 0

    # ------------------------------------------------------------------ identity
    @property
    def identity_mode(self) -> bool:
        return self.identity is not None or self.identity_broken

    async def setup_identity_from_env(self, env: Any = None) -> None:
        """SENTINEL_IDENTITY_FILE unset => nothing (legacy). Set but unusable => FAIL CLOSED: every connection is refused."""
        env = os.environ if env is None else env
        if not (env.get("SENTINEL_IDENTITY_FILE") or "").strip():
            return
        store, reason = await asyncio.to_thread(identity_mod.load_identity, env)
        if store is None:
            self.identity, self.identity_broken = None, True
            logger.error("SENTINEL_IDENTITY_FILE is set but unusable (%s): EVERY inbox and proxy connection is refused",
                         safe_text.clean_field(reason, 300))
        else:
            self.identity, self.identity_broken = store, False

    def _tenant_cfg(self, tenant: str):
        return self.identity.tenant(tenant) if self.identity is not None else None

    def _timeout_for(self, session: "ProxySession") -> float:
        cfg = self._tenant_cfg(session.tenant) if session.identity_mode else None
        t = getattr(cfg, "gate_timeout_s", None)
        return float(t) if t else self._timeout

    @staticmethod
    def _idf(session: "ProxySession", operator: str | None = None) -> dict:
        return {"operator": operator} if session.identity_mode else {}

    # ------------------------------------------------------------------ durable log
    async def open_log_from_env(self, env: Any = None) -> None:
        """SENTINEL_EVENT_LOG unset => nothing (legacy). Set but unusable => ERROR once and every session is refused."""
        env = os.environ if env is None else env
        path = (env.get("SENTINEL_EVENT_LOG") or "").strip()
        if not path:
            return
        self.log_path = path

        def _open():
            key = eventlog.load_key(env)
            store = eventlog.EventStore(path, key=key, anchor_path=(env.get("SENTINEL_LOG_ANCHOR") or None))
            info = store.open()
            return store, key is not None, info

        try:
            self.store, self.log_keyed, info = await asyncio.to_thread(_open)
            self._log_events = int(info.get("seq", 0))
            self.log_unusable = False
        except Exception as exc:
            self.store, self.log_unusable = None, True
            logger.error("SENTINEL_EVENT_LOG is set but the log is unusable (%s): EVERY proxy session will be refused "
                         "(log_unavailable)", safe_text.clean_field(f"{type(exc).__name__}: {exc}", 300))

    async def close_log(self) -> None:
        store, self.store = self.store, None
        if store is not None:
            try:
                await asyncio.to_thread(store.close)
            except Exception:
                logger.exception("inbox: closing the event log failed")

    def event_log_info(self) -> dict | None:
        """For /health: None when no log is configured. Cheap: the last seq is cached, verify() is never run here."""
        if self.log_path is None and self.store is None:
            return None
        return {"path": self.log_path, "events": self._log_events, "keyed": self.log_keyed,
                "ok": self.store is not None and not self.log_unusable}

    async def _append(self, kind: str, sid: str, cid: str | None, payload: dict) -> str:
        """'ok' | 'dup' | 'fail'. With no store configured this is a no-op 'ok' (legacy). Runs in a thread."""
        store = self.store
        if store is None:
            return "ok"
        try:
            ev = await asyncio.to_thread(lambda: store.append(kind, session_id=sid, call_id=cid, payload=payload))
            seq = getattr(ev, "seq", None)
            if isinstance(seq, int):
                self._log_events = max(self._log_events or 0, seq)
            return "ok"
        except eventlog.DuplicateEvent:
            return "dup"
        except Exception as exc:
            logger.error("inbox: event log append (%s) failed: %s", kind,
                         safe_text.clean_field(f"{type(exc).__name__}: {exc}", 200))
            return "fail"

    async def _log_decision(self, session: "ProxySession", call_id: str, decision: str, reason: str, actor: str,
                            rule_id: str | None, digest: str | None, note: str | None = None,
                            operator: str | None = None):
        """Write the decision record BEFORE anything is sent. -> (decision, reason, actor) EFFECTIVE, or None if the
        decision was already recorded (duplicate: ignore). An approve that cannot be recorded becomes deny/log_unavailable."""
        payload = {"decision": decision, "reason": reason, "actor": actor, "rule_id": rule_id, "policy_digest": digest}
        if note and decision == "deny" and reason == "human":
            payload["note"] = note
        if session.identity_mode:
            payload["operator"], payload["tenant"] = operator, session.tenant
        res = await self._append("decision", session.log_sid, call_id, payload)
        if res == "dup":
            return None
        if res == "fail":
            if decision == "approve":
                decision, reason, actor = "deny", "log_unavailable", "system"
                payload.pop("note", None)
                await self._append("decision", session.log_sid, call_id,
                                   {**payload, "decision": decision, "reason": reason, "actor": actor})   # best effort
        return decision, reason, actor

    @staticmethod
    def _alert_records(alerts: list, secrets=frozenset()) -> list:
        out = []
        for a in alerts:
            if isinstance(a, dict):
                out.append({"severity": a.get("severity"), "trigger": a.get("trigger"), "score": a.get("drift_score"),
                            "threshold": a.get("threshold"), "message": eventlog.scrub(a.get("message"), secrets)})
        return out

    # ------------------------------------------------------------------ helpers
    def _new_monitor(self):
        if self._monitor_factory is not None:
            return self._monitor_factory()
        import proposal_monitor
        return proposal_monitor.get_monitor_factory().new_session()

    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)
        return t

    def pending_count(self) -> int:
        return sum(len(s.pending) for s in self.sessions.values())

    def _pending_payload(self, p: _Pending, deadline_s: float | None = None) -> dict:
        if deadline_s is None:
            deadline_s = self._timeout_for(p.session)
        d = {"session_id": p.session.session_id, "call_id": p.call_id, "server": p.server, "tool": p.tool,
             "args": p.args, "auto": p.auto, "alerts": p.alerts, "deadline_s": deadline_s}
        if p.policy_mode:
            d["rule_id"], d["policy_digest"] = p.rule_id, p.policy_digest
        d["secrets_used"] = list(p.secrets_used)
        d["session_summary"], d["session_history"], d["earlier_denied"] = p.summary, p.history, p.earlier_denied
        if p.session.identity_mode:
            d["agent_id"], d["tenant"] = p.session.agent_id, p.session.tenant
            d["escalation_level"] = p.escalation_level
            d["age_s"] = max(0, int(self._clock() - p.since))
        return d

    @staticmethod
    def _policy_fields(p: _Pending) -> dict:
        return {"rule_id": p.rule_id, "policy_digest": p.policy_digest} if p.policy_mode else {}

    async def _broadcast(self, payload: dict, tenant: str | None = None) -> None:
        """Send to the UIs. Identity mode: ONLY the UIs of `tenant` (no tenant given => nobody: fail closed)."""
        if self.identity_mode:
            uis = [u for u in self._uis if u.principal is not None and tenant is not None and u.principal.tenant == tenant]
        else:
            uis = list(self._uis)
        if not uis:
            return
        results = await asyncio.gather(*(u.send(payload) for u in uis), return_exceptions=True)
        for u, ok in zip(uis, results):
            if ok is not True and u in self._uis:
                self._uis.remove(u)

    # ------------------------------------------------------------------ proxy side
    async def proxy_hello(self, peer: Any, frame: Any, principal: Any = None) -> ProxySession | None:
        """Validate the FIRST frame. Returns the session, or None after sending hello_reject (the caller closes)."""
        conn = _Peer(peer, PROXY_SEND_TIMEOUT_S)

        async def reject(reason: str) -> None:
            await conn.send({"event": "hello_reject", "reason": reason})
            await conn.close()
            return None

        if not isinstance(frame, dict) or frame.get("event") != "proxy_hello":
            return await reject("bad_hello")
        sid = frame.get("session_id")
        if not isinstance(sid, str) or not SESSION_ID_RE.fullmatch(sid):
            return await reject("bad_session_id")
        servers = frame.get("servers", [])
        auto_approve = frame.get("auto_approve", [])
        if not _str_list(servers, MAX_SERVERS, MAX_SHORT) or not _str_list(auto_approve, MAX_AUTO_APPROVE, MAX_SHORT):
            return await reject("bad_hello")
        if principal is not None and principal.servers is not None and not all(
                any(fnmatch.fnmatchcase(sv, g) for g in principal.servers) for sv in servers):
            return await reject("forbidden_server")             # the agent declares a server outside its allowlist
        if self.log_unusable:
            return await reject("log_unavailable")
        tenant = principal.tenant if (self.identity_mode and principal is not None) else "default"
        live = self.sessions.get((tenant, sid))
        if live is not None and not live.closed:
            return await reject("duplicate_session_id")                # only inside ONE tenant
        session = ProxySession(sid, list(servers), list(auto_approve), conn)
        session.boundary = validate_boundary(frame.get("boundary"))
        if self.identity_mode:
            session.identity_mode = True
            session.agent_id = principal.id if principal is not None else "agent"
            session.tenant = principal.tenant if principal is not None else "default"
        self.sessions[(session.tenant, sid)] = session          # claimed before any await: a racing second hello sees it
        try:
            tcfg = self._tenant_cfg(session.tenant) if session.identity_mode else None
            session.policy_mode, session.policy, session.policy_registry = await asyncio.to_thread(
                _resolve_policy, getattr(tcfg, "policy_file", None))
        except Exception:
            logger.exception("inbox: policy resolution failed; treating the policy as broken")
            session.policy_mode, session.policy, session.policy_registry = True, None, None
        try:
            session.monitor = await asyncio.to_thread(self._new_monitor)
        except Exception:
            logger.exception("inbox: could not build a monitor for session %s; auto calls will be held", sid)
            session.monitor = None
        if self.store is not None:         # write-ahead: the hello is on disk before the ack
            res = await self._append("proxy_hello", session.log_sid, None, self._hello_payload(session))
            if res != "ok":
                if self.sessions.get((session.tenant, sid)) is session:
                    del self.sessions[(session.tenant, sid)]
                session.closed = True
                return await reject("log_unavailable")
            session.logged_hello = True
        if not await conn.send({"event": "hello_ack", "session_id": sid}):
            await self.proxy_closed(session)
            return None
        # a UI that is already open learns the servers and the boundary from this event (the snapshot only reaches UIs that connect later):
        # without them a sandboxed session would be displayed as unsandboxed
        self._spawn(self._broadcast({"event": "inbox_session", "session_id": sid, "state": "open",
                                     "servers": session.servers, "boundary": session.boundary}, session.tenant))
        return session

    def _hello_payload(self, session: "ProxySession") -> dict:
        mon = session.monitor
        reg, frozen = session.policy_registry, None
        try:
            if reg is None:
                reg = getattr(mon, "registry", None)
            if self._monitor_factory is None:
                fm = proposal_monitor.get_monitor_factory().frozen_model
                frozen = fm.get("sha256") if isinstance(fm, dict) else None
        except Exception:
            pass
        try:
            reg_digest = reg.digest() if reg is not None else None
        except Exception:
            reg_digest = None
        return {"session_id": session.session_id, "servers": session.servers, "auto_approve": session.auto_approve,
                "monitor_mode": getattr(mon, "mode", None) if mon is not None else None,
                "policy_digest": session.policy.digest() if session.policy is not None else None,
                "registry_digest": reg_digest, "frozen_model_sha256": frozen, "boundary": session.boundary,
                **({"agent_id": session.agent_id, "tenant": session.tenant} if session.identity_mode else {})}

    async def handle_proxy_frame(self, session: ProxySession, frame: Any) -> bool:
        """Process one parsed frame. Returns False when the connection must be closed (protocol violation)."""
        if not isinstance(frame, dict):
            logger.warning("inbox: proxy %s sent a non-object frame; closing", session.session_id)
            return False
        ev = frame.get("event")
        if ev == "proxy_call":
            return self._start_call(session, frame)
        if ev == "proxy_result":
            await self._forward_result(session, frame)
            return True
        if ev == "proxy_cancel":
            self._cancel(session, frame)
            return True
        logger.warning("inbox: proxy %s sent unknown event %s; ignoring", session.session_id, repr(ev)[:80])
        return True

    def _cancel(self, session: ProxySession, frame: dict) -> None:
        """proxy_cancel: the proxy dropped the call. Never approves, never closes the connection, never teaches the monitor."""
        call_id = frame.get("call_id")
        if not _is_str(call_id, MAX_CALL_ID, min_len=1):
            logger.warning("inbox: ignoring a proxy_cancel without a usable call_id from %s", session.session_id)
            return
        reason = "timeout" if frame.get("reason") == "timeout" else "cancelled"
        p = session.pending.get(call_id)
        if p is not None:
            if p.claim("deny", reason):          # once-only: a no-op if a human (or the timer) already decided
                p.cancelled = True
            return
        if call_id in session.starting:
            session.cancelled_early.add(call_id)
            return
        logger.info("inbox: proxy_cancel for an unknown or already resolved call ignored")

    def _start_call(self, session: ProxySession, frame: dict) -> bool:
        call_id = frame.get("call_id")
        if not _is_str(call_id, MAX_CALL_ID, min_len=1):
            logger.warning("inbox: proxy %s sent a proxy_call without a usable call_id; closing", session.session_id)
            return False
        # reserve (session_id, call_id) NOW, synchronously: two frames can never both pass the duplicate check
        fresh = session.reserve(call_id)
        if not fresh:
            coro = self._reply(session, call_id, "deny", "duplicate")
        elif len(session.tasks) >= MAX_INFLIGHT:
            logger.warning("inbox: session %s exceeded %d in-flight calls", session.session_id, MAX_INFLIGHT)
            coro = self._reply(session, call_id, "deny", "invalid")
        else:
            session.starting.add(call_id)
            coro = self._run_call(session, call_id, frame)
        task = asyncio.create_task(coro)
        session.tasks.add(task)
        task.add_done_callback(session.tasks.discard)
        return True

    async def _reply(self, session: ProxySession, call_id: str, decision: str, reason: str,
                     note: str | None = None) -> None:
        msg = {"event": "proxy_decision", "call_id": call_id, "decision": decision, "reason": reason}
        if note and decision == "deny" and reason == "human":      # the operator's note reaches the agent on human denials only
            msg["note"] = note
        await session.conn.send(msg)

    async def _register(self, session: ProxySession, tool: str, args: dict, decision: str) -> None:
        if session.monitor is None:
            return
        try:
            await asyncio.to_thread(session.monitor.register_decision, tool, args, decision)
        except Exception:
            logger.exception("inbox: monitor.register_decision failed; continuing")

    async def _run_call(self, session: ProxySession, call_id: str, frame: dict) -> None:
        try:
            await self._run_call_inner(session, call_id, frame)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("inbox: unexpected error handling call %r; denying", call_id)
            session.pending.pop(call_id, None)
            await self._reply(session, call_id, "deny", "invalid")
        finally:
            session.starting.discard(call_id)
            session.cancelled_early.discard(call_id)

    async def _run_call_inner(self, session: ProxySession, call_id: str, frame: dict) -> None:
        sid = session.session_id
        server, tool, args, auto = frame.get("server"), frame.get("tool"), frame.get("args"), frame.get("auto")
        if not (_is_str(server, MAX_SHORT) and _is_str(tool, MAX_SHORT, min_len=1) and isinstance(args, dict)
                and isinstance(auto, bool)):
            await self._reply(session, call_id, "deny", "invalid")
            return

        secrets_used = validate_secrets_used(frame.get("secrets_used"))     # names only; invalid => []
        alerts: list = []
        # "working": a monitor with a detector looked at the call, did not hit an error, and returned a list
        mon = session.monitor
        working = mon is not None and not getattr(mon, "is_rules", False)
        if mon is not None:
            errors_before = proposal_monitor.error_count()
            try:
                alerts = await asyncio.to_thread(mon.on_proposal, "", tool, args, call_id)
                if not isinstance(alerts, list):
                    raise TypeError("monitor returned a non-list")
            except Exception:
                logger.exception("inbox: monitor.on_proposal failed on %r; continuing without alerts", call_id)
                alerts, working = [], False
            if proposal_monitor.error_count() > errors_before:      # real monitors swallow errors and return []
                working = False
        if call_id in session.cancelled_early:     # the proxy dropped it while the monitor ran: never hold or approve
            return
        # (a session closed while the monitor ran is NOT dropped here: call_proposed is written first, then denied/disconnected below)

        rule_id: str | None = None
        digest: str | None = None
        verdict: str | None = None
        policy_rec = None
        if session.policy_mode:
            # the proxy's `auto` flag is IGNORED in policy mode; a broken policy asks for everything
            auto = False
            digest = session.policy.digest() if session.policy is not None else None
            verdict = "ask"
            if session.policy is not None:
                try:
                    dec = await asyncio.to_thread(session.policy.evaluate, server, tool, args,
                                                  registry=session.policy_registry, alerts_present=bool(alerts),
                                                  secrets_used=bool(secrets_used))
                    verdict, rule_id = dec.verdict, dec.rule_id
                    if verdict not in ("allow", "deny", "ask"):
                        verdict, rule_id = "ask", None
                except Exception:
                    logger.exception("inbox: policy evaluation failed; asking the human")
                    verdict, rule_id = "ask", None
            policy_rec = {"verdict": verdict, "rule_id": rule_id, "digest": digest}
            if call_id in session.cancelled_early:
                return

        # what happens next, decided BEFORE anything is logged or sent
        immediate: tuple | None = None            # (decision, reason, actor)
        if session.policy_mode:
            if verdict == "deny":
                immediate = ("deny", "policy", "policy")
            elif verdict == "allow" and working and not alerts:
                immediate = ("approve", "policy", "policy")
        elif auto and working and not alerts and not secrets_used:     # credentials are never granted by the legacy flag
            immediate = ("approve", "auto", "auto")

        # secret VALUES of this call (from its own arguments): free text that may echo them (alert messages, tool output) is scrubbed before it is logged
        call_secrets = eventlog.secret_values(args) if self.store is not None else frozenset()
        if call_secrets:
            session.secrets[call_id] = call_secrets
            while len(session.secrets) > 200:
                session.secrets.pop(next(iter(session.secrets)))
        # write-ahead: call_proposed is on disk before inbox_pending / any auto or policy reply
        res = await self._append("call_proposed", session.log_sid, call_id,
                                 {"server": server, "tool": tool, "args": args, "auto": auto,
                                  "alerts": self._alert_records(alerts, call_secrets), "policy": policy_rec,
                                  "secrets_used": secrets_used})
        if res == "dup":
            return
        if res == "fail":
            await self._reply(session, call_id, "deny", "log_unavailable")
            return
        if call_id in session.cancelled_early:
            await self._log_decision(session, call_id, "deny", "cancelled", "system", rule_id, digest)
            return
        if session.closed:
            await self._log_decision(session, call_id, "deny", "disconnected", "system", rule_id, digest)
            await self._register(session, tool, args, "deny")
            return

        pol_fields = {"rule_id": rule_id, "policy_digest": digest} if session.policy_mode else {}
        if immediate is not None:
            eff = await self._log_decision(session, call_id, *immediate, rule_id, digest)
            if eff is None:
                return
            decision, reason, _actor = eff
            session.record(call_id, server, tool, args, decision, reason, rule_id, None)
            await self._register(session, tool, args, decision)
            await self._reply(session, call_id, decision, reason)
            await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                                   "decision": decision, "reason": reason, **pol_fields, **self._idf(session)},
                                  session.tenant)
            return

        # held for a human: not auto, or auto with an alert, or auto with a degraded monitor (fail closed)
        p = _Pending(session, call_id, server, tool, args, auto, alerts, rule_id=rule_id, policy_digest=digest,
                     policy_mode=session.policy_mode, secrets_used=secrets_used)
        p.summary, p.history, p.earlier_denied = session.views()        # state BEFORE this call
        session.pending[call_id] = p
        session.starting.discard(call_id)
        # the decision timer starts NOW; the broadcast runs beside it and cannot delay it
        p.since = self._clock()
        announce = self._spawn(self._broadcast({"event": "inbox_pending", **self._pending_payload(p)}, session.tenant))
        esc = self._start_escalation(p)
        try:
            await asyncio.wait_for(p.event.wait(), self._timeout_for(session))
        except asyncio.TimeoutError:
            p.claim("deny", "timeout")
        finally:
            if esc is not None:                      # no escalation, no notification after the call is resolved
                esc.cancel()
                await asyncio.gather(esc, return_exceptions=True)
        session.pending.pop(call_id, None)
        if p.cancelled:                  # proxy_cancel: no proxy_decision, no monitor registration
            eff = await self._log_decision(session, call_id, "deny", p.reason or "cancelled", "system", rule_id, digest)
            await asyncio.gather(announce, return_exceptions=True)
            if eff is None:
                return
            session.record(call_id, server, tool, args, "deny", "cancelled", rule_id, None)
            await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                                   "decision": "deny", "reason": p.reason, **self._policy_fields(p), **self._idf(session)},
                                  session.tenant)
            return
        decision, reason = ("approve" if p.decision == "approve" else "deny"), p.reason or "invalid"
        actor = "human" if reason == "human" else "system"
        note = p.note if (decision == "deny" and reason == "human") else None      # never a note on an approve
        operator = p.operator if reason == "human" else None
        eff = await self._log_decision(session, call_id, decision, reason, actor, rule_id, digest, note, operator)
        if eff is None:
            await asyncio.gather(announce, return_exceptions=True)
            return
        decision, reason, _actor = eff
        if not (decision == "deny" and reason == "human"):
            note = None
        session.record(call_id, server, tool, args, decision, reason, rule_id, note)
        await self._register(session, tool, args, decision)
        await self._reply(session, call_id, decision, reason, note)
        await asyncio.gather(announce, return_exceptions=True)       # pending before resolved on every UI
        extra_note = {"note": note} if note else {}
        await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                               "decision": decision, "reason": reason, **self._policy_fields(p), **extra_note,
                               **self._idf(session, operator if reason == "human" else None)}, session.tenant)

    async def _forward_result(self, session: ProxySession, frame: dict) -> None:
        call_id, status = frame.get("call_id"), frame.get("status")
        if not _is_str(call_id, MAX_CALL_ID, min_len=1) or call_id not in session.seen or status not in ("ok", "error"):
            logger.warning("inbox: ignoring a malformed or unknown proxy_result from %s", session.session_id)
            return
        summary = safe_text.clean_field(frame.get("summary", "") if isinstance(frame.get("summary"), str) else "",
                                        SUMMARY_LIMIT)
        if self.store is not None:         # best effort: never raises into the call path
            # the tool OUTPUT is free text and often echoes the arguments: by default only its status and length are logged;
            # SENTINEL_LOG_RESULTS=1 also stores the summary, scrubbed of this call's secret argument values
            rec = {"status": status, "summary_len": len(summary)}
            if os.environ.get("SENTINEL_LOG_RESULTS") == "1":
                rec["summary"] = eventlog.scrub(summary, session.secrets.get(call_id, frozenset()))
            await self._append("call_result", session.log_sid, call_id, rec)
        await self._broadcast({"event": "inbox_result", "session_id": session.session_id, "call_id": call_id,
                               "status": status, "summary": summary}, session.tenant)

    async def proxy_closed(self, session: ProxySession) -> None:
        """The proxy went away: every pending call of the session is a deny/disconnected."""
        if session.closed:
            return
        session.closed = True
        for p in list(session.pending.values()):
            p.claim("deny", "disconnected")
        if session.tasks:
            await asyncio.gather(*list(session.tasks), return_exceptions=True)
        if self.sessions.get((session.tenant, session.session_id)) is session:
            del self.sessions[(session.tenant, session.session_id)]
        if session.logged_hello:
            await self._append("proxy_close", session.log_sid, None, {"reason": "disconnected"})   # best effort
        await self._broadcast({"event": "inbox_session", "session_id": session.session_id, "state": "closed"},
                              session.tenant)

    async def audit_auth_failure(self, kind: str, reason: str, remote: Any) -> None:
        """Log a failed authentication (no credential material), at most once per (remote, 60 s)."""
        try:
            key = str(remote)
            now = self._clock()
            last = self._auth_audit.get(key)
            if last is not None and now - last < AUTH_AUDIT_WINDOW_S:
                return
            if len(self._auth_audit) > 2048:
                self._auth_audit.clear()
            self._auth_audit[key] = now
            await self._append("auth_failed", None, None, {"kind": kind, "reason": reason,
                                                           "remote_hash": hashlib.sha256(key.encode()).hexdigest()[:12]})
        except Exception:
            logger.exception("inbox: could not audit a failed authentication")

    # ------------------------------------------------------------------ escalation
    def _start_escalation(self, p: _Pending):
        if not p.session.identity_mode:
            return None
        cfg = self._tenant_cfg(p.session.tenant)
        levels = tuple(getattr(cfg, "levels", ()) or ())
        if not levels:
            return None
        return asyncio.create_task(self._escalate(p, levels))

    async def _escalate(self, p: _Pending, levels: tuple) -> None:
        fired = 0
        try:
            while p.decision is None:
                for idx, lvl in escalation.plan(levels, self._clock() - p.since, fired):
                    if p.decision is not None:
                        return
                    fired = idx
                    p.escalation_level = idx
                    await self._broadcast({"event": "inbox_escalated", "session_id": p.session.session_id,
                                           "call_id": p.call_id, "level": idx, "after_s": lvl.after_s}, p.session.tenant)
                    for name in lvl.notify:
                        self._notify(p, idx, name)
                nxt = escalation.next_due_in(levels, self._clock() - p.since, fired)
                if nxt is None:
                    return
                await self._sleep(nxt)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("inbox: escalation task failed")

    def _channel(self, tenant: str, name: str):
        key = (tenant, name)
        if key in self._channels:
            return self._channels[key]
        ch = None
        cfg = self._tenant_cfg(tenant)
        raw = (getattr(cfg, "channels", None) or {}).get(name)
        if raw is None:
            if key not in self._channel_problems:
                self._channel_problems.add(key)
                logger.error("inbox: escalation names an unknown channel %r for tenant %r; skipping it", name, tenant)
        else:
            try:
                ch = notify_mod.validate_channel(name, {
                    "type": raw.type, "url": raw.url, "format": raw.format, "secret_env": raw.secret_env,
                    "include_args": raw.include_args, "allow_private": raw.allow_private,
                    "allow_http_loopback": bool(getattr(raw, "allow_http_loopback", False))})
            except Exception as exc:
                logger.error("inbox: notification channel %r of tenant %r is invalid (%s); skipping it", name, tenant,
                             safe_text.clean_field(str(exc), 200))
        self._channels[key] = ch
        return ch

    def _notify(self, p: _Pending, level: int, name: str) -> None:
        ch = self._channel(p.session.tenant, name)
        if ch is None:
            return
        event = {"tenant": p.session.tenant, "agent_id": p.session.agent_id, "server": p.server, "tool": p.tool,
                 "call_id": p.call_id, "age_s": max(0, int(self._clock() - p.since)), "level": level,
                 "link": (os.environ.get("SENTINEL_PUBLIC_URL") or "") + "/#inbox"}
        if ch.include_args:                              # arguments only when the channel opted in, and only the redacted preview
            event["args_preview"] = args_preview(p.args)
        self._spawn(self._send_notification(ch, event, p, level))

    async def _send_notification(self, ch, event: dict, p: _Pending, level: int) -> None:
        ok, status = False, None
        try:
            if self._notifier is None:
                self._notifier = notify_mod.Notifier()
            res = await asyncio.wait_for(self._notifier.send(ch, event), NOTIFY_TIMEOUT_S)
            ok, status = bool(getattr(res, "ok", False)), getattr(res, "status", None)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("inbox: notification to channel %r failed or timed out", ch.name)
        if self.store is not None:                       # best effort
            await self._append("notification", p.session.log_sid, p.call_id,
                               {"channel": ch.name, "level": level, "ok": ok, "status": status})

    # ------------------------------------------------------------------ UI side
    def snapshot(self, recent: list | None = None, capabilities: dict | None = None, principal: Any = None) -> dict:
        """Identity mode: ONLY the principal's tenant (no principal => nothing: fail closed)."""
        sessions = []
        for s in self.sessions.values():
            if self.identity_mode and (principal is None or s.tenant != principal.tenant):
                continue
            pend = [self._pending_payload(p) for p in s.pending.values()]
            sessions.append({"session_id": s.session_id, "servers": s.servers, "boundary": s.boundary, "pending": pend})
        caps = capabilities if capabilities is not None else {"policy_writable": False, "event_log": self.store is not None}
        out = {"event": "inbox_snapshot", "sessions": sessions, "recent": list(recent or []), "capabilities": caps}
        if principal is not None:
            out["principal"] = {"id": principal.id, "tenant": principal.tenant, "role": principal.role}
        return out

    def _policy_path_for(self, principal: Any) -> str:
        """A tenant's own policy file wins over SENTINEL_POLICY (identity mode)."""
        cfg = self._tenant_cfg(principal.tenant) if principal is not None else None
        return (getattr(cfg, "policy_file", None) or os.environ.get("SENTINEL_POLICY") or "").strip()

    def _capabilities(self, principal: Any = None) -> dict:
        """policy_writable: SENTINEL_POLICY_WRITABLE=1 AND a usable policy file (identity mode: also role admin, and the
        TENANT's file). Runs in a thread (reads the file)."""
        writable = False
        if (os.environ.get("SENTINEL_POLICY_WRITABLE") or "").strip() == "1" and \
                (principal is None or principal.role == "admin"):
            path = self._policy_path_for(principal)
            if path:
                try:
                    writable = policy_mod.load_policy_file(path)[0] is not None
                except Exception:
                    writable = False
        caps = {"policy_writable": writable, "event_log": self.store is not None}
        if principal is not None:
            caps["can_decide"] = principal.role in ("approver", "admin")
        return caps

    async def ui_connected(self, peer: Any, principal: Any = None) -> _Peer:
        """Register a UI and send its snapshot. The UI's send lock is held from registration until the snapshot is out, so any broadcast that
        happens meanwhile (e.g. a proxy closing) queues BEHIND the snapshot: the snapshot is always the first frame a UI receives. The snapshot is
        built after the history read, so it already contains every state change made before it; a later duplicate broadcast is harmless (items are keyed)."""
        ui = _Peer(peer, UI_SEND_TIMEOUT_S)
        ui.principal = principal
        async with ui._lock:
            self._uis.append(ui)
            recent: list = []
            if self.store is not None:
                try:
                    if self.identity_mode:
                        recent = await asyncio.to_thread(self.store.recent_resolved, 50,
                                                         principal.tenant if principal is not None else "\0")
                        prefix = (principal.tenant + "/") if principal is not None else "\0"
                        recent = [{**r, "session_id": r["session_id"][len(prefix):]}
                                  if isinstance(r.get("session_id"), str) and r["session_id"].startswith(prefix) else r
                                  for r in recent]
                    else:
                        recent = await asyncio.to_thread(self.store.recent_resolved, 50)
                except Exception:
                    logger.exception("inbox: could not read the recent history from the event log")
            caps = await asyncio.to_thread(self._capabilities, principal) if self.identity_mode \
                else await asyncio.to_thread(self._capabilities)
            try:
                await asyncio.wait_for(ui.peer.send_json(self.snapshot(recent, caps, principal)), UI_SEND_TIMEOUT_S)
            except Exception:
                logger.warning("inbox: could not send the snapshot to a UI; closing it")
                ui.dead = True
                if ui in self._uis:
                    self._uis.remove(ui)
        if ui.dead:
            await ui.close()
        return ui

    def ui_disconnected(self, ui: _Peer) -> None:
        if ui in self._uis:
            self._uis.remove(ui)

    # ------------------------------------------------------------------ standing rules (OP4)
    def _find_call(self, sid: Any, call_id: Any, tenant: str | None = None):
        """(server, tool, args) of a call this hub saw in THAT session (pending or the in-memory ring), else None."""
        if not isinstance(sid, str) or not isinstance(call_id, str):
            return None
        s = self.sessions.get((tenant or "default", sid))             # another tenant's session is simply unknown
        if s is None:
            return None
        p = s.pending.get(call_id)
        if p is not None:
            return p.server, p.tool, p.args
        for item in reversed(s.ring):
            if item["call_id"] == call_id:
                return item["server"], item["tool"], item["args"]
        return None

    def _writable_policy(self, principal: Any = None):
        """-> (path, digest_before) when standing rules may be written, else None. Reads the file: run in a thread."""
        if (os.environ.get("SENTINEL_POLICY_WRITABLE") or "").strip() != "1":
            return None
        path = self._policy_path_for(principal)
        if not path:
            return None
        pol = policy_mod.load_policy_file(path)[0]
        return (path, pol.digest()) if pol is not None else None

    async def _rule_result(self, ok: bool, reason: str, rule_id: str | None = None, digest: str | None = None,
                           tenant: str | None = None) -> None:
        await self._broadcast({"event": "inbox_rule_result", "ok": ok, "rule_id": rule_id, "reason": reason,
                               "policy_digest": digest, "applies": "new_sessions"}, tenant)

    async def _rule_request(self, frame: dict, ui: Any = None) -> None:
        principal = getattr(ui, "principal", None)
        tenant = principal.tenant if principal is not None else None
        now = time.monotonic()
        while self._rule_times and now - self._rule_times[0] > RULE_RATE_WINDOW_S:
            self._rule_times.popleft()
        if len(self._rule_times) >= RULE_RATE_LIMIT:
            await self._rule_result(False, "rate_limited", tenant=tenant)
            return
        self._rule_times.append(now)
        try:
            await self._rule_request_inner(frame, principal, ui)
        except Exception:
            logger.exception("inbox: unexpected error while adding a standing rule")
            await self._rule_result(False, "write_failed", tenant=tenant)

    async def _rule_request_inner(self, frame: dict, principal: Any = None, ui: Any = None) -> None:
        tenant = principal.tenant if principal is not None else None
        rr = lambda ok, reason, rid=None, dg=None: self._rule_result(ok, reason, rid, dg, tenant)       # noqa: E731
        async with self._rule_lock:            # one rule write at a time: digest_before is the digest of what we then change
            target = await asyncio.to_thread(self._writable_policy, principal)
            if target is None:
                return await rr(False, "not_writable")
            if frame.get("confirm") is not True:
                return await rr(False, "not_confirmed")
            sid, call_id = frame.get("session_id"), frame.get("call_id")
            found = self._find_call(sid, call_id, tenant)
            if found is None:
                return await rr(False, "unknown_call")
            server, tool, args = found
            if principal is not None and not identity_mod.can(principal, "rules", server=server, tenant=tenant):
                return await self._forbidden(ui, "rules", "server")
            path, digest_before = target
            note = f"added from the Inbox (session {sid}, call {safe_text.clean_field(call_id, 64)})"[:200]
            try:
                rule = await asyncio.to_thread(policy_writer.build_rule, frame.get("verdict"), frame.get("scope"),
                                               server, tool, args, note=note)
            except ValueError as exc:
                reason = str(exc) if str(exc) in ("cannot_build", "scope_not_allowed") else "cannot_build"
                return await rr(False, reason)
            # write-ahead: the event is on disk BEFORE the policy file changes; no log, no change
            if self.store is not None:
                res = await self._append("policy_rule_added", (f"{tenant}/{sid}" if principal is not None else sid), call_id,
                                         {"rule": rule, "digest_before": digest_before, "session_id": sid, "call_id": call_id})
                if res != "ok":
                    return await rr(False, "log_unavailable")
            try:
                out = await asyncio.to_thread(policy_writer.append_rule, path, rule)
            except policy_writer.PolicyWriteError as exc:
                reason = exc.reason if exc.reason in ("invalid_policy", "write_failed") else "write_failed"
                logger.error("inbox: standing rule not written (%s)", reason)
                return await rr(False, reason)
            logger.info("inbox: standing rule %s added (policy digest %s -> %s); applies to NEW sessions",
                        out.get("rule_id"), out.get("digest_before"), out.get("digest_after"))
            await rr(True, "ok", out.get("rule_id"), out.get("digest_after"))

    async def _forbidden(self, ui: Any, action: str, reason: str) -> None:
        """Answer THAT connection only; nothing changes."""
        if ui is not None:
            await ui.send({"event": "inbox_forbidden", "action": action, "reason": reason})

    async def handle_ui_frame(self, frame: Any, ui: Any = None) -> None:
        """Only inbox_decision / inbox_rule_request do anything. Never raises, never approves anything but the exact string
        'approve'. session_id is REQUIRED: the decision resolves only that session's call. Identity mode: `ui` carries the
        principal (role, tenant, server allowlist); another tenant's call is ignored exactly like an unknown one."""
        principal = getattr(ui, "principal", None)
        if self.identity_mode and principal is None:
            logger.warning("inbox: ignoring a UI frame from an unauthenticated connection")
            return
        if isinstance(frame, dict) and frame.get("event") == "inbox_rule_request":
            if principal is not None and principal.role != "admin":
                return await self._forbidden(ui, "rules", "role")
            await self._rule_request(frame, ui)
            return
        if not isinstance(frame, dict) or frame.get("event") != "inbox_decision":
            logger.warning("inbox: ignoring a UI frame that is not an inbox_decision")
            return
        if principal is not None and principal.role not in ("approver", "admin"):
            return await self._forbidden(ui, "decide", "role")
        sid, call_id, decision = frame.get("session_id"), frame.get("call_id"), frame.get("decision")
        if (not isinstance(sid, str) or not isinstance(call_id, str) or not isinstance(decision, str)
                or decision not in ("approve", "deny")):
            logger.warning("inbox: ignoring an invalid inbox_decision")
            return
        s = self.sessions.get((principal.tenant if principal is not None else "default", sid))    # other tenants: unknown
        p = s.pending.get(call_id) if s is not None else None
        if p is None:
            logger.info("inbox: decision for an unknown or already resolved call ignored")
            return
        if principal is not None and not identity_mod.can(principal, "decide", server=p.server, tenant=s.tenant):
            return await self._forbidden(ui, "decide", "server")
        if p.claim(decision, "human"):
            p.operator = principal.id if principal is not None else None
            if decision == "deny":
                p.note = clean_note(frame.get("note"))


# ---------------------------------------------------------------------- socket loops (duck-typed websocket)
async def _recv(ws: Any) -> Any:
    """-> raw text/bytes frame; raises on disconnect."""
    msg = await ws.receive()
    if msg.get("type") == "websocket.disconnect":
        raise ConnectionError("disconnected")
    return msg.get("text") if msg.get("text") is not None else msg.get("bytes")


async def _authenticate(hub: InboxHub, ws: Any, kind: str):
    """Identity mode only. Credential: `Authorization: Bearer ...` header, else a first frame {"event":"auth","token":...} within
    5 s. -> (Principal | None, reason). `?token=` is never looked at. Never raises."""
    try:
        if hub.identity is None:                       # SENTINEL_IDENTITY_FILE was set but unusable: refuse everyone
            return None, "unauthorized"
        cred = None
        header = ws.headers.get("authorization") if getattr(ws, "headers", None) is not None else None
        if isinstance(header, str) and header[:7].lower() == "bearer ":
            cred = header[7:].strip()
        else:
            try:
                raw = await asyncio.wait_for(_recv(ws), AUTH_FRAME_TIMEOUT_S)
            except Exception:
                return None, "timeout"
            frame = parse_frame(raw)
            if isinstance(frame, dict) and frame.get("event") == "auth" and isinstance(frame.get("token"), str):
                cred = frame["token"]
        client = getattr(ws, "client", None)
        remote = getattr(client, "host", None)
        principal, reason = await asyncio.to_thread(hub.identity.authenticate_ex, kind, cred, remote)
        if principal is None:
            await hub.audit_auth_failure(kind, reason, remote)
            return None, "throttled" if reason == "throttled" else "unauthorized"
        return principal, "ok"
    except Exception:
        logger.exception("inbox: authentication failed unexpectedly")
        return None, "unauthorized"


async def serve_proxy(hub: InboxHub, ws: Any) -> None:
    """Drive an ACCEPTED proxy websocket until it closes. Never raises."""
    session = None
    try:
        principal = None
        if hub.identity_mode:
            principal, why = await _authenticate(hub, ws, "agent")
            if principal is None:
                if why != "timeout":
                    try:
                        await ws.send_json({"event": "hello_reject", "reason": "unauthorized"})
                    except Exception:
                        pass
                try:
                    await ws.close(1008)
                except Exception:
                    pass
                return
        try:
            raw = await asyncio.wait_for(_recv(ws), HELLO_TIMEOUT_S)
        except Exception:
            return
        session = await hub.proxy_hello(ws, parse_frame(raw), principal)
        if session is None:
            return
        while True:
            frame = parse_frame(await _recv(ws))
            if frame is None:
                logger.warning("inbox: proxy %s sent an unparseable or oversize frame; closing", session.session_id)
                break
            if not await hub.handle_proxy_frame(session, frame):
                break
    except Exception:
        logger.info("inbox: proxy socket ended")
    finally:
        if session is not None:
            # cleanup must finish even if this handler is being cancelled (server shutdown, test client teardown)
            cleanup = asyncio.ensure_future(hub.proxy_closed(session))
            try:
                await asyncio.shield(cleanup)
            except BaseException:
                logger.info("inbox: proxy cleanup continues in the background")
        try:
            await ws.close()
        except Exception:
            pass


async def serve_ui(hub: InboxHub, ws: Any) -> None:
    """Drive an ACCEPTED UI websocket until it closes. Never raises; a UI going away never affects pending calls."""
    ui = None
    try:
        principal = None
        if hub.identity_mode:
            principal, why = await _authenticate(hub, ws, "operator")
            if principal is None:
                if why != "timeout":
                    try:
                        await ws.send_json({"event": "auth_error", "reason": why})
                    except Exception:
                        pass
                try:
                    await ws.close(1008)
                except Exception:
                    pass
                return
            await ws.send_json({"event": "auth_ok", "principal": {"id": principal.id, "tenant": principal.tenant,
                                                                  "role": principal.role}})
        ui = await hub.ui_connected(ws, principal)
        while True:
            frame = parse_frame(await _recv(ws))
            if frame is None:
                logger.warning("inbox: UI sent an unparseable or oversize frame; ignoring")
                continue
            await hub.handle_ui_frame(frame, ui)
    except Exception:
        logger.info("inbox: UI socket ended")
    finally:
        if ui is not None:
            hub.ui_disconnected(ui)
        try:
            await ws.close()
        except Exception:
            pass
