"""InboxHub: approval inbox for external (MCP proxy) sessions. See docs/plans/PROPOSAL-1-mcp-proxy.md (wire protocol).

Pure asyncio, no FastAPI imports. Peers are duck-typed: ``await peer.send_json(dict)`` and ``await peer.close(code)``.
Fail-closed: anything that is not the exact string "approve" from a human is a deny; a timeout, a proxy disconnect, a
duplicate or an invalid call is a deny. Frames are never trusted: nothing a peer sends can raise out of the hub, and
exception text is never sent to a peer (it goes to the log only).
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import eventlog
import gate
import policy as policy_mod
import proposal_monitor
import safe_text

logger = logging.getLogger(__name__)

_logged_policy_problems: set = set()


def _resolve_policy():
    """-> (policy_mode, Policy | None, registry | None). SENTINEL_POLICY unset => (False, None, None): legacy behaviour.
    Set but unusable => (True, None, ...): a BROKEN policy, every call is `ask`. Never raises."""
    path = (os.environ.get("SENTINEL_POLICY") or "").strip()
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
    cancelled: bool = False       # resolved by the proxy's proxy_cancel (not a human decision)

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

    def reserve(self, call_id: str) -> bool:
        """Synchronous duplicate check + registration (no await in between). False: already seen."""
        if call_id in self.seen:
            return False
        self.seen.add(call_id)
        self.seen_order.append(call_id)
        while len(self.seen_order) > MAX_SEEN:
            self.seen.discard(self.seen_order.popleft())
        return True


class InboxHub:
    def __init__(self, gate_timeout: float | None = None, monitor_factory: Callable[[], Any] | None = None,
                 store: Any = None):
        self._timeout = float(gate.GATE_TIMEOUT_S if gate_timeout is None else gate_timeout)
        self._monitor_factory = monitor_factory
        self.sessions: dict[str, ProxySession] = {}
        self._uis: list[_Peer] = []
        self._bg: set = set()
        self.store = store                 # durable event log (eventlog.EventStore-like) or None: legacy behaviour
        self.log_unusable = False          # a log was configured but could not be opened: refuse every session
        self.log_path: str | None = None
        self.log_keyed = False
        self._log_events: int | None = None   # last known seq (cached for /health; never verify() there)
        if store is not None:
            self._log_events = 0

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
                            rule_id: str | None, digest: str | None):
        """Write the decision record BEFORE anything is sent. -> (decision, reason, actor) EFFECTIVE, or None if the
        decision was already recorded (duplicate: ignore). An approve that cannot be recorded becomes deny/log_unavailable."""
        payload = {"decision": decision, "reason": reason, "actor": actor, "rule_id": rule_id, "policy_digest": digest}
        res = await self._append("decision", session.session_id, call_id, payload)
        if res == "dup":
            return None
        if res == "fail":
            if decision == "approve":
                decision, reason, actor = "deny", "log_unavailable", "system"
                await self._append("decision", session.session_id, call_id,
                                   {**payload, "decision": decision, "reason": reason, "actor": actor})   # best effort
        return decision, reason, actor

    @staticmethod
    def _alert_records(alerts: list) -> list:
        out = []
        for a in alerts:
            if isinstance(a, dict):
                out.append({"severity": a.get("severity"), "trigger": a.get("trigger"), "score": a.get("drift_score"),
                            "threshold": a.get("threshold"), "message": a.get("message")})
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

    @staticmethod
    def _pending_payload(p: _Pending, deadline_s: float) -> dict:
        d = {"session_id": p.session.session_id, "call_id": p.call_id, "server": p.server, "tool": p.tool,
             "args": p.args, "auto": p.auto, "alerts": p.alerts, "deadline_s": deadline_s}
        if p.policy_mode:
            d["rule_id"], d["policy_digest"] = p.rule_id, p.policy_digest
        return d

    @staticmethod
    def _policy_fields(p: _Pending) -> dict:
        return {"rule_id": p.rule_id, "policy_digest": p.policy_digest} if p.policy_mode else {}

    async def _broadcast(self, payload: dict) -> None:
        uis = list(self._uis)
        if not uis:
            return
        results = await asyncio.gather(*(u.send(payload) for u in uis), return_exceptions=True)
        for u, ok in zip(uis, results):
            if ok is not True and u in self._uis:
                self._uis.remove(u)

    # ------------------------------------------------------------------ proxy side
    async def proxy_hello(self, peer: Any, frame: Any) -> ProxySession | None:
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
        if self.log_unusable:
            return await reject("log_unavailable")
        live = self.sessions.get(sid)
        if live is not None and not live.closed:
            return await reject("duplicate_session_id")
        session = ProxySession(sid, list(servers), list(auto_approve), conn)
        self.sessions[sid] = session          # claimed before any await: a racing second hello sees it
        try:
            session.policy_mode, session.policy, session.policy_registry = await asyncio.to_thread(_resolve_policy)
        except Exception:
            logger.exception("inbox: policy resolution failed; treating the policy as broken")
            session.policy_mode, session.policy, session.policy_registry = True, None, None
        try:
            session.monitor = await asyncio.to_thread(self._new_monitor)
        except Exception:
            logger.exception("inbox: could not build a monitor for session %s; auto calls will be held", sid)
            session.monitor = None
        if self.store is not None:         # write-ahead: the hello is on disk before the ack
            res = await self._append("proxy_hello", sid, None, self._hello_payload(session))
            if res != "ok":
                if self.sessions.get(sid) is session:
                    del self.sessions[sid]
                session.closed = True
                return await reject("log_unavailable")
            session.logged_hello = True
        if not await conn.send({"event": "hello_ack", "session_id": sid}):
            await self.proxy_closed(session)
            return None
        self._spawn(self._broadcast({"event": "inbox_session", "session_id": sid, "state": "open"}))
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
                "registry_digest": reg_digest, "frozen_model_sha256": frozen}

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

    async def _reply(self, session: ProxySession, call_id: str, decision: str, reason: str) -> None:
        await session.conn.send({"event": "proxy_decision", "call_id": call_id, "decision": decision, "reason": reason})

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
        if session.closed:
            await self._register(session, tool, args, "deny")
            return

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
                                                  registry=session.policy_registry, alerts_present=bool(alerts))
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
        elif auto and working and not alerts:
            immediate = ("approve", "auto", "auto")

        # write-ahead: call_proposed is on disk before inbox_pending / any auto or policy reply
        res = await self._append("call_proposed", sid, call_id,
                                 {"server": server, "tool": tool, "args": args, "auto": auto,
                                  "alerts": self._alert_records(alerts), "policy": policy_rec})
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
            await self._register(session, tool, args, decision)
            await self._reply(session, call_id, decision, reason)
            await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                                   "decision": decision, "reason": reason, **pol_fields})
            return

        # held for a human: not auto, or auto with an alert, or auto with a degraded monitor (fail closed)
        p = _Pending(session, call_id, server, tool, args, auto, alerts, rule_id=rule_id, policy_digest=digest,
                     policy_mode=session.policy_mode)
        session.pending[call_id] = p
        session.starting.discard(call_id)
        # the decision timer starts NOW; the broadcast runs beside it and cannot delay it
        announce = self._spawn(self._broadcast({"event": "inbox_pending", **self._pending_payload(p, self._timeout)}))
        try:
            await asyncio.wait_for(p.event.wait(), self._timeout)
        except asyncio.TimeoutError:
            p.claim("deny", "timeout")
        session.pending.pop(call_id, None)
        if p.cancelled:                  # proxy_cancel: no proxy_decision, no monitor registration
            eff = await self._log_decision(session, call_id, "deny", p.reason or "cancelled", "system", rule_id, digest)
            await asyncio.gather(announce, return_exceptions=True)
            if eff is None:
                return
            await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                                   "decision": "deny", "reason": p.reason, **self._policy_fields(p)})
            return
        decision, reason = ("approve" if p.decision == "approve" else "deny"), p.reason or "invalid"
        actor = "human" if reason == "human" else "system"
        eff = await self._log_decision(session, call_id, decision, reason, actor, rule_id, digest)
        if eff is None:
            await asyncio.gather(announce, return_exceptions=True)
            return
        decision, reason, _actor = eff
        await self._register(session, tool, args, decision)
        await self._reply(session, call_id, decision, reason)
        await asyncio.gather(announce, return_exceptions=True)       # pending before resolved on every UI
        await self._broadcast({"event": "inbox_resolved", "session_id": sid, "call_id": call_id,
                               "decision": decision, "reason": reason, **self._policy_fields(p)})

    async def _forward_result(self, session: ProxySession, frame: dict) -> None:
        call_id, status = frame.get("call_id"), frame.get("status")
        if not _is_str(call_id, MAX_CALL_ID, min_len=1) or call_id not in session.seen or status not in ("ok", "error"):
            logger.warning("inbox: ignoring a malformed or unknown proxy_result from %s", session.session_id)
            return
        summary = safe_text.clean_field(frame.get("summary", "") if isinstance(frame.get("summary"), str) else "",
                                        SUMMARY_LIMIT)
        if self.store is not None:         # best effort: never raises into the call path
            await self._append("call_result", session.session_id, call_id, {"status": status, "summary": summary})
        await self._broadcast({"event": "inbox_result", "session_id": session.session_id, "call_id": call_id,
                               "status": status, "summary": summary})

    async def proxy_closed(self, session: ProxySession) -> None:
        """The proxy went away: every pending call of the session is a deny/disconnected."""
        if session.closed:
            return
        session.closed = True
        for p in list(session.pending.values()):
            p.claim("deny", "disconnected")
        if session.tasks:
            await asyncio.gather(*list(session.tasks), return_exceptions=True)
        if self.sessions.get(session.session_id) is session:
            del self.sessions[session.session_id]
        if session.logged_hello:
            await self._append("proxy_close", session.session_id, None, {"reason": "disconnected"})   # best effort
        await self._broadcast({"event": "inbox_session", "session_id": session.session_id, "state": "closed"})

    # ------------------------------------------------------------------ UI side
    def snapshot(self, recent: list | None = None) -> dict:
        sessions = []
        for s in self.sessions.values():
            pend = []
            for p in s.pending.values():
                d = self._pending_payload(p, self._timeout)
                pend.append(d)
            sessions.append({"session_id": s.session_id, "servers": s.servers, "pending": pend})
        return {"event": "inbox_snapshot", "sessions": sessions, "recent": list(recent or [])}

    async def ui_connected(self, peer: Any) -> _Peer:
        ui = _Peer(peer, UI_SEND_TIMEOUT_S)
        self._uis.append(ui)
        recent: list = []
        if self.store is not None:
            try:
                recent = await asyncio.to_thread(self.store.recent_resolved, 50)
            except Exception:
                logger.exception("inbox: could not read the recent history from the event log")
        if not await ui.send(self.snapshot(recent)) and ui in self._uis:
            self._uis.remove(ui)
        return ui

    def ui_disconnected(self, ui: _Peer) -> None:
        if ui in self._uis:
            self._uis.remove(ui)

    async def handle_ui_frame(self, frame: Any) -> None:
        """Only inbox_decision does anything. Never raises, never approves anything but the exact string 'approve'.
        session_id is REQUIRED: the decision resolves only that session's call."""
        if not isinstance(frame, dict) or frame.get("event") != "inbox_decision":
            logger.warning("inbox: ignoring a UI frame that is not an inbox_decision")
            return
        sid, call_id, decision = frame.get("session_id"), frame.get("call_id"), frame.get("decision")
        if (not isinstance(sid, str) or not isinstance(call_id, str) or not isinstance(decision, str)
                or decision not in ("approve", "deny")):
            logger.warning("inbox: ignoring an invalid inbox_decision")
            return
        s = self.sessions.get(sid)
        p = s.pending.get(call_id) if s is not None else None
        if p is None:
            logger.info("inbox: decision for an unknown or already resolved call ignored")
            return
        p.claim(decision, "human")


# ---------------------------------------------------------------------- socket loops (duck-typed websocket)
async def _recv(ws: Any) -> Any:
    """-> raw text/bytes frame; raises on disconnect."""
    msg = await ws.receive()
    if msg.get("type") == "websocket.disconnect":
        raise ConnectionError("disconnected")
    return msg.get("text") if msg.get("text") is not None else msg.get("bytes")


async def serve_proxy(hub: InboxHub, ws: Any) -> None:
    """Drive an ACCEPTED proxy websocket until it closes. Never raises."""
    session = None
    try:
        try:
            raw = await asyncio.wait_for(_recv(ws), HELLO_TIMEOUT_S)
        except Exception:
            return
        session = await hub.proxy_hello(ws, parse_frame(raw))
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
        ui = await hub.ui_connected(ws)
        while True:
            frame = parse_frame(await _recv(ws))
            if frame is None:
                logger.warning("inbox: UI sent an unparseable or oversize frame; ignoring")
                continue
            await hub.handle_ui_frame(frame)
    except Exception:
        logger.info("inbox: UI socket ended")
    finally:
        if ui is not None:
            hub.ui_disconnected(ui)
        try:
            await ws.close()
        except Exception:
            pass
