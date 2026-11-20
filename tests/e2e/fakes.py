"""Test doubles and helpers for the X1 black-box acceptance tests.

Everything here is derived from docs/modules/SPEC.md, DECISIONS.md and
frontend/src/types/contracts.ts only.  Nothing depends on agent_loop internals.
"""
from __future__ import annotations

import json
import math
import re
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable

import httpx
import openai
import pytest
from starlette.websockets import WebSocketDisconnect

REPO = Path(__file__).resolve().parents[2]
CONTRACTS_TS = REPO / "frontend" / "src" / "types" / "contracts.ts"

TERMINAL_EVENTS = ("session_complete", "error")


# ---------------------------------------------------------------------------
# openai-shaped fake client
# ---------------------------------------------------------------------------

class _Obj:
    """Attribute bag that also offers the pydantic-ish helpers openai objects have."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def model_dump(self, **_):
        out = {}
        for k, v in self.__dict__.items():
            if isinstance(v, _Obj):
                v = v.model_dump()
            elif isinstance(v, list):
                v = [i.model_dump() if isinstance(i, _Obj) else i for i in v]
            out[k] = v
        return out


def call(name: str, args: dict | None = None, id: str | None = None) -> _Obj:
    return _Obj(
        id=id or f"call_{name}",
        type="function",
        function=_Obj(name=name, arguments=json.dumps(args or {})),
    )


def turn(content: str | None = None, tool_calls: Iterable[_Obj] | None = None) -> _Obj:
    """One assistant turn: content and/or tool calls."""
    tcs = list(tool_calls) if tool_calls else None
    msg = _Obj(role="assistant", content=content, tool_calls=tcs)
    choice = _Obj(
        index=0, message=msg, finish_reason="tool_calls" if tcs else "stop"
    )
    return _Obj(id="chatcmpl-fake", model="fake-model", choices=[choice], usage=None)


def _req() -> httpx.Request:
    return httpx.Request("POST", "http://fake.invalid/v1/chat/completions")


def auth_error(msg: str = "Incorrect API key provided") -> Exception:
    return openai.AuthenticationError(
        msg, response=httpx.Response(401, request=_req()), body=None
    )


def transient_error(kind: str = "connection") -> Exception:
    if kind == "timeout":
        return openai.APITimeoutError(request=_req())
    return openai.APIConnectionError(request=_req())


class FakeClient:
    """Replays a script. Entries are turn(...) objects or exceptions to raise.

    When the script is exhausted it answers with a plain-text final turn so a
    misbehaving loop cannot spin forever on an empty script.
    """

    def __init__(self, script: Iterable[Any]):
        self.script = list(script)
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script.pop(0) if self.script else turn("All done.")
        if isinstance(item, BaseException):
            raise item
        return item


# ---------------------------------------------------------------------------
# contracts.ts parser + validator
# ---------------------------------------------------------------------------

def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _match_brace(s: str, start: int) -> int:
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced braces")


def _split_top(s: str, seps: str) -> list[str]:
    parts, depth, cur, quote = [], 0, [], None
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "{<([":
            depth += 1
            cur.append(ch)
        elif ch in "}>)]":
            depth -= 1
            cur.append(ch)
        elif ch in seps and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def parse_fields(body: str) -> dict[str, tuple[bool, str]]:
    """'a: string; b?: number' -> {'a': (required, 'string'), ...}"""
    fields = {}
    for chunk in _split_top(body, ";\n"):
        m = re.match(r"^(\w+)(\?)?\s*:\s*(.+)$", chunk, flags=re.S)
        assert m, f"cannot parse contract field: {chunk!r}"
        fields[m.group(1)] = (m.group(2) is None, " ".join(m.group(3).split()))
    return fields


def load_contract() -> tuple[dict[str, dict], dict[str, str], list[str]]:
    """Returns (events_by_name, type_aliases, server_event_names)."""
    src = _strip_comments(CONTRACTS_TS.read_text())
    aliases = {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"export type (\w+)\s*=\s*([^;]+);", src)
        if m.group(1) not in ("ServerEvent", "ClientMessage")
    }
    by_iface: dict[str, dict] = {}
    for m in re.finditer(r"export interface (\w+)\s*\{", src):
        end = _match_brace(src, m.end() - 1)
        by_iface[m.group(1)] = parse_fields(src[m.end(): end])
    union = re.search(r"export type ServerEvent\s*=([^;]+);", src).group(1)
    server_ifaces = [n.strip() for n in union.split("|") if n.strip()]
    events = {}
    for iface in server_ifaces:
        name = by_iface[iface]["event"][1].strip('"')
        events[name] = by_iface[iface]
    # task_complete is a legacy mock-server-only alias: the real server must not send it.
    server_names = [n for n in events if n != "task_complete"]
    return events, aliases, server_names


EVENTS, ALIASES, SERVER_EVENT_NAMES = load_contract()


def _check_type(t: str, v: Any, path: str) -> list[str]:
    t = t.strip()
    alts = _split_top(t, "|")
    if len(alts) > 1:
        errs = [_check_type(a, v, path) for a in alts]
        return [] if any(not e for e in errs) else [f"{path}: {v!r} matches none of {t}"]
    if t in ALIASES:
        return _check_type(ALIASES[t], v, path)
    if t == "string":
        return [] if isinstance(v, str) else [f"{path}: expected string, got {v!r}"]
    if t == "number":
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
        return [] if ok else [f"{path}: expected finite number, got {v!r}"]
    if t == "boolean":
        return [] if isinstance(v, bool) else [f"{path}: expected boolean, got {v!r}"]
    if t == "null":
        return [] if v is None else [f"{path}: expected null, got {v!r}"]
    if t == "unknown":
        return []
    if t.startswith("Record<"):
        return [] if isinstance(v, dict) else [f"{path}: expected object, got {v!r}"]
    if t[0] in "\"'":
        return [] if v == t.strip("\"'") else [f"{path}: expected {t}, got {v!r}"]
    if t.startswith("{"):
        return _check_fields(parse_fields(t[1:-1]), v, path)
    raise AssertionError(f"unsupported contract type expression {t!r}")


def _check_fields(fields: dict, obj: Any, path: str) -> list[str]:
    if not isinstance(obj, dict):
        return [f"{path}: expected object, got {obj!r}"]
    errs = []
    for k, (required, t) in fields.items():
        if k not in obj:
            if required:
                errs.append(f"{path}.{k}: missing")
            continue
        errs += _check_type(t, obj[k], f"{path}.{k}")
    for k in obj:
        if k not in fields:
            errs.append(f"{path}.{k}: not in contract")
    return errs


def validate_event(ev: Any) -> list[str]:
    """Empty list == the event conforms to contracts.ts (exact key set + types)."""
    if not isinstance(ev, dict) or "event" not in ev:
        return [f"not an event object: {ev!r}"]
    name = ev["event"]
    if name not in SERVER_EVENT_NAMES:
        return [f"event {name!r} is not a server event in contracts.ts"]
    return _check_fields(EVENTS[name], ev, name)


# ---------------------------------------------------------------------------
# Guarded websocket driving (a hung server FAILS the test, never hangs it)
# ---------------------------------------------------------------------------

def guarded(fn: Callable[[], Any], timeout: float = 8.0, what: str = "session", progress=None):
    """Run fn in a daemon thread; fail the test if it does not finish in time."""
    box: dict[str, Any] = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            box["error"] = e

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        tail = ""
        if progress is not None:
            tail = f"; events so far: {[e.get('event') if isinstance(e, dict) else e for e in progress]}"
        pytest.fail(f"{what} hung: no completion within {timeout}s{tail}")
    if "error" in box:
        raise box["error"]
    return box.get("value")


START = {
    "event": "start_task",
    "task": "Summarize the project files",
    "scenario": "aligned",
    "model": "fake",
    "mode": "live",
}


def start_msg(**over) -> dict:
    return {**START, **over}


class Events(list):
    """Received events; `.closed` is True/False after a terminal event."""

    closed: bool | None = None


TERMINAL_GRACE_S = 0.2


def _grace_receive(ws, wait: float):
    """One receive bounded by `wait`: ('event', ev) | ('closed', None) | ('open', None)."""
    box: dict = {}

    def target():
        try:
            box["ev"] = ws.receive_json()
        except BaseException:  # noqa: BLE001 - disconnect / socket torn down
            box["closed"] = True

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(wait)
    if th.is_alive():
        return "open", None
    return ("closed", None) if "closed" in box else ("event", box["ev"])


def drive(ws, policy: Callable[[dict, list], Iterable[Any]] | None, events: Events) -> Events:
    """Receive until the server closes the socket, or until a terminal event has
    been seen and the server then stays quiet for TERMINAL_GRACE_S (so a server
    that forgets to close does not slow every test; `events.closed` records it).

    policy(event, events_so_far) -> messages to send in response.
    """
    while True:
        try:
            ev = ws.receive_json()
        except WebSocketDisconnect:
            events.closed = True
            return events
        events.append(ev)
        if isinstance(ev, dict) and ev.get("event") in TERMINAL_EVENTS:
            while True:
                kind, extra = _grace_receive(ws, TERMINAL_GRACE_S)
                if kind == "event":
                    events.append(extra)  # anything after a terminal is a violation
                    continue
                events.closed = kind == "closed"
                return events
        if policy and isinstance(ev, dict):
            for msg in policy(ev, events) or ():
                ws.send_json(msg)


def approve_all(ev, events):
    if ev.get("event") == "tool_pending":
        return [decision(ev["node_id"], "approve")]
    return ()


def deny_all(ev, events):
    if ev.get("event") == "tool_pending":
        return [decision(ev["node_id"], "deny")]
    return ()


def decision(node_id: str, value: Any) -> dict:
    return {"event": "tool_decision", "node_id": node_id, "decision": value}


def run_session(client, policy=None, *, first=None, url="/ws", headers=None,
                timeout: float = 8.0, send_start: bool = True) -> list[dict]:
    """Connect, send the first message, drive to disconnect. Returns every event."""
    events = Events()

    def body():
        kw = {"headers": headers} if headers else {}
        with client.websocket_connect(url, **kw) as ws:
            if send_start:
                ws.send_json(first if first is not None else start_msg())
            return drive(ws, policy, events)

    guarded(body, timeout, progress=events)
    return events


def of(events: list, name: str) -> list[dict]:
    return [e for e in events if isinstance(e, dict) and e.get("event") == name]


def terminals(events: list) -> list[dict]:
    return [e for e in events if isinstance(e, dict) and e.get("event") in TERMINAL_EVENTS]
