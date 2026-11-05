"""WebSocket link to the SENTINEL backend hub (/proxy/ws). Fail-closed by construction."""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from typing import Any

from websockets.asyncio.client import connect

from sentinel_proxy.config import strip_query

_KNOWN_REASONS = {"human", "auto", "timeout", "invalid", "disconnected", "duplicate"}
UNREACHABLE = "SENTINEL backend unreachable"
LOST = "SENTINEL backend connection lost"


def log(msg: str) -> None:
    print(f"[sentinel-proxy] {msg}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class Decision:
    approved: bool
    reason: str


class BackendLink:
    def __init__(self, url: str, hello: dict[str, Any], *, call_timeout_s: float = 330.0):
        self._url = url
        self._hello = hello
        self._call_timeout = call_timeout_s
        self._ws: Any = None
        self._connected = False
        self._ever_connected = False
        self._pending: dict[str, asyncio.Future[Decision]] = {}
        self.ready = asyncio.Event()
        self.fatal = asyncio.Event()
        self.fatal_reason = ""

    @property
    def connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------ connection
    async def run(self) -> None:
        delay = 0.5
        while not self.fatal.is_set():
            try:
                async with connect(self._url, open_timeout=5, max_size=1 << 20) as ws:
                    await ws.send(json.dumps(self._hello))
                    first = _parse(await asyncio.wait_for(ws.recv(), 10))
                    ev = first.get("event") if first else None
                    if ev == "hello_reject":
                        reason = str(first.get("reason", "unknown"))[:80]
                        if reason == "duplicate_session_id" and self._ever_connected:
                            log("hello rejected (duplicate_session_id) after a reconnect; retrying")
                            raise ConnectionError("duplicate session on reconnect")
                        self.fatal_reason = f"backend rejected hello: {reason}"
                        self.fatal.set()
                        return
                    if ev != "hello_ack":
                        raise ConnectionError("unexpected first frame from backend")
                    self._ws, self._connected, self._ever_connected = ws, True, True
                    self.ready.set()
                    delay = 0.5
                    log(f"connected to {strip_query(self._url)}")
                    async for msg in ws:
                        self._on_frame(msg)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # connection refused, dropped, timeout, bad frame...
                log(f"backend link down: {type(e).__name__}: {e}")
            finally:
                self._drop()
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10.0)

    def _drop(self) -> None:
        self._connected = False
        self._ws = None
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_result(Decision(False, LOST))
        self._pending.clear()

    def _on_frame(self, msg: Any) -> None:
        frame = _parse(msg)
        if frame is None:
            log("ignoring malformed backend frame")
            return
        if frame.get("event") != "proxy_decision":
            log(f"ignoring backend event {str(frame.get('event'))[:40]!r}")
            return
        cid = frame.get("call_id")
        fut = self._pending.get(cid) if isinstance(cid, str) else None
        if fut is None or fut.done():
            log("ignoring decision for unknown call_id")
            return
        reason = frame.get("reason")
        reason = reason if reason in _KNOWN_REASONS else "invalid"
        # Only the exact string "approve" approves.
        fut.set_result(Decision(frame.get("decision") == "approve", reason))

    async def wait_started(self, timeout: float) -> None:
        """Wait up to `timeout` for the first hello_ack (or a fatal reject)."""
        waiters = [asyncio.ensure_future(self.ready.wait()), asyncio.ensure_future(self.fatal.wait())]
        try:
            await asyncio.wait(waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waiters:
                w.cancel()

    # ------------------------------------------------------------ calls
    async def decide(self, call: dict[str, Any]) -> Decision:
        ws = self._ws
        if not self._connected or ws is None:
            return Decision(False, UNREACHABLE)
        cid = call["call_id"]
        fut: asyncio.Future[Decision] = asyncio.get_running_loop().create_future()
        self._pending[cid] = fut
        try:
            await ws.send(json.dumps(call))
            return await asyncio.wait_for(fut, self._call_timeout)
        except asyncio.TimeoutError:
            return Decision(False, "timeout")
        except asyncio.CancelledError:
            raise
        except Exception:
            return Decision(False, LOST)
        finally:
            self._pending.pop(cid, None)

    async def send_result(self, call_id: str, status: str, summary: str) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            await ws.send(json.dumps({"event": "proxy_result", "call_id": call_id, "status": status, "summary": summary}))
        except Exception as e:
            log(f"could not send proxy_result: {type(e).__name__}")


def _parse(msg: Any) -> dict[str, Any] | None:
    if not isinstance(msg, str):
        return None
    try:
        v = json.loads(msg)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None
