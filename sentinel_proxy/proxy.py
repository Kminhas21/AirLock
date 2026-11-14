"""MCP server (toward the agent) + MCP clients (toward downstream servers) with the approval gate."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

import anyio

import mcp_types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel.server import Server
from mcp.shared.exceptions import MCPError

from sentinel_proxy.backend import BackendLink, log
from sentinel_proxy import resolve, sandbox
from sentinel_proxy.config import ConfigError, ProxyConfig, ServerConfig, build_name_map, is_auto, scrub, summarize


class SandboxRefused(Exception):
    """A sandboxed server cannot be started with the requested boundary (fail closed; exit code 4)."""


class Downstream:
    def __init__(self, name: str):
        self.name = name
        self.session: ClientSession | None = None
        self.tools: list[types.Tool] = []
        self.dead = False
        self.status: dict[str, Any] | None = None  # trampoline status of the startup / session process


_STATUS_PREFIX = "SENTINEL_SANDBOX_STATUS "


def check_feasible(name: str, spec: dict) -> None:
    """Mirror of the trampoline's pre-check, done in the proxy so an impossible boundary never spawns anything."""
    info = sandbox.probe()
    abi, can_unshare = int(info.get("landlock_abi", 0)), bool(info.get("unshare_net", False))
    net, missing = spec["network"], []
    if abi < 1:
        missing.append("landlock_fs")
    if (net == "none" and not can_unshare and abi < 4) or (net == "loopback" and not can_unshare):
        missing.append("netns")
    if missing and spec["require"]:
        raise SandboxRefused(f"server {name!r}: this host cannot enforce {', '.join(missing)} "
                             f"(landlock_abi={abi}, unshare_net={can_unshare}); refusing to start (require=true)")


class StderrTap:
    """Child stderr -> pipe -> (status line captured, everything else forwarded to our stderr with secrets scrubbed)."""

    def __init__(self, label: str, secret_values=()):
        self.label, self.values = label, list(secret_values)
        r, w = os.pipe()
        self._rfile = os.fdopen(r, "rb", buffering=0)
        self.errlog = os.fdopen(w, "w")
        self.status: dict[str, Any] | None = None
        self.tail: list[str] = []
        self.status_seen = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), self._rfile)
        self._task = asyncio.create_task(self._pump(reader))

    def close_write(self) -> None:
        try:
            self.errlog.close()
        except Exception:
            pass

    async def _pump(self, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                line = scrub(raw.decode("utf-8", "replace").rstrip("\n"), self.values)
                if line.startswith(_STATUS_PREFIX) and self.status is None:
                    try:
                        st = json.loads(line[len(_STATUS_PREFIX):])
                        if isinstance(st, dict):
                            self.status = st
                            self.status_seen.set()
                            continue
                    except ValueError:
                        pass
                self.tail = (self.tail + [line[:300]])[-5:]
                print(f"[{self.label}] {line[:1000]}", file=sys.stderr, flush=True)
        except Exception:
            return

    async def wait_status(self, timeout: float = 2.0) -> None:
        try:
            await asyncio.wait_for(self.status_seen.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def finish(self) -> None:
        self.close_write()
        if self._task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), 1.0)
            except Exception:
                self._task.cancel()


def remove_sandbox_home(status: dict[str, Any] | None) -> None:
    """Delete the trampoline's private HOME (status `home`), and nothing else."""
    home = (status or {}).get("home")
    if not isinstance(home, str) or not home:
        return
    try:
        if (os.path.basename(home).startswith("sentinel-sbx-") and not os.path.islink(home) and os.path.isdir(home)
                and os.path.realpath(os.path.dirname(home)) == os.path.realpath(tempfile.gettempdir())):
            shutil.rmtree(home, ignore_errors=True)
    except OSError:
        pass


def _denied(reason: str, note: str = "") -> types.CallToolResult:
    text = f"Denied by SENTINEL: {reason}" + (f" (operator note: {note})" if note else "")
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=True)


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=True)


def _summary(res: types.CallToolResult) -> str:
    parts = [c.text for c in res.content if isinstance(c, types.TextContent)]
    return summarize(" ".join(parts) or f"[{len(res.content)} non-text content block(s)]")


class Proxy:
    def __init__(self, cfg: ProxyConfig, link: BackendLink | None = None):
        self.cfg = cfg
        self.link = link
        self.downstreams: dict[str, Downstream] = {}
        self.names: dict[str, tuple[str, str]] = {}
        self.exposed_tools: list[types.Tool] = []
        self._by_orig: dict[tuple[str, str], types.Tool] = {}
        self._taps: list[StderrTap] = []  # session servers' taps (for emergency_stop)

    # ------------------------------------------------------------ spawning
    @asynccontextmanager
    async def open_session(self, sc: ServerConfig, *, secrets: dict[str, str] | None = None, label: str = ""):
        """Spawn one (possibly sandboxed) server and yield (ClientSession, StderrTap). Always kills it on exit and
        removes its private HOME. `secrets` ({ENV_NAME: value}) are put in the PROCESS environment only."""
        secrets = secrets or {}
        tap = StderrTap(label or sc.name, secrets.values())
        try:
            if sc.sandbox is not None:
                spec = dict(sc.sandbox)
                spec["env_allow"] = list(dict.fromkeys([*spec["env_allow"], *secrets]))
                command, args, env = sandbox.sandbox_params(spec, sc.command, list(sc.args), {**sc.env, **secrets})
                params = StdioServerParameters(command=command, args=args, env=env, cwd=sc.cwd)
            else:
                params = StdioServerParameters(command=sc.command, args=list(sc.args), env=sc.env or None, cwd=sc.cwd)
            await tap.start()
            async with stdio_client(params, errlog=tap.errlog) as (r, w):
                tap.close_write()  # the child holds its own copy
                async with ClientSession(r, w) as session:
                    yield session, tap
        finally:
            await tap.finish()
            remove_sandbox_home(tap.status)
            tap.close_write()

    async def _enter_session(self, stack: AsyncExitStack, sc: ServerConfig) -> tuple[ClientSession, StderrTap]:
        session, tap = await stack.enter_async_context(self.open_session(sc))
        self._taps.append(tap)
        return session, tap

    def _check_status(self, sc: ServerConfig, tap: StderrTap) -> None:
        if sc.sandbox is None:
            return
        st = tap.status
        if st is None:
            if sc.sandbox["require"]:
                raise SandboxRefused(f"server {sc.name!r}: the sandbox reported no status; refusing to use it")
            return
        if st.get("missing") and sc.sandbox["require"]:
            raise SandboxRefused(f"server {sc.name!r}: sandbox layers missing: {', '.join(map(str, st['missing']))}")

    async def _discover(self, session: ClientSession) -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor = None
        while True:
            res = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
            tools.extend(res.tools)
            cursor = res.next_cursor
            if not cursor:
                return tools

    def _startup_failure(self, sc: ServerConfig, tap: StderrTap | None, e: Exception) -> Exception:
        tail = " | ".join(tap.tail) if tap else ""
        if sc.sandbox is not None and "sentinel-sandbox:" in tail and "command not found" not in tail:
            return SandboxRefused(f"server {sc.name!r}: the sandbox refused to start it: {tail[:400]}")
        return DownstreamStartError(f"downstream server {sc.name!r} failed to start: {type(e).__name__}: {e}")

    async def start_downstreams(self, stack: AsyncExitStack) -> None:
        for name, sc in self.cfg.servers.items():
            d = Downstream(name)
            if sc.sandbox is not None:
                check_feasible(name, sc.sandbox)
            tap: StderrTap | None = None
            try:
                if sc.lifecycle == "per_call":
                    # keyless worker, only for tools/list; then closed (kills it and removes its HOME)
                    async with self.open_session(sc, label=f"{name}:startup") as (session, tap):
                        await session.initialize()
                        d.tools = await self._discover(session)
                        await tap.wait_status()
                        d.status = tap.status
                        self._check_status(sc, tap)
                else:
                    session, tap = await self._enter_session(stack, sc)
                    await session.initialize()
                    d.session = session
                    d.tools = await self._discover(session)
                    await tap.wait_status()
                    d.status = tap.status
                    self._check_status(sc, tap)
            except SandboxRefused:
                raise
            except Exception as e:
                raise self._startup_failure(sc, tap, e) from e
            self.downstreams[name] = d
        self.names = build_name_map(
            {n: (self.cfg.servers[n].prefix, [t.name for t in d.tools]) for n, d in self.downstreams.items()}
        )
        for entry in self.cfg.auto_approve:
            srv, _, tool = entry.partition(":")
            if tool != "*" and tool not in {t.name for t in self.downstreams[srv].tools}:
                log(f"WARNING: auto_approve entry {entry!r} matches no tool; it will never match")
        for ex, (srv, orig) in self.names.items():
            tool = next(t for t in self.downstreams[srv].tools if t.name == orig)
            self._by_orig[(srv, orig)] = tool
            self.exposed_tools.append(tool.model_copy(update={"name": ex}))
        for n, b in self.boundary().items():
            log(f"boundary {n}: lifecycle={b['lifecycle']} network={b['network']} layers={b['layers']} "
                f"missing={b['missing']} secrets={b['secrets']}")

    def emergency_stop(self) -> None:
        """Hard stop for a fatal error while serving: SIGKILL our child processes, remove sandbox HOMEs. Best effort."""
        import signal

        try:
            for task in os.listdir("/proc/self/task"):
                with open(f"/proc/self/task/{task}/children") as f:
                    for pid in f.read().split():
                        try:
                            os.kill(int(pid), signal.SIGKILL)
                        except OSError:
                            pass
        except OSError:
            pass
        for tap in self._taps:
            remove_sandbox_home(tap.status)

    def boundary(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for name, sc in self.cfg.servers.items():
            st = self.downstreams[name].status if name in self.downstreams else None
            if sc.sandbox is None:
                layers, missing, network = [], [], "host"
            else:
                layers = [x for x in (st or {}).get("layers", []) if isinstance(x, str)]
                missing = [x for x in (st or {}).get("missing", []) if isinstance(x, str)]
                network = sc.sandbox["network"]
            out[name] = {"lifecycle": sc.lifecycle, "layers": layers, "missing": missing, "network": network,
                         "secrets": list(sc.secrets)}
        return out

    def build_server(self) -> Server:
        async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=list(self.exposed_tools))

        async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            return await self.call(params.name, params.arguments)

        return Server("sentinel-proxy", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    # ------------------------------------------------------------ calls
    async def call(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        target = self.names.get(name)
        if target is None:
            raise MCPError(types.INVALID_PARAMS, "Unknown tool")  # no backend contact
        server, orig = target
        sc = self.cfg.servers[server]
        d = self.downstreams[server]
        per_call = sc.lifecycle == "per_call"
        if not per_call and (d.dead or d.session is None):
            return _error(f"Downstream server {server!r} is not running")
        args = arguments or {}
        ro = self._by_orig[(server, orig)].annotations
        auto = is_auto(self.cfg, server, orig, ro.read_only_hint if ro else None)
        secrets_used = sc.secrets_for(orig) if per_call else []
        call_id = uuid.uuid4().hex
        frame = {"event": "proxy_call", "call_id": call_id, "server": server, "tool": orig, "args": args, "auto": auto,
                 "secrets_used": secrets_used}
        frame.update(await _resolution(args, sc))
        decision = await self.link.decide(frame)
        if not decision.approved:
            return _denied(decision.reason, decision.note)
        if per_call:
            return await self._call_worker(sc, call_id, orig, args, secrets_used)
        try:
            res = await d.session.call_tool(orig, args)
        except MCPError as e:
            await self.link.send_result(call_id, "error", summarize(e.error.message))
            return _error(f"Downstream server {server!r} returned an error: {summarize(e.error.message, 500)}")
        except Exception as e:  # process died / pipe closed
            d.dead = True
            log(f"downstream {server!r} failed: {type(e).__name__}: {e}")
            await self.link.send_result(call_id, "error", f"downstream failed: {type(e).__name__}")
            return _error(f"Downstream server {server!r} failed: {type(e).__name__}")
        await self.link.send_result(call_id, "error" if res.is_error else "ok", _summary(res))
        return res

    async def _call_worker(self, sc: ServerConfig, call_id: str, tool: str, args: dict[str, Any],
                           secret_names: list[str]) -> types.CallToolResult:
        """One approved call = one fresh sandboxed worker that holds only this call's secrets and is always killed."""
        values: dict[str, str] = {}
        for n in secret_names:  # read NOW, from the proxy's own environment
            v = os.environ.get(sc.secrets[n]["from_env"])
            if not v:
                await self.link.send_result(call_id, "error", "secret_unavailable")
                return _denied("secret_unavailable")
            values[n] = v
        vals = list(values.values())
        timed_out = False
        try:
            async with self.open_session(sc, secrets=values, label=f"{sc.name}:call") as (session, _tap):
                try:  # caught INSIDE the transport's task group, or it would surface as an ExceptionGroup
                    with anyio.fail_after(sc.call_timeout_s):
                        await session.initialize()
                        res = await session.call_tool(tool, args)
                except TimeoutError:
                    timed_out = True
        except TimeoutError:
            timed_out = True
        except MCPError as e:
            msg = scrub(summarize(e.error.message, 500), vals)
            await self.link.send_result(call_id, "error", msg[:300])
            return _error(f"Downstream server {sc.name!r} returned an error: {msg}")
        except Exception as e:
            log(f"worker for {sc.name!r} failed: {type(e).__name__}")
            await self.link.send_result(call_id, "error", f"worker failed: {type(e).__name__}")
            return _error(f"Downstream server {sc.name!r} failed: {type(e).__name__}")
        if timed_out:
            await self.link.send_result(call_id, "error", "worker timed out")
            return _error(f"Downstream server {sc.name!r}: worker timed out")
        await self.link.send_result(call_id, "error" if res.is_error else "ok", scrub(_summary(res), vals))
        return res


async def _resolution(args: dict[str, Any], sc: ServerConfig) -> dict[str, Any]:
    """proxy_call fields with the symlink-resolved path arguments (B4); {} when nothing resolves differently. A slow filesystem cannot
    stall the call: past RESOLVE_TIMEOUT_S the call is sent as `resolved_incomplete` (the hub then holds what it would allow). The worker
    thread is not stopped by the timeout (a hung lookup keeps its thread); that only costs a thread, never an allow."""
    try:
        maps, incomplete = await asyncio.wait_for(asyncio.to_thread(resolve.resolve_args, args, resolve.bases_for(sc), resolve.home_known(sc),
                                                                  resolve.map_bases_for(sc)), RESOLVE_TIMEOUT_S)
    except Exception:
        maps, incomplete = [], True
    out: dict[str, Any] = {}
    if maps:
        out["resolved"] = maps
    if incomplete:
        out["resolved_incomplete"] = True
    return out


RESOLVE_TIMEOUT_S = 2.0


class DownstreamStartError(Exception):
    pass


__all__ = ["Proxy", "DownstreamStartError", "SandboxRefused", "ConfigError"]
