"""MCP server (toward the agent) + MCP clients (toward downstream servers) with the approval gate."""
from __future__ import annotations

import uuid
from contextlib import AsyncExitStack
from typing import Any

import mcp_types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel.server import Server
from mcp.shared.exceptions import MCPError

from sentinel_proxy.backend import BackendLink, log
from sentinel_proxy.config import ConfigError, ProxyConfig, build_name_map, is_auto, summarize


class Downstream:
    def __init__(self, name: str):
        self.name = name
        self.session: ClientSession | None = None
        self.tools: list[types.Tool] = []
        self.dead = False


def _denied(reason: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=f"Denied by SENTINEL: {reason}")], is_error=True)


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=True)


def _summary(res: types.CallToolResult) -> str:
    parts = [c.text for c in res.content if isinstance(c, types.TextContent)]
    return summarize(" ".join(parts) or f"[{len(res.content)} non-text content block(s)]")


class Proxy:
    def __init__(self, cfg: ProxyConfig, link: BackendLink):
        self.cfg = cfg
        self.link = link
        self.downstreams: dict[str, Downstream] = {}
        self.names: dict[str, tuple[str, str]] = {}
        self.exposed_tools: list[types.Tool] = []
        self._by_orig: dict[tuple[str, str], types.Tool] = {}

    async def start_downstreams(self, stack: AsyncExitStack) -> None:
        for name, sc in self.cfg.servers.items():
            d = Downstream(name)
            params = StdioServerParameters(command=sc.command, args=list(sc.args), env=sc.env or None, cwd=sc.cwd)
            try:
                r, w = await stack.enter_async_context(stdio_client(params))
                d.session = await stack.enter_async_context(ClientSession(r, w))
                await d.session.initialize()
                cursor = None
                while True:
                    res = await d.session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
                    d.tools.extend(res.tools)
                    cursor = res.next_cursor
                    if not cursor:
                        break
            except Exception as e:
                raise DownstreamStartError(f"downstream server {name!r} failed to start: {type(e).__name__}: {e}") from e
            self.downstreams[name] = d
        self.names = build_name_map(
            {n: (self.cfg.servers[n].prefix, [t.name for t in d.tools]) for n, d in self.downstreams.items()}
        )
        for ex, (srv, orig) in self.names.items():
            tool = next(t for t in self.downstreams[srv].tools if t.name == orig)
            self._by_orig[(srv, orig)] = tool
            self.exposed_tools.append(tool.model_copy(update={"name": ex}))

    def build_server(self) -> Server:
        async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=list(self.exposed_tools))

        async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
            return await self.call(params.name, params.arguments)

        return Server("sentinel-proxy", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    async def call(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        target = self.names.get(name)
        if target is None:
            raise MCPError(types.INVALID_PARAMS, "Unknown tool")  # no backend contact
        server, orig = target
        d = self.downstreams[server]
        if d.dead or d.session is None:
            return _error(f"Downstream server {server!r} is not running")
        args = arguments or {}
        ro = self._by_orig[(server, orig)].annotations
        auto = is_auto(self.cfg, server, orig, ro.read_only_hint if ro else None)
        call_id = uuid.uuid4().hex
        decision = await self.link.decide(
            {"event": "proxy_call", "call_id": call_id, "server": server, "tool": orig, "args": args, "auto": auto}
        )
        if not decision.approved:
            return _denied(decision.reason)
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


class DownstreamStartError(Exception):
    pass


__all__ = ["Proxy", "DownstreamStartError", "ConfigError"]
