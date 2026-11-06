from __future__ import annotations

import argparse
import asyncio
import os
import sys
from contextlib import AsyncExitStack

from mcp.server.stdio import stdio_server

from sentinel_proxy.backend import BackendLink, log
from sentinel_proxy.config import ConfigError, gate_timeout_s, load_config_file, with_token
from sentinel_proxy.proxy import DownstreamStartError, Proxy, SandboxRefused


async def serve(cfg) -> int:
    proxy = Proxy(cfg)
    code = 0
    async with AsyncExitStack() as stack:
        try:
            await proxy.start_downstreams(stack)
        except ConfigError as e:
            print(f"sentinel-proxy: {e}", file=sys.stderr)
            return 2
        except SandboxRefused as e:
            print(f"sentinel-proxy: sandbox: {e}", file=sys.stderr)
            return 4
        except DownstreamStartError as e:
            print(f"sentinel-proxy: {e}", file=sys.stderr)
            return 1
        hello = {
            "event": "proxy_hello",
            "session_id": cfg.session_id,
            "servers": list(cfg.servers),
            "auto_approve": list(cfg.auto_approve),
            "boundary": proxy.boundary(),
        }
        url = with_token(cfg.backend, os.environ.get("SENTINEL_WS_TOKEN"))
        link = BackendLink(url, hello, call_timeout_s=gate_timeout_s())
        proxy.link = link
        link_task = asyncio.create_task(link.run())
        try:
            try:
                wait = float(os.environ.get("SENTINEL_PROXY_CONNECT_WAIT_S", "3"))
            except ValueError:
                wait = 3.0
            await link.wait_started(wait)
            if link.fatal.is_set():
                print(f"sentinel-proxy: {link.fatal_reason}", file=sys.stderr)
                return 3
            if not link.connected:
                log("backend not reachable yet; serving with every call denied until it connects")
            server = proxy.build_server()
            async with stdio_server() as (r, w):
                srv_task = asyncio.create_task(server.run(r, w, server.create_initialization_options()))
                fatal_task = asyncio.create_task(link.fatal.wait())
                done, _ = await asyncio.wait({srv_task, fatal_task}, return_when=asyncio.FIRST_COMPLETED)
                if fatal_task in done:
                    print(f"sentinel-proxy: {link.fatal_reason}", file=sys.stderr)
                    code = 3
                    srv_task.cancel()
                else:
                    fatal_task.cancel()
                try:
                    await srv_task
                except (asyncio.CancelledError, Exception) as e:
                    if not isinstance(e, asyncio.CancelledError):
                        log(f"server stopped: {type(e).__name__}: {e}")
        finally:
            link_task.cancel()
            await asyncio.gather(link_task, return_exceptions=True)
    return code


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sentinel_proxy", description="SENTINEL stdio MCP approval proxy")
    ap.add_argument("--config", required=True, help="proxy.json")
    ap.add_argument("--session-id")
    ap.add_argument("--backend")
    try:
        ns = ap.parse_args(argv)
    except SystemExit as e:  # argparse already printed usage to stderr
        sys.stderr.flush()
        os._exit(2 if e.code else 0)
    try:
        cfg = load_config_file(ns.config, session_id_override=ns.session_id, backend_override=ns.backend)
    except ConfigError as e:
        print(f"sentinel-proxy: invalid configuration:\n{e}", file=sys.stderr)
        sys.exit(2)
    log(f"session {cfg.session_id}, servers: {', '.join(cfg.servers)}")
    try:
        code = asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        code = 0
    sys.stderr.flush()
    # stdin may still be blocked in a reader thread; do not wait for it.
    os._exit(code)
