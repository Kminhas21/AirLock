"""Downstream MCP server for the enforcement-boundary tests. Reports what the (sandboxed) process can see and do."""
import asyncio
import errno
import json
import os
import socket
import sys
import time

import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

OBJ = {"type": "object"}
NAMES = ["whoami_env", "whoami_env2", "try_write", "try_net", "sleep"]
TOOLS = [types.Tool(name=n, description=n, input_schema=OBJ) for n in NAMES]


def _errno(e):
    return errno.errorcode.get(e.errno, str(e.errno))


async def list_tools(ctx, params):
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(ctx, params):
    a = params.arguments or {}
    out = {}
    if params.name in ("whoami_env", "whoami_env2"):
        out["env_names"] = sorted(os.environ)
        var = a.get("secret_var")
        out["secret"] = os.environ.get(var) if var else None
        if out["secret"]:
            print(f"probe saw secret {out['secret']}", file=sys.stderr, flush=True)
    elif params.name == "try_write":
        try:
            with open(a["path"], "w") as f:
                f.write("x")
            out["write"] = "ok"
        except OSError as e:
            out["write"] = "err:" + _errno(e)
    elif params.name == "try_net":
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect(("127.0.0.1", int(a["port"])))
            out["net"] = "connected"
        except OSError as e:
            out["net"] = "err:" + (_errno(e) if e.errno else type(e).__name__)
        finally:
            s.close()
    elif params.name == "sleep":
        await asyncio.sleep(float(a.get("seconds", 30)))
        out["slept"] = True
    return types.CallToolResult(content=[types.TextContent(text=json.dumps(out))])


async def main():
    pf = os.environ.get("FAKE_PID_FILE")
    if pf:
        with open(pf, "a") as f:
            f.write(f"{os.getpid()}\n")
    server = Server("fake-probe", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
