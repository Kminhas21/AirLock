"""Downstream MCP server whose tools FAIL in the ways a confined worker can fail (tests/proxy/test_confined_call_failures.py).

Every start and every call prints a marker on STDERR (the proxy's tap keeps the tail), so a test can tell which process served which call:
  PID <n>              at start
  CALL <tool> <n>      on every executed call
"""
import asyncio
import os
import sys

import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

OBJ = {"type": "object"}
NAMES = ["pid", "hang", "boom_mcp", "echo_secret", "crash", "tool_error", "try_write"]
TOOLS = [types.Tool(name=n, description=n, input_schema=OBJ) for n in NAMES]


async def list_tools(ctx, params):
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(ctx, params):
    a = params.arguments or {}
    print(f"CALL {params.name} {os.getpid()}", file=sys.stderr, flush=True)
    if params.name == "hang":
        await asyncio.sleep(float(a.get("seconds", 60)))
    elif params.name == "boom_mcp":
        raise MCPError(types.INVALID_PARAMS, "bad things happened")
    elif params.name == "echo_secret":
        return types.CallToolResult(content=[types.TextContent(text=f"key={os.environ.get('API_KEY', '')}")])   # echoes the secret it got
    elif params.name == "crash":
        os._exit(7)                                     # the worker dies in the middle of the call
    elif params.name == "tool_error":
        return types.CallToolResult(content=[types.TextContent(text="the tool says no")], is_error=True)
    elif params.name == "try_write":
        try:
            with open(a["path"], "w") as f:
                f.write("x")
            return types.CallToolResult(content=[types.TextContent(text="write:ok")])
        except OSError as e:
            return types.CallToolResult(content=[types.TextContent(text=f"write:errno={e.errno}")])
    return types.CallToolResult(content=[types.TextContent(text=f"pid={os.getpid()}")])


async def main():
    print(f"PID {os.getpid()}", file=sys.stderr, flush=True)
    server = Server("fake-fail", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
