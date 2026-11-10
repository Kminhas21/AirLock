"""Tiny real downstream MCP server (stdio) for proxy tests.

Every executed call appends a JSON line to $FAKE_DOWNSTREAM_LOG, so tests can prove a call
did (or did NOT) reach the downstream.
"""
import asyncio
import json
import os

import mcp_types as types
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

OBJ = {"type": "object"}
TOOLS = [
    types.Tool(name="read_file", description="read", input_schema={**OBJ, "properties": {"path": {"type": "string"}}},
               annotations=types.ToolAnnotations(read_only_hint=True)),
    types.Tool(name="write_file", description="write", input_schema=OBJ),
    types.Tool(name="echo", description="echo", input_schema=OBJ),
    types.Tool(name="crash", description="kills the process", input_schema=OBJ),
]


def record(name, args):
    path = os.environ.get("FAKE_DOWNSTREAM_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"tool": name, "args": args}) + "\n")


async def list_tools(ctx, params):
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(ctx, params):
    args = params.arguments or {}
    record(params.name, args)
    if params.name == "crash":
        os._exit(1)
    return types.CallToolResult(content=[types.TextContent(text=f"{params.name}:{json.dumps(args, sort_keys=True)}")])


async def main():
    server = Server("fake-downstream", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
