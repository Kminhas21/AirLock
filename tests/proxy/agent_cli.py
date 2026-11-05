"""A one-shot MCP 'agent' for browser tests: python agent_cli.py <proxy-config.json> <tool> '<json args>'
Starts the REAL proxy over stdio (like any MCP client would), calls one tool, prints {"is_error":..,"text":..} and exits."""
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]


async def main(cfg: str, tool: str, args: dict) -> None:
    params = StdioServerParameters(command=sys.executable, args=["-m", "sentinel_proxy", "--config", cfg], cwd=str(ROOT),
                                   env={"SENTINEL_PROXY_CONNECT_WAIT_S": "2", "PYTHONUNBUFFERED": "1"})
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, args)
            print(json.dumps({"is_error": bool(res.is_error), "text": "".join(getattr(c, "text", "") for c in res.content)}), flush=True)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], json.loads(sys.argv[3])))
