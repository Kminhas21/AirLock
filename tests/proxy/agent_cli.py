"""Modes:
  python agent_cli.py <proxy-config.json> <tool> '<json args>'   one call, then exit
  python agent_cli.py --serve <proxy-config.json>                ONE proxy session; stdin lines {"tool":..,"args":{..}},
                                                                 one {"is_error":..,"text":..} line out per call; exits on EOF
(one-shot docs follow) A one-shot MCP 'agent' for browser tests: python agent_cli.py <proxy-config.json> <tool> '<json args>'
Starts the REAL proxy over stdio (like any MCP client would), calls one tool, prints {"is_error":..,"text":..} and exits."""
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]


def _params(cfg: str) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "sentinel_proxy", "--config", cfg], cwd=str(ROOT),
                                 env={"SENTINEL_PROXY_CONNECT_WAIT_S": "2", "PYTHONUNBUFFERED": "1",
                                      **({"SENTINEL_WS_TOKEN": os.environ["SENTINEL_WS_TOKEN"]} if os.environ.get("SENTINEL_WS_TOKEN") else {}),
                                      # host variables the proxy may read secrets from (config `secrets.*.from_env`), named by the test harness
                                      **{n: os.environ[n] for n in filter(None, os.environ.get("SENTINEL_AGENT_PASSTHROUGH", "").split(",")) if n in os.environ}})


def _out(res) -> str:
    return json.dumps({"is_error": bool(res.is_error), "text": "".join(getattr(c, "text", "") for c in res.content)})


async def main(cfg: str, tool: str, args: dict) -> None:
    async with stdio_client(_params(cfg)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            print(_out(await s.call_tool(tool, args)), flush=True)


async def serve(cfg: str) -> None:
    loop = asyncio.get_running_loop()
    async with stdio_client(_params(cfg)) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            while True:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                    res = await s.call_tool(req["tool"], req.get("args") or {})
                    print(_out(res), flush=True)
                except Exception as e:
                    print(json.dumps({"is_error": True, "text": f"agent_cli error: {type(e).__name__}: {e}"}), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        asyncio.run(serve(sys.argv[2]))
    else:
        asyncio.run(main(sys.argv[1], sys.argv[2], json.loads(sys.argv[3])))
