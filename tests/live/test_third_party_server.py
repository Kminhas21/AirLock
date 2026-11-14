"""A REAL third-party MCP server (Desktop Commander 0.3.1, npm, pinned in tests/realdeps; workflow D1) through the real proxy and hub.

Differential: the same MCP client drives the server DIRECTLY and THROUGH SENTINEL and everything it can observe must be identical (initialize,
capabilities, instructions, every tool's schema and annotations, resources, prompts, call results), while every proxied call was held for a human.
Then the safety invariants with a shell tool: a start_process does not run while it is held, runs once a human approves, and a denied one never runs.
Desktop Commander runs with a private HOME and its telemetry and feature-flag fetch switched off (tests/live/livelib.py dc_env)."""
import asyncio
import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.harness import ROOT, TOKEN, Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality


def _calls(d):
    out = d.parent / "written" / "out.txt"           # outside the listed directory, so list_directory sees the same thing both times
    return [("list_directory", {"path": str(d)}), ("read_file", {"path": str(d / "a.txt")}),
            ("write_file", {"path": str(out), "content": "hello", "mode": "rewrite"}),
            ("edit_block", {"file_path": str(out), "old_string": "hello", "new_string": "HELLO"}),
            ("read_file", {"path": str(out)}), ("read_file", {"path": str(d / "does-not-exist.txt")})]


async def _observe(params: StdioServerParameters, calls) -> dict:
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w, read_timeout_seconds=None) as s:
            init = (await asyncio.wait_for(s.initialize(), 120)).model_dump(exclude_none=True, by_alias=True, mode="json")
            out = {"server": init["serverInfo"]["name"], "version": init["serverInfo"].get("version"), "protocol": init["protocolVersion"],
                   "capabilities": sorted(init.get("capabilities", {})), "instructions": init.get("instructions")}
            out["tools"] = {t.name: t.model_dump(exclude_none=True, by_alias=True, mode="json") for t in (await s.list_tools()).tools}
            for kind, fn in (("resources", s.list_resources), ("prompts", s.list_prompts)):
                try:
                    out[kind] = sorted(json.dumps(x.model_dump(exclude_none=True, by_alias=True, mode="json"), sort_keys=True) for x in getattr(await fn(), kind))
                except Exception as e:                                   # an unsupported list must fail the SAME way both ways
                    out[kind] = f"error: {type(e).__name__}"
            out["calls"] = []
            for tool, args in calls:
                res = (await asyncio.wait_for(s.call_tool(tool, args), 120)).model_dump(exclude_none=True, by_alias=True, mode="json")
                res.pop("_meta", None)
                out["calls"].append((tool, res))
    return out


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dc")
    b = Backend(tmp / "backend.log", {"SENTINEL_EVENT_LOG": str(tmp / "events.db"), "SENTINEL_LOG_KEY": livelib.LOG_KEY})
    b.db = tmp / "events.db"
    yield b
    b.stop()


async def test_desktop_commander_looks_identical_direct_and_through_the_gate_and_every_call_was_held(realdeps, hub, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "written").mkdir()
    (work / "a.txt").write_text("hello world\n")
    dc = realdeps["desktop_commander"]
    direct = await _observe(StdioServerParameters(command=dc, args=[], env=livelib.dc_env(tmp_path / "home-direct")), _calls(work))

    sid = "dc-diff"
    cfg = tmp_path / "proxy.json"
    cfg.write_text(json.dumps({"session_id": sid, "backend": f"{hub.ws}/proxy/ws", "servers": {"dc": livelib.dc_server(dc, tmp_path / "home-proxy")}}))
    op = await Operator.connect(hub, lambda p: "approve")
    try:
        proxied = await _observe(StdioServerParameters(command=sys.executable, args=["-m", "sentinel_proxy", "--config", str(cfg)], cwd=str(ROOT),
                                                       env={"SENTINEL_WS_TOKEN": TOKEN, "PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT),
                                                            "SENTINEL_PROXY_CONNECT_WAIT_S": "10"}), _calls(work))
    finally:
        await op.close()

    assert direct["server"] and len(direct["tools"]) >= 10 and "start_process" in direct["tools"]
    assert proxied["protocol"] == direct["protocol"]
    # the documented differences (docs/proxy.md "Compatibility with real MCP servers"), pinned so a change is noticed: the proxy is one
    # tools-only server for all downstreams; resources, prompts, logging and the server's instructions are not offered
    assert proxied["server"] == "sentinel-proxy" and proxied["capabilities"] == ["tools"] and proxied["instructions"] is None
    assert "tools" in direct["capabilities"] and direct["resources"] and proxied["resources"].startswith("error") and proxied["prompts"].startswith("error")
    assert set(proxied["tools"]) == set(direct["tools"])
    for name in direct["tools"]:
        assert proxied["tools"][name] == direct["tools"][name], name                 # schema, annotations, output schema, title: byte for byte
    assert [c[0] for c in proxied["calls"]] == [c[0] for c in direct["calls"]]
    for (tool, d), (_, p) in zip(direct["calls"], proxied["calls"]):
        assert p == d, tool
    assert (tmp_path / "written" / "out.txt").read_text() == "HELLO"
    assert direct["calls"][-1][1].get("isError") is True                              # the server's own error came back as an error, unchanged

    evs = livelib.events(hub.db, sid)
    props, decs = livelib.proposals(evs), livelib.decisions(evs)
    assert [p["tool"] for p in props.values()] == [c[0] for c in _calls(work)]       # every call reached the log, in order
    assert all(decs[c]["actor"] == "human" and decs[c]["decision"] == "approve" for c in props)   # and each one was a human decision


async def test_a_shell_command_runs_only_after_a_human_approves_and_a_denied_one_never_runs(realdeps, hub, tmp_path):
    held, verdicts = [], {}

    def decide(p):
        held.append(p)
        return verdicts.get(p["args"].get("command"))                  # None = leave it held

    op = await Operator.connect(hub, decide)
    sid = "dc-shell"
    agent = await Agent.start(hub, sid, {"dc": livelib.dc_server(realdeps["desktop_commander"], tmp_path / "home")}, tmp_path)
    ran, never = tmp_path / "ran.marker", tmp_path / "never.marker"
    try:
        cmd = f"touch {ran} && echo sentinel-approved-output"
        call = asyncio.create_task(agent.call("start_process", {"command": cmd, "timeout_ms": 10000}))
        for _ in range(240):
            if any(p["args"].get("command") == cmd for p in held):
                break
            await asyncio.sleep(0.25)
        card = next(p for p in held if p["args"].get("command") == cmd)
        assert card["tool"] == "start_process" and card["args"]["command"] == cmd          # the human sees exactly what the agent sent
        await asyncio.sleep(2.0)
        assert not ran.exists() and not call.done()                                         # held: the command has NOT run
        await op.ws.send(json.dumps({"event": "inbox_decision", "session_id": card["session_id"], "call_id": card["call_id"], "decision": "approve"}))
        r = await asyncio.wait_for(call, 120)
        assert not r["is_error"] and "sentinel-approved-output" in r["text"], r
        assert ran.exists()

        bad = f"touch {never}"
        verdicts[bad] = "deny"
        r = await agent.call("start_process", {"command": bad, "timeout_ms": 10000})
        assert r["is_error"] and r["text"].startswith("Denied by SENTINEL"), r
        verdicts["echo after"] = "approve"
        r = await agent.call("start_process", {"command": "echo after", "timeout_ms": 10000})   # the link still works, and nothing ran late
        assert not r["is_error"], r
        assert not never.exists()
    finally:
        await agent.stop()
        await op.close()
    evs = livelib.events(hub.db, sid)
    props, decs = livelib.proposals(evs), livelib.decisions(evs)
    by_cmd = {p["args"]["command"]: c for c, p in props.items()}
    assert decs[by_cmd[cmd]]["decision"] == "approve" and decs[by_cmd[cmd]]["actor"] == "human"
    assert decs[by_cmd[bad]]["decision"] == "deny" and decs[by_cmd[bad]]["actor"] == "human"
    assert not any(e["kind"] == "call_result" and e["call_id"] == by_cmd[bad] for e in evs)   # a denied call has no result: it never reached the server
    code, out = livelib.cli("verify", str(hub.db))
    assert code == 0 and out.strip().splitlines()[-1].startswith("OK:"), out
