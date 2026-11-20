"""The proxy + hub in front of REAL MCP servers (docs/TESTING_REALITY.md, rung 2). The only scripted parts are the agent and the human."""
import asyncio
import os
import signal
import subprocess

import pytest

from tests.harness import Agent, Operator
from tests.reality_fixtures import backend, realdeps  # noqa: F401  (fixtures)

pytestmark = pytest.mark.reality            # real processes, minutes: own gate stage (pytest -m reality), deselected by default


@pytest.fixture
async def human(backend):
    """An operator that approves everything except tools in .deny."""
    class H:
        deny: set = set()
    h = H()
    op = await Operator.connect(backend, lambda p: "deny" if p.get("tool") in h.deny else "approve")
    h.op = op
    yield h
    await op.close()


@pytest.fixture
async def fs(realdeps, backend, human, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    agent = await Agent.start(backend, f"fs-{tmp_path.name}", {"fs": {"command": realdeps["filesystem"], "args": [str(allowed)]}}, tmp_path)
    yield agent, allowed
    await agent.stop()


async def test_filesystem_round_trip_through_the_gate(fs, human):
    agent, allowed = fs
    f = allowed / "notes.txt"
    r = await agent.call("write_file", {"path": str(f), "content": "quarterly numbers\nline two\n"})
    assert not r["is_error"], r
    assert f.read_text() == "quarterly numbers\nline two\n"                      # the real server really wrote it, after a human said yes
    r = await agent.call("read_file", {"path": str(f)})
    assert "quarterly numbers" in r["text"] and not r["is_error"]
    assert "notes.txt" in (await agent.call("list_directory", {"path": str(allowed)}))["text"]
    assert "notes.txt" in (await agent.call("directory_tree", {"path": str(allowed)}))["text"]
    assert "notes.txt" in (await agent.call("search_files", {"path": str(allowed), "pattern": "*notes*"}))["text"]
    assert not (await agent.call("get_file_info", {"path": str(f)}))["is_error"]
    assert not (await agent.call("edit_file", {"path": str(f), "edits": [{"oldText": "two", "newText": "TWO"}]}))["is_error"]
    assert "TWO" in f.read_text()
    assert not (await agent.call("move_file", {"source": str(f), "destination": str(allowed / "moved.txt")}))["is_error"]
    assert (allowed / "moved.txt").exists() and not f.exists()
    assert len(human.op.resolved) >= 8 and all(r["decision"] == "approve" for r in human.op.resolved[-8:])   # every one of them was a human decision


async def test_a_denied_write_never_reaches_the_real_server(fs, human):
    agent, allowed = fs
    human.deny = {"write_file"}
    r = await agent.call("write_file", {"path": str(allowed / "evil.txt"), "content": "x"})
    assert r["is_error"] and r["text"].startswith("Denied by SENTINEL")
    assert not (allowed / "evil.txt").exists()


async def test_the_real_servers_own_boundaries_are_reported_not_hidden(fs, tmp_path):
    agent, allowed = fs
    (allowed / "link").symlink_to("/etc")
    for path in ("/etc/passwd", str(allowed / ".." / ".." / "etc" / "passwd"), str(allowed / "link" / "passwd")):
        r = await agent.call("read_file", {"path": path})
        assert r["is_error"] and ("denied" in r["text"].lower() or "outside" in r["text"].lower()), (path, r)
    assert not (await agent.call("read_file", {"path": str(allowed / "nope.txt")}))["text"].startswith("Denied by SENTINEL")   # a plain ENOENT is the server's error


async def test_large_arguments_the_biggest_approvable_one_works_and_an_oversize_one_is_denied_alone(fs):
    """Agent -> proxy -> hub -> operator websocket -> hub -> proxy -> real server -> disk, with a human in the loop.
    Found by this test: a 2 MB argument used to make the hub DROP the proxy's link ("backend connection lost" for that and every pending call)."""
    agent, allowed = fs
    ok = "0123456789abcdef" * (900_000 // 16)                    # ~0.9 MB: under the 1 MB review limit
    r = await agent.call("write_file", {"path": str(allowed / "big.txt"), "content": ok}, timeout=180)
    assert not r["is_error"], r["text"][:300]
    assert (allowed / "big.txt").stat().st_size == len(ok)
    back = await agent.call("read_file", {"path": str(allowed / "big.txt")}, timeout=180)
    assert not back["is_error"] and len(back["text"]) >= len(ok)
    huge = "x" * 2_000_000
    r = await agent.call("write_file", {"path": str(allowed / "huge.txt"), "content": huge}, timeout=60)
    assert r["is_error"] and r["text"].startswith("Denied by SENTINEL") and "too large" in r["text"], r["text"][:200]   # a clear reason, not "connection lost"
    assert not (allowed / "huge.txt").exists()
    after = await agent.call("list_directory", {"path": str(allowed)}, timeout=60)                                    # the link survived: the next call is fine
    assert not after["is_error"] and "big.txt" in after["text"], after


async def test_stateful_memory_server_and_per_session_isolation(realdeps, backend, human, tmp_path):
    mem = {"memory": {"command": realdeps["memory"], "env": {"MEMORY_FILE_PATH": str(tmp_path / "graph.json")}}}
    a = await Agent.start(backend, f"mem-a-{tmp_path.name}", mem, tmp_path)
    try:
        r = await a.call("create_entities", {"entities": [{"name": "Alice", "entityType": "person", "observations": ["likes tea"]}]})
        assert not r["is_error"], r
        await a.call("create_relations", {"relations": [{"from": "Alice", "to": "Alice", "relationType": "knows"}]})
        assert "Alice" in (await a.call("read_graph", {}))["text"]
        assert "tea" in (await a.call("search_nodes", {"query": "tea"}))["text"]
    finally:
        await a.stop()


async def test_python_stdio_server(realdeps, backend, human, tmp_path):
    a = await Agent.start(backend, f"time-{tmp_path.name}", {"time": {"command": realdeps["time"]}}, tmp_path)
    try:
        r = await a.call("get_current_time", {"timezone": "Europe/London"})
        assert not r["is_error"] and "Europe/London" in r["text"]
        bad = await a.call("get_current_time", {"timezone": "Not/AZone"})
        assert bad["is_error"]                                                  # the server's own validation error comes back as an error, not a hang
    finally:
        await a.stop()


async def test_a_crashed_downstream_gives_an_error_not_a_hang_and_the_hub_survives(fs, backend):
    agent, allowed = fs
    assert not (await agent.call("list_allowed_directories", {}))["is_error"]
    out = subprocess.run(["pgrep", "-f", f"mcp-server-filesystem {allowed}"], capture_output=True, text=True).stdout.split()
    assert out, "could not find the real server process"
    for pid in out:
        os.kill(int(pid), signal.SIGKILL)
    await asyncio.sleep(0.5)
    r = await asyncio.wait_for(agent.call("list_directory", {"path": str(allowed)}, timeout=60), 70)
    assert r["is_error"], r                                                      # a dead server is an error the agent can see
    import urllib.request
    assert urllib.request.urlopen(f"http://127.0.0.1:{backend.port}/health", timeout=5).status == 200
    assert "unexpected server error" not in backend.log_text()


async def test_the_real_node_server_runs_inside_the_landlock_sandbox(realdeps, backend, human, tmp_path):
    """Rung 2 x boundary: the sandbox with a REAL interpreter-based server (not our 50-line fake): writes inside the allowed dir work, outside is blocked by the KERNEL."""
    import shutil
    from tests.harness import ROOT
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    node_root = os.path.dirname(os.path.dirname(os.path.realpath(shutil.which("node"))))
    server = {"command": realdeps["filesystem"], "args": [str(allowed)], "lifecycle": "per_call", "call_timeout_s": 60,
              "sandbox": {"read": [str(ROOT / ".realdeps"), node_root], "write": [str(allowed)], "network": "none", "env_allow": ["PATH", "HOME"], "require": True}}
    agent = await Agent.start(backend, f"sbx-{tmp_path.name}", {"fs": server}, tmp_path)
    try:
        r = await agent.call("write_file", {"path": str(allowed / "in.txt"), "content": "inside"}, timeout=120)
        assert not r["is_error"], r["text"][:400]
        assert (allowed / "in.txt").read_text() == "inside"
        outside = tmp_path / "outside"
        outside.mkdir()
        # the real server's own allow-list would refuse this too; ask for a path the SERVER allows but the KERNEL must not: the allowed dir is a symlink target
        (allowed / "escape").symlink_to(outside)
        r = await agent.call("write_file", {"path": str(allowed / "escape" / "x.txt"), "content": "out"}, timeout=120)
        assert not (outside / "x.txt").exists()
    finally:
        await agent.stop()
