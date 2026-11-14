"""LIVE: builtin:starter in front of the REAL reference filesystem server, through the real proxy and hub (DECISIONS D29, B3 + B4).

A symlink notes.txt -> .env inside the allowed directory must be held for a human, not auto-allowed (B4), and its secret must not reach
the agent when the human denies; a plain read is still auto-allowed; a read with an argument the real tool does not have is held (B3)."""
import asyncio

import pytest

from tests.harness import Agent, Backend, Operator
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

SECRET = "API_KEY=sk-live-b3b4-not-a-real-key"


@pytest.fixture(scope="module")
def starter_backend(tmp_path_factory):
    b = Backend(tmp_path_factory.mktemp("b3b4") / "backend.log", env={"SENTINEL_POLICY": "builtin:starter"})
    yield b
    b.stop()


@pytest.fixture
async def rig(realdeps, starter_backend, tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / ".env").write_text(SECRET + "\n")
    (allowed / "plain.txt").write_text("just notes\n")
    (allowed / "notes.txt").symlink_to(allowed / ".env")
    (allowed / "rel-notes.txt").symlink_to(".env")
    (allowed / "sub" / "deep").mkdir(parents=True)
    (allowed / "lnk").symlink_to(allowed / "sub" / "deep")     # an ordinary symlinked directory ...
    (allowed / "b").symlink_to(allowed / ".env")               # ... and a link whose '..' route only Node's lexical order reaches
    (allowed / "my\u00a0notes").symlink_to(allowed / ".env")   # the server maps "my notes" (ASCII space) onto this entry
    (allowed / "sub" / "my notes").write_text("decoy\n")         # exists in the KERNEL order of lnk/../my notes only
    held: list = []
    op = await Operator.connect(starter_backend, lambda p: (held.append(p), "deny")[1])
    agent = await Agent.start(starter_backend, f"b3b4-{tmp_path.name}",
                              {"fs": {"command": realdeps["filesystem"], "args": [str(allowed)]}}, tmp_path)
    yield agent, allowed, held, op
    await agent.stop()
    await op.close()


def _policy_allowed(op, n_before):
    return [r for r in op.resolved[n_before:] if r.get("reason") == "policy" and r.get("decision") == "approve"]


async def test_a_plain_read_is_still_auto_allowed(rig):
    agent, allowed, held, op = rig
    n = len(op.resolved)
    r = await agent.call("read_text_file", {"path": str(allowed / "plain.txt")})
    assert not r["is_error"] and "just notes" in r["text"], r
    await asyncio.sleep(0.3)
    assert held == [] and _policy_allowed(op, n), op.resolved[n:]


@pytest.mark.parametrize("name", ["notes.txt", "rel-notes.txt"])
async def test_a_symlink_to_dotenv_is_held_and_the_secret_never_reaches_the_agent(rig, name):
    agent, allowed, held, op = rig
    for path in (str(allowed / name), name):                  # absolute, and relative (the server resolves it in its allowed dir)
        held.clear()
        r = await agent.call("read_text_file", {"path": path})
        assert r["is_error"] and r["text"].startswith("Denied by SENTINEL"), (path, r)
        assert SECRET not in r["text"] and "sk-live" not in r["text"]
        assert len(held) == 1 and held[0]["rule_id"] == "ask-sensitive-path", repr(held)[:3000]
        assert held[0]["args"] == {"path": path}
        assert any(str(allowed / ".env") in str(v) for m in held[0].get("resolved", []) for v in m.values()), held[0]


async def test_a_read_with_an_unknown_extra_argument_is_held(rig):
    agent, allowed, held, op = rig
    r = await agent.call("read_text_file", {"path": str(allowed / "plain.txt"), "isUrl": False})
    assert r["is_error"] and r["text"].startswith("Denied by SENTINEL"), r
    assert len(held) == 1 and held[0]["tool"] == "read_text_file" and held[0].get("rule_id") is None   # no allow rule matched: default ask


@pytest.mark.parametrize("rel", ["lnk/../b", "my notes", "lnk/../my notes"])
async def test_node_path_order_and_unicode_equivalents_cannot_reach_the_secret(rig, rel):
    """review B1: '..' after a symlinked dir is removed lexically by the server BEFORE realpath; review M1: the server maps a missing name
    onto a Unicode-equivalent entry. Both must be held, absolute and relative, and the secret never reaches the agent."""
    agent, allowed, held, op = rig
    for path in (str(allowed / rel), rel):
        held.clear()
        r = await agent.call("read_text_file", {"path": path})
        assert SECRET not in r["text"] and "sk-live" not in r["text"], (path, r)
        assert r["is_error"] and r["text"].startswith("Denied by SENTINEL"), (path, r)
        assert len(held) == 1, (path, held)


async def test_a_kernel_order_decoy_in_a_list_cannot_reach_the_secret(rig):
    agent, allowed, held, op = rig
    r = await agent.call("read_multiple_files", {"paths": [str(allowed / "plain.txt"), str(allowed / "lnk" / ".." / "my notes")]})
    assert SECRET not in r["text"] and "sk-live" not in r["text"], r
    assert r["is_error"] and r["text"].startswith("Denied by SENTINEL") and len(held) == 1, r


async def test_a_relative_path_against_the_fourth_allowed_directory_cannot_reach_the_secret(realdeps, starter_backend, tmp_path):
    """re-review MAJOR 2: the server tries EVERY allowed directory for a relative path; a capped list of bases dropped the one it used"""
    d1, d2, d3 = tmp_path / "p1" / "a", tmp_path / "p2" / "a", tmp_path / "p3" / "x"
    for d in (d1, d2, d3):
        d.mkdir(parents=True)
    (d3 / ".env").write_text(SECRET + "\n")
    (d3 / "b").symlink_to(".env")
    held: list = []
    op = await Operator.connect(starter_backend, lambda p: (held.append(p), "deny")[1])
    agent = await Agent.start(starter_backend, f"b3b4-4th-{tmp_path.name}",
                              {"fs": {"command": realdeps["filesystem"], "args": [str(d1), str(d2), str(d3)]}}, tmp_path)
    try:
        r = await agent.call("read_text_file", {"path": "../x/b"})
    finally:
        await agent.stop()
        await op.close()
    assert SECRET not in r["text"] and "sk-live" not in r["text"], r
    assert r["is_error"] and r["text"].startswith("Denied by SENTINEL") and len(held) == 1, r


@pytest.mark.parametrize("case", ["decoy_in_other_base", "plain_relative_read"])
async def test_two_allowed_dirs_the_first_one_decides(realdeps, starter_backend, tmp_path, case):
    """confirmation review: the server resolves a non-escaping relative name against the FIRST allowed dir and maps it there onto a
    Unicode-equivalent link (d0/my\\u00a0notes -> .env); a harmless d1/'my notes' must not make the call look safe. Plain reads are
    still auto-allowed: an absolute path, and a relative name present in every allowed dir (one missing in any allowed dir is held)."""
    d0, d1 = tmp_path / "d0", tmp_path / "d1"
    d0.mkdir()
    d1.mkdir()
    (d0 / ".env").write_text(SECRET + "\n")
    (d0 / "my notes").symlink_to(".env")
    (d1 / "my notes").write_text("decoy\n")
    (d0 / "plain.txt").write_text("just notes\n")
    (d0 / "only0.txt").write_text("just notes\n")
    (d1 / "plain.txt").write_text("other\n")
    held: list = []
    op = await Operator.connect(starter_backend, lambda p: (held.append(p), "deny")[1])
    agent = await Agent.start(starter_backend, f"b3b4-2d-{case[:5]}-{abs(hash(str(tmp_path))) % 10**8}",
                              {"fs": {"command": realdeps["filesystem"], "args": [str(d0), str(d1)]}}, tmp_path)
    try:
        if case == "decoy_in_other_base":
            r = await agent.call("read_text_file", {"path": "my notes"})
            assert SECRET not in r["text"] and "sk-live" not in r["text"], r
            assert r["is_error"] and r["text"].startswith("Denied by SENTINEL") and len(held) == 1, r
        else:
            for path in ("plain.txt", str(d0 / "only0.txt")):
                r = await agent.call("read_text_file", {"path": path})
                assert not r["is_error"] and "just notes" in r["text"] and held == [], (path, r, held)
    finally:
        await agent.stop()
        await op.close()
