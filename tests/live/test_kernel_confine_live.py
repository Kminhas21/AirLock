"""LIVE: auto-allowed path calls are kernel-confined (DECISIONS D31, workflow A4). builtin:starter in front of the REAL filesystem server
1.0.0 and Desktop Commander, both sandboxed with `runtime`, through the real proxy and hub.

Path prediction is gone: the hub judges only the written text, and an auto-allowed call runs in a worker that Landlock lets read only the
objects the agent NAMED (opened with RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS). Every past prediction bypass (K0-K5) runs twice:
  default     the proxy's precheck sees a symlink / escape / too many bases and the call is held (or, for a missing name, the call runs and
              the kernel denies the server's respelling);
  force_true  SENTINEL_CONFINE_PRECHECK=force_true makes the precheck say "confinable": the call IS auto-allowed with no card, the server
              gets it, and the kernel still denies the read.
Either way the secret is in neither the agent's result nor the event log (results are logged here: SENTINEL_LOG_RESULTS=1)."""
import uuid
from pathlib import Path

import pytest

from tests.harness import ROOT, Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

SECRET = f"SECRET-{uuid.uuid4().hex}"
FORCE = {"SENTINEL_CONFINE_PRECHECK": "force_true"}


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("confine")
    b = Backend(tmp / "backend.log", {"SENTINEL_POLICY": "builtin:starter", "SENTINEL_EVENT_LOG": str(tmp / "events.db"),
                                      "SENTINEL_LOG_KEY": livelib.LOG_KEY, "SENTINEL_LOG_RESULTS": "1"})
    b.db = tmp / "events.db"
    yield b
    b.stop()


def _secret(d: Path) -> None:
    (d / ".env").write_text(SECRET + "\n")


def k0(t):
    w = t / "w"
    w.mkdir()
    _secret(w)
    (w / "notes.txt").symlink_to(w / ".env")
    return [w], [str(w / "notes.txt"), "notes.txt"]


def k1(t):
    w = t / "w"
    (w / "sub" / "deep").mkdir(parents=True)
    _secret(w)
    (w / "lnk").symlink_to(w / "sub" / "deep")
    (w / "b").symlink_to(w / ".env")                   # the server removes '..' lexically: lnk/../b names b -> .env
    return [w], [str(w / "lnk" / ".." / "b"), "lnk/../b"]


def k2(t):
    w = t / "w"
    w.mkdir()
    _secret(w)
    (w / "my notes").symlink_to(w / ".env")       # the server maps the missing "my notes" onto this entry
    return [w], [str(w / "my notes"), "my notes"]


def k3(t):
    dirs, _ = k2(t)
    w = dirs[0]
    (w / "sub" / "deep").mkdir(parents=True)
    (w / "sub" / "my notes").write_text("decoy\n")     # the KERNEL order of lnk/../my notes names this harmless file
    (w / "lnk").symlink_to(w / "sub" / "deep")
    return [w], [str(w / "lnk" / ".." / "my notes"), "lnk/../my notes"]


def _k4(t, n):
    dirs = [t / f"p{i}" / "a" for i in range(1, n)] + [t / f"p{n}" / "x"]
    for d in dirs:
        d.mkdir(parents=True)
    _secret(dirs[-1])
    (dirs[-1] / "b").symlink_to(".env")
    return dirs, ["../x/b"]


def k4_fourth(t):
    return _k4(t, 4)


def k4_fifth(t):
    return _k4(t, 5)


def k5(t):
    d0, d1 = t / "d0", t / "d1"
    d0.mkdir()
    d1.mkdir()
    _secret(d0)
    (d0 / "my notes").symlink_to(".env")
    (d1 / "my notes").write_text("harmless\n")
    return [d0, d1], ["my notes"]


# case -> (builder, what happens without the knob: "held" = a card the human denies, "kernel" = auto-allowed, the kernel denies)
CASES = {"K0": (k0, "held"), "K1": (k1, "held"), "K2": (k2, "kernel"), "K3": (k3, "held"), "K4-4th": (k4_fourth, "held"),
         "K4-5th": (k4_fifth, "held"), "K5": (k5, "held")}


class Human:
    """Approves `approve` tools, denies the rest; records every card."""

    def __init__(self, approve=()):
        self.cards, self.approve = [], set(approve)

    def __call__(self, p):
        self.cards.append(p)
        return "approve" if p["tool"] in self.approve else "deny"


def _fs(realdeps, dirs, write=()):
    return livelib.sandboxed({"command": realdeps["filesystem"], "args": [str(d) for d in dirs]}, read=dirs, write=write)


async def _session(hub, server, sid, tmp_path, calls, env=None, approve=()):
    human = Human(approve)
    op = await Operator.connect(hub, human)
    agent = await Agent.start(hub, sid, {"fs": server}, tmp_path, env=env)
    out = []
    try:
        for tool, args in calls:
            n = len(human.cards)
            r = await agent.call(tool, args, timeout=120)
            out.append((r, human.cards[n:]))
    finally:
        await agent.stop()
        await op.close()
    return out


def _log(hub, sid):
    evs = livelib.events(hub.db, sid)
    return evs, livelib.proposals(evs), livelib.decisions(evs)


def _kernel_denied(r) -> bool:
    """The server's own error for a read Landlock refused (the filesystem server: "EACCES: permission denied, open ..."): a worker that
    failed to start, or a call that never reached the server, would say something else and must not pass as a kernel denial."""
    t = r["text"]
    return r["is_error"] and not t.startswith("Denied by SENTINEL") and ("EACCES" in t or "permission denied" in t.lower())


def _no_secret_anywhere(hub, sid, results):
    for r, _cards in results:
        assert SECRET not in r["text"], r
    evs, props, _ = _log(hub, sid)
    assert SECRET not in str(evs)
    assert SECRET not in hub.log_text()
    for p in props.values():
        assert "resolved" not in p and "resolved_invalid" not in p, p      # prediction is gone
    return props


@pytest.mark.parametrize("mode", ["default", "force_true"])
@pytest.mark.parametrize("case", sorted(CASES))
async def test_past_prediction_bypasses_never_reach_the_secret(realdeps, hub, tmp_path, case, mode):
    build, default_outcome = CASES[case]
    dirs, values = build(tmp_path)
    sid = f"kc-{case}-{mode}-{uuid.uuid4().hex[:6]}"
    results = await _session(hub, _fs(realdeps, dirs), sid, tmp_path, [("read_text_file", {"path": v}) for v in values],
                             env=FORCE if mode == "force_true" else None)
    props = _no_secret_anywhere(hub, sid, results)
    _, _, decs = _log(hub, sid)
    outcome = "kernel" if mode == "force_true" else default_outcome
    for (r, cards), (cid, prop) in zip(results, props.items()):
        assert r["is_error"], (case, mode, prop["args"], r)
        if outcome == "held":
            assert len(cards) == 1 and r["text"].startswith("Denied by SENTINEL"), (case, prop["args"], r, cards)
            assert decs[cid]["reason"] == "human"
        else:                                          # auto-allowed, no card, the server got the call, the kernel said no
            assert cards == [], (case, mode, prop["args"], cards)
            assert decs[cid]["decision"] == "approve" and decs[cid]["reason"] == "policy", decs[cid]
            assert not r["text"].startswith("Denied by SENTINEL"), r
            assert _kernel_denied(r), (case, mode, r)      # EACCES from the server, not a worker that failed to start


async def test_the_card_shows_where_a_link_leads_and_nothing_evaluates_it(realdeps, hub, tmp_path):
    dirs, values = k0(tmp_path)
    sid = f"kc-card-{uuid.uuid4().hex[:6]}"
    results = await _session(hub, _fs(realdeps, dirs), sid, tmp_path, [("read_text_file", {"path": values[0]})])
    _no_secret_anywhere(hub, sid, results)
    (r, cards), = results
    assert len(cards) == 1 and cards[0]["links"] == {"path": str(dirs[0] / ".env")}, cards
    assert cards[0]["rule_id"] == "allow-read-file"                 # the allow rule matched the TEXT; the link made it unconfinable


async def test_plain_reads_lists_and_trees_are_auto_allowed_with_the_right_content(realdeps, hub, tmp_path):
    w = tmp_path / "w"
    (w / "sub").mkdir(parents=True)
    (w / "plain.txt").write_text("just notes\n")
    (w / "sub" / "a.txt").write_text("alpha\n")
    _secret(w)
    sid = f"kc-use-{uuid.uuid4().hex[:6]}"
    results = await _session(hub, _fs(realdeps, [w]), sid, tmp_path, [
        ("read_text_file", {"path": str(w / "plain.txt")}),
        ("read_text_file", {"path": "plain.txt"}),
        ("list_directory", {"path": str(w)}),
        ("directory_tree", {"path": str(w)}),
        ("read_multiple_files", {"paths": [str(w / "plain.txt"), str(w / "sub" / "a.txt")]}),
    ])
    _no_secret_anywhere(hub, sid, results)
    texts = [r["text"] for r, _ in results]
    assert all(not r["is_error"] and cards == [] for r, cards in results), results
    assert "just notes" in texts[0] and "just notes" in texts[1]
    assert "plain.txt" in texts[2] and "sub" in texts[2] and "a.txt" in texts[3]
    assert "just notes" in texts[4] and "alpha" in texts[4]
    _, props, decs = _log(hub, sid)
    assert all(d["decision"] == "approve" and d["reason"] == "policy" for d in decs.values()) and len(decs) == 5


async def test_a_list_grant_never_reads_a_file_and_a_read_grant_never_reads_a_neighbour(realdeps, hub, tmp_path):
    """search_files is allowed with a `list` grant on its directory: names only. Then the session's own process still serves a
    human-approved write, and an auto-allowed read of the new file (a fresh confined worker) sees it."""
    w = tmp_path / "w"
    w.mkdir()
    (w / "plain.txt").write_text("just notes\n")
    _secret(w)
    sid = f"kc-mix-{uuid.uuid4().hex[:6]}"
    results = await _session(hub, _fs(realdeps, [w], write=[w]), sid, tmp_path, [
        ("search_files", {"path": str(w), "pattern": "**/*env*"}),
        ("write_file", {"path": str(w / "new.txt"), "content": "written by a human-approved call\n"}),
        ("read_text_file", {"path": str(w / "new.txt")}),
    ], approve={"write_file"})
    _no_secret_anywhere(hub, sid, results)
    (search, c0), (write, c1), (read, c2) = results
    assert c0 == [] and not search["is_error"] and ".env" in search["text"], search
    assert len(c1) == 1 and not write["is_error"], write                      # held, approved, served by the session process
    assert (w / "new.txt").read_text() == "written by a human-approved call\n"
    assert c2 == [] and not read["is_error"] and "human-approved" in read["text"], read


async def test_desktop_commander_plain_read_is_auto_allowed_and_a_forced_link_read_is_denied_by_the_kernel(realdeps, hub, tmp_path):
    w = tmp_path / "w"
    w.mkdir()
    (w / "plain.txt").write_text("just notes\n")
    _secret(w)
    (w / "notes.txt").symlink_to(w / ".env")
    dc = livelib.sandboxed(livelib.dc_server(realdeps["desktop_commander"], tmp_path / "dc-home"), read=[w],
                           env_allow=["DESKTOP_COMMANDER_DISABLE_TELEMETRY", "DC_FLAG_URL", "NO_COLOR"])
    for env, held in ((None, True), (FORCE, False)):
        sid = f"kc-dc-{'f' if env else 'd'}-{uuid.uuid4().hex[:6]}"
        results = await _session(hub, dc, sid, tmp_path, [("read_file", {"path": str(w / "plain.txt")}),
                                                          ("read_file", {"path": str(w / "notes.txt")})], env=env)
        _no_secret_anywhere(hub, sid, results)
        (plain, c0), (link, c1) = results
        assert c0 == [] and not plain["is_error"] and "just notes" in plain["text"], plain
        assert link["is_error"] and len(c1) == (1 if held else 0), (link, c1)
        assert link["text"].startswith("Denied by SENTINEL") == held, link
        if not held:
            assert _kernel_denied(link), link


async def test_K6_PINNED_KNOWN_GAP_a_hard_link_to_a_secret_is_readable(realdeps, hub, tmp_path):
    """PINNED KNOWN GAP (docs/boundary.md, DECISIONS D31): a hard link IS the same file. Landlock grants the object the agent NAMED, and the
    name `hl` is an ordinary file inside an allowed directory that shares the inode of `.env`: nothing in the kernel or in the written
    text tells them apart, so the read is auto-allowed and returns the content. The suite pins this so the gap stays visible: if this test
    ever fails because the read is now denied, the gap was closed, and the docs and D31 headline must say so. Mitigation: do not let an
    allowed directory contain a hard link to a secret (the agent cannot create one: `link` is not offered by the starter's allows)."""
    gap = f"HARDLINK-{uuid.uuid4().hex}"
    w = tmp_path / "w"
    w.mkdir()
    (w / ".env").write_text(gap + "\n")
    (w / "hl").hardlink_to(w / ".env")
    sid = f"kc-k6-{uuid.uuid4().hex[:6]}"
    (r, cards), = await _session(hub, _fs(realdeps, [w]), sid, tmp_path, [("read_text_file", {"path": str(w / "hl")})])
    assert cards == [] and not r["is_error"] and gap in r["text"], r         # the gap: auto-allowed, no card, the content is returned
    _, _, decs = _log(hub, sid)
    assert [d["reason"] for d in decs.values()] == ["policy"]


def test_prediction_code_is_gone():
    assert not (ROOT / "server" / "resolved_args.py").exists()
    assert not (ROOT / "sentinel_proxy" / "resolve.py").exists()
