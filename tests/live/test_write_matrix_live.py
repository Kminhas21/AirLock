"""LIVE: what an auto-allowed call can WRITE today (phase 1 of the "narrow write right" plan, workflow A4). The REAL filesystem server 1.0.0
behind the real proxy and hub, sandboxed with `runtime`. The policy auto-allows every write tool on files beneath `w/` with `confine: read`
(exactly what a standing "Always allow" on a write card builds), so each call runs in a worker the kernel confines to READ_FILE on the objects
the agent NAMED. There is no `write` right yet, so the matrix is: the server gets the call (no card), its own error says EACCES, and the tree
is byte-for-byte what it was (names, bytes, inodes, link counts), checked from outside. A control proves the same server CAN write: a call
outside the rule is held, a human approves it, and the session process (its own sandbox) writes the file.

When a `write` right is added, the rows that become allowed flip on purpose; the rest stay as the negative control."""
import json
import os
import stat
import uuid
from pathlib import Path

import pytest

from tests.harness import Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

FORCE = {"SENTINEL_CONFINE_PRECHECK": "force_true"}
ORIGINAL = {"a.txt": "GRANTED\n", "neighbour.txt": "NEIGHBOUR\n", "secret.txt": "SECRET\n"}


def policy_for(w: Path) -> dict:
    under = lambda key: [{"path": key, "op": "under", "value": str(w)}]          # noqa: E731
    return {"version": 1, "default": "ask", "rules": [
        {"id": "auto-write", "verdict": "allow", "when": {"server": "fs", "tool": ["write_file", "edit_file", "create_directory"],
                                                          "arg_keys": ["path", "content", "edits", "dryRun"], "args": under("path")},
         "confine": {"path": "read"}},
        {"id": "auto-move", "verdict": "allow", "when": {"server": "fs", "tool": "move_file", "arg_keys": ["source", "destination"],
                                                         "args": under("source") + under("destination")},
         "confine": {"source": "read", "destination": "read"}},
    ]}


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("writematrix")
    w, ctl = root / "w", root / "ctl"
    w.mkdir()
    ctl.mkdir()
    pol = root / "policy.json"
    pol.write_text(json.dumps(policy_for(w)))
    b = Backend(root / "backend.log", {"SENTINEL_POLICY": str(pol), "SENTINEL_EVENT_LOG": str(root / "events.db"),
                                       "SENTINEL_LOG_KEY": livelib.LOG_KEY, "SENTINEL_LOG_RESULTS": "1"})
    b.db = root / "events.db"
    yield b, w, ctl, root
    b.stop()


class Human:
    def __init__(self, approve=()):
        self.cards, self.approve = [], set(approve)

    def __call__(self, p):
        self.cards.append(p)
        return "approve" if p["tool"] in self.approve else "deny"


def snapshot(d: Path) -> dict:
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            p = Path(root) / n
            s = p.lstat()
            kind = "dir" if stat.S_ISDIR(s.st_mode) else "link" if stat.S_ISLNK(s.st_mode) else "file"
            out[str(p.relative_to(d))] = (kind, s.st_ino, s.st_nlink, stat.S_IMODE(s.st_mode),
                                          p.read_bytes() if kind == "file" else os.readlink(p) if kind == "link" else None)
    return out


def tree(w: Path) -> Path:
    d = w / uuid.uuid4().hex[:8]
    (d / "sub").mkdir(parents=True)
    for n, text in ORIGINAL.items():
        (d / n).write_text(text)
    (d / "hard.txt").hardlink_to(d / "secret.txt")                 # a second name of `secret.txt`
    (d / "lnk").symlink_to(d / "a.txt")
    return d


async def session(realdeps, b, w, ctl, calls, env=None, approve=()):
    human = Human(approve)
    op = await Operator.connect(b, human)
    server = livelib.sandboxed({"command": realdeps["filesystem"], "args": [str(w), str(ctl)]}, read=[w, ctl], write=[ctl])
    agent = await Agent.start(b, f"wm-{uuid.uuid4().hex[:8]}", {"fs": server}, w.parent, env=env)
    out = []
    try:
        for tool, args in calls:
            n = len(human.cards)
            out.append((await agent.call(tool, args, timeout=120), human.cards[n:]))
    finally:
        await agent.stop()
        await op.close()
    return out


def cases(d: Path) -> list:
    """(label, tool, args): every way to change a file or a name, aimed at the granted file, a neighbour, a new name, a directory."""
    return [
        ("overwrite", "write_file", {"path": str(d / "a.txt"), "content": "OVERWRITTEN\n"}),
        ("edit", "edit_file", {"path": str(d / "a.txt"), "edits": [{"oldText": "GRANTED", "newText": "EDITED"}]}),
        ("truncate-by-empty-write", "write_file", {"path": str(d / "a.txt"), "content": ""}),
        ("neighbour", "write_file", {"path": str(d / "neighbour.txt"), "content": "OVERWRITTEN\n"}),
        ("create-new-name", "write_file", {"path": str(d / "new.txt"), "content": "NEW\n"}),
        ("create-in-subdir", "write_file", {"path": str(d / "sub" / "new.txt"), "content": "NEW\n"}),
        ("create-in-missing-dir", "write_file", {"path": str(d / "missing" / "new.txt"), "content": "NEW\n"}),
        ("mkdir", "create_directory", {"path": str(d / "newdir")}),
        ("mkdir-nested", "create_directory", {"path": str(d / "x" / "y" / "z")}),
        ("rename", "move_file", {"source": str(d / "a.txt"), "destination": str(d / "renamed.txt")}),
        ("rename-over-neighbour", "move_file", {"source": str(d / "a.txt"), "destination": str(d / "neighbour.txt")}),
        ("rename-into-subdir", "move_file", {"source": str(d / "a.txt"), "destination": str(d / "sub" / "a.txt")}),
        ("write-through-hard-link-name", "write_file", {"path": str(d / "hard.txt"), "content": "OVERWRITTEN\n"}),
        ("edit-through-hard-link-name", "edit_file", {"path": str(d / "hard.txt"), "edits": [{"oldText": "SECRET", "newText": "X"}]}),
    ]


SERVER_REFUSES = {"rename-over-neighbour": "already exists"}


def _kernel_denied(r) -> bool:
    """The server's own error for something Landlock refused (or a name that does not exist): never a SENTINEL denial, never a success."""
    t = r["text"]
    return r["is_error"] and not t.startswith("Denied by SENTINEL") and ("EACCES" in t or "permission denied" in t.lower() or "ENOENT" in t)


async def test_every_write_of_an_auto_allowed_confined_call_is_denied_by_the_kernel_and_the_tree_is_unchanged(realdeps, world):
    b, w, ctl, root = world
    d = tree(w)
    before = snapshot(d)
    calls = [(t, a) for _label, t, a in cases(d)]
    results = await session(realdeps, b, w, ctl, calls)
    for (label, tool, args), (r, cards) in zip(cases(d), results):
        assert cards == [], (label, cards)                                   # the policy allowed it: no card
        if label in SERVER_REFUSES:                                          # the server's own check fires before it asks the kernel
            assert r["is_error"] and SERVER_REFUSES[label] in r["text"] and not r["text"].startswith("Denied by SENTINEL"), (label, r)
        else:
            assert _kernel_denied(r), (label, r)                             # the server ran and the kernel said no
    assert snapshot(d) == before                                             # nothing changed, from outside the sandbox
    evs = livelib.events(b.db)
    decs = [livelib.decisions(evs)[cid] for cid, p in livelib.proposals(evs).items() if p["args"].get("path", p["args"].get("source", "")).startswith(str(d))]
    assert len(decs) == len(calls) and all(x["decision"] == "approve" and x["reason"] == "policy" for x in decs)


async def test_a_name_that_is_a_symlink_is_held_and_forced_through_the_kernel_still_cannot_write(realdeps, world):
    b, w, ctl, root = world
    d = tree(w)
    before = snapshot(d)
    call = ("write_file", {"path": str(d / "lnk"), "content": "THROUGH-THE-LINK\n"})
    (held, cards), = await session(realdeps, b, w, ctl, [call])
    assert len(cards) == 1 and held["is_error"] and held["text"].startswith("Denied by SENTINEL"), (held, cards)
    assert cards[0]["links"] == {"path": str(d / "a.txt")}                    # the card says where the link leads
    (forced, cards2), = await session(realdeps, b, w, ctl, [call], env=FORCE)
    assert cards2 == [] and _kernel_denied(forced), forced                    # auto-allowed by force: the kernel grants nothing on a link
    assert snapshot(d) == before


async def test_control_a_human_approved_write_outside_the_rule_is_served_by_the_session_process_and_does_write(realdeps, world):
    """The same server in the same sandbox CAN write (its own `write` directory): the matrix above is the confined worker's doing, not a
    read-only tree or a broken server. The call is held (outside the rule), the human approves, the session process writes."""
    b, w, ctl, root = world
    target = ctl / f"{uuid.uuid4().hex[:6]}.txt"
    (r, cards), = await session(realdeps, b, w, ctl, [("write_file", {"path": str(target), "content": "HUMAN-APPROVED\n"})], approve={"write_file"})
    assert len(cards) == 1 and not r["is_error"], (r, cards)
    assert target.read_text() == "HUMAN-APPROVED\n"


async def test_a_human_denied_write_changes_nothing_and_says_so(realdeps, world):
    b, w, ctl, root = world
    target = ctl / f"{uuid.uuid4().hex[:6]}.txt"
    (r, cards), = await session(realdeps, b, w, ctl, [("write_file", {"path": str(target), "content": "NO\n"})])
    assert len(cards) == 1 and r["is_error"] and r["text"].startswith("Denied by SENTINEL") and not target.exists()
