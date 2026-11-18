"""The proxy's confined call with the `write` right (DECISIONS D32), in-process: the real Proxy, real sandboxed worker processes, a scripted hub link
(tests/proxy/test_confined_call.py is the template). What is pinned: the frame the hub sees (`write_confinable`, `write_why`), that the BEFORE-IMAGE
exists before the worker starts, that the worker's status must prove the same inode (else `call_tool` is never sent), what `writes` reports after
success, a tool error, a timeout and a crash, that one call is one worker / one `call_tool` / one result with nothing retried, that no before-image
means no worker, and that a decision the proxy did not vouch for (a forged or buggy hub) writes nothing.

`try_write` of tests/proxy/fake_downstream_fail.py opens the path with O_TRUNC and writes "x": a plain overwrite as the real servers do."""
import hashlib
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import pytest

from sentinel_proxy import confine, sandbox
from sentinel_proxy.backend import Decision
from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy
from tests.no_skip_plugin import sandbox_skipif

pytestmark = [pytest.mark.slow,  # GATE_TIER=pr: real sandboxed processes (docs/TESTING_REALITY.md "CI tiers")
              sandbox_skipif(sandbox.landlock_abi() < sandbox.WRITE_MIN_ABI or not sandbox.openat2_ok() or not sandbox.probe()["unshare_net"],
                             reason="a confined write worker needs Landlock ABI >= 3, openat2 and a network namespace on this host")]

HERE = Path(__file__).resolve().parent
FAIL = str(HERE / "fake_downstream_fail.py")
POLICY_WRITE = Decision(True, "policy", confine={"path": "write"})
HUMAN = Decision(True, "human")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Link:
    """The hub: every call gets `decision`; frames and results (with `writes`) are recorded."""

    def __init__(self, decision):
        self.decision, self.frames, self.results = decision, [], []

    async def decide(self, frame):
        self.frames.append(frame)
        return self.decision(frame) if callable(self.decision) else self.decision

    async def send_result(self, call_id, status, summary, writes=None):
        self.results.append((call_id, status, summary, writes))


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.delenv(confine.FORCE_ENV, raising=False)
    w = tmp_path / "w"
    (w / "sub").mkdir(parents=True)
    (w / "a.md").write_text("OLD CONTENT\n")
    (w / ".env").write_text("SECRET\n")
    (w / "sub" / "n.txt").write_text("NESTED\n")
    undo = tmp_path / "state" / "undo"
    return type("W", (), {"w": w, "undo": undo, "tmp": tmp_path})


def cfg(world, lifecycle="session", call_timeout_s=60, runtime=True):
    sb = {"read": [str(world.w)], "write": [str(world.w)], "runtime": [str(HERE)], "network": "none"}
    if not runtime:
        sb.pop("runtime")
        sb["read"].append(str(HERE))
    return parse_config({"undo_dir": str(world.undo),
                         "servers": {"fs": {"command": sys.executable, "args": [FAIL, str(world.w)], "lifecycle": lifecycle,
                                            "call_timeout_s": call_timeout_s, "sandbox": sb}}})


class Spy:
    def __init__(self, proxy, world):
        self.specs, self.calls, self.undo_existed = [], [], []
        original = proxy.open_session

        @asynccontextmanager
        async def wrapped(sc, **kw):
            if kw.get("spec") is not None:                            # a confined worker is about to start: the before-image must already be there
                self.undo_existed.append(sorted(str(p.relative_to(world.undo)) for p in Path(world.undo).rglob("*") if p.is_file()))
                self.specs.append(kw["spec"])
            async with original(sc, **kw) as (session, tap):
                real = session.call_tool

                async def call_tool(name, args, *a, **k):
                    self.calls.append(name)
                    return await real(name, args, *a, **k)
                session.call_tool = call_tool
                yield session, tap
        proxy.open_session = wrapped


async def running(world, decision, **kw):
    link = Link(decision)
    stack = AsyncExitStack()
    p = Proxy(cfg(world, **kw), link)
    await stack.__aenter__()
    await p.start_downstreams(stack)
    return p, link, stack, Spy(p, world)


def text(res):
    return " ".join(c.text for c in res.content)


# --------------------------------------------------------------------------- the frame


@pytest.mark.parametrize("name, ok, why", [("a.md", True, None), ("new.md", False, "new_file"), ("sub", False, "not_regular"),
                                           ("out.md", False, "outside_write_dir")])
async def test_the_frame_tells_the_hub_whether_this_write_is_confinable_and_why_not(world, name, ok, why):
    p, link, stack, _ = await running(world, HUMAN)
    path = str(world.w / name) if name != "out.md" else str(world.tmp / "out.md")
    try:
        await p.call("try_write", {"path": path, "content": "x"})
    finally:
        await stack.aclose()
    f = link.frames[0]
    assert f["write_confinable"] is ok and f.get("write_why") == why and f["confinable"] is True


async def test_a_call_that_is_not_write_shaped_carries_no_write_fields(world):
    p, link, stack, _ = await running(world, HUMAN)
    try:
        await p.call("pid", {"path": str(world.w / "a.md")})
        await p.call("pid", {})
    finally:
        await stack.aclose()
    assert all("write_confinable" not in f and "write_why" not in f for f in link.frames)


@pytest.mark.parametrize("how", ["symlink", "hard_link", "executable", "fifo", "big"])
async def test_each_kind_of_file_the_kernel_would_refuse_is_reported_as_unconfinable_with_its_reason(world, how):
    t = world.w / "t.md"
    t.write_text("T")
    if how == "symlink":
        t.unlink()
        t.symlink_to(world.w / "a.md")
    elif how == "hard_link":
        os.link(t, world.w / "t2.md")
    elif how == "executable":
        os.chmod(t, 0o755)
    elif how == "fifo":
        t.unlink()
        os.mkfifo(t)
    else:
        t.write_bytes(b"x" * (confine.WRITE_MAX_BYTES + 1))
    p, link, stack, _ = await running(world, HUMAN)
    try:
        await p.call("pid", {"path": str(t), "content": "x"})
    finally:
        await stack.aclose()
    want = {"symlink": "symlink", "hard_link": "hard_link", "executable": "executable", "fifo": "not_regular", "big": "too_large"}[how]
    assert (link.frames[0]["write_confinable"], link.frames[0]["write_why"]) == (False, want)


# --------------------------------------------------------------------------- the overwrite


@pytest.mark.parametrize("lifecycle", ["session", "per_call"])
async def test_an_auto_allowed_overwrite_runs_in_a_fresh_worker_that_can_write_only_that_file_and_reports_what_it_wrote(world, lifecycle):
    (world.w / "other.md").write_text("OTHER\n")
    p, link, stack, spy = await running(world, POLICY_WRITE, lifecycle=lifecycle)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
        res2 = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert text(res) == "write:ok" and not res.is_error
    assert (world.w / "a.md").read_text() == "x"
    cid, status, summary, writes = link.results[0]
    assert status == "ok" and len(writes) == 1
    o = os.stat(world.w / "a.md")
    rec = writes[0]
    assert rec["path"] == str(world.w / "a.md") and (rec["dev"], rec["ino"]) == (o.st_dev, o.st_ino)
    assert rec["size_before"] == 12 and rec["sha256_before"] == sha(b"OLD CONTENT\n")
    assert rec["size_after"] == 1 and rec["sha256_after"] == sha(b"x") and rec["replaced"] is False
    assert Path(rec["undo"]).read_bytes() == b"OLD CONTENT\n" and rec["undo"].startswith(str(world.undo) + "/" + cid)
    # the second call's before-image is the first call's result, in its own directory
    assert Path(link.results[1][3][0]["undo"]).read_bytes() == b"x" and link.results[1][3][0]["undo"] != rec["undo"]
    assert link.results[1][3][0]["sha256_before"] == sha(b"x")
    assert spy.calls == ["try_write", "try_write"] and len(spy.specs) == 2


async def test_the_worker_spec_holds_one_write_grant_beneath_the_write_directory_and_no_data_directory_and_an_8_mib_cap(world):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "sub" / "n.txt"), "content": "x"})
    finally:
        await stack.aclose()
    s = spy.specs[0]
    assert s["grants"] == [[str(world.w), "sub/n.txt", "write"]] and s["read"] == [] and s["write"] == [] and s["rlimits"]["fsize_mb"] == 8


async def test_the_before_image_exists_before_the_worker_is_started(world):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert len(spy.undo_existed) == 1 and len(spy.undo_existed[0]) == 1 and spy.undo_existed[0][0].endswith("/0")


async def test_a_worker_cannot_write_a_neighbour_even_when_the_tool_is_asked_to(world):
    """The hub approved `a.md`; the tool is then asked for another path in the SAME call is impossible (one path), so the neighbour check is the
    kernel matrix (tests/proxy/test_sandbox_write.py). Here: the call for `a.md` leaves `.env` and the neighbours byte for byte as they were."""
    before = {p.name: p.read_bytes() for p in world.w.iterdir() if p.is_file()}
    p, link, stack, _ = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    after = {p_.name: p_.read_bytes() for p_ in world.w.iterdir() if p_.is_file()}
    assert {k for k in after if after[k] != before[k]} == {"a.md"} and set(after) == set(before)


async def test_a_human_approved_write_runs_in_the_session_process_with_no_before_image_and_no_writes(world):
    p, link, stack, spy = await running(world, HUMAN)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert text(res) == "write:ok" and spy.specs == []
    assert link.results[0][3] is None and not list(world.undo.rglob("*"))          # nothing was copied (the directory may exist: the precheck makes it)


# --------------------------------------------------------------------------- what the proxy did not vouch for writes nothing


@pytest.mark.parametrize("name, why", [("new.md", "new_file"), ("lnk.md", "symlink"), ("sub", "not_regular")])
async def test_a_forged_write_decision_for_a_write_the_proxy_did_not_vouch_for_starts_no_worker_and_writes_nothing(world, name, why):
    (world.w / "lnk.md").symlink_to(world.w / ".env")
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("try_write", {"path": str(world.w / name), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: write_unsupported"
    assert spy.specs == [] and spy.calls == [] and not (world.w / "new.md").exists()
    assert (world.w / ".env").read_text() == "SECRET\n"
    assert link.results == [(link.frames[0]["call_id"], "error", "write_unsupported", None)]
    assert link.frames[0]["write_why"] == why


async def test_a_write_decision_for_a_server_that_cannot_be_confined_is_refused(world):
    p, link, stack, spy = await running(world, POLICY_WRITE, runtime=False)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res).startswith("Denied by SENTINEL") and spy.specs == [] and (world.w / "a.md").read_text() == "OLD CONTENT\n"


async def test_a_decision_with_write_on_something_other_than_path_is_refused_and_nothing_runs(world):
    p, link, stack, spy = await running(world, Decision(True, "policy", confine={"destination": "write"}))
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "destination": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and spy.specs == [] and (world.w / "a.md").read_text() == "OLD CONTENT\n"


# --------------------------------------------------------------------------- no before-image, no worker


async def test_a_snapshot_that_fails_after_the_decision_runs_nothing(world, monkeypatch):
    p, link, stack, spy = await running(world, POLICY_WRITE)

    def boom(*a, **k):
        raise confine.SnapshotError("disk full")
    monkeypatch.setattr(confine, "take_snapshot", boom)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed"
    assert spy.specs == [] and spy.calls == [] and (world.w / "a.md").read_text() == "OLD CONTENT\n"
    assert link.results[-1][1:3] == ("error", "confine_failed") and link.results[-1][3] is None


async def test_the_force_knob_does_not_let_a_missing_before_image_through_for_a_file_that_exists_and_is_plain(world, monkeypatch):
    """`force_true` lets the KERNEL decide for what the precheck would refuse; it never lets a write that HAS a name the proxy cannot copy run
    silently: a snapshot failure still ends in confine_failed unless the object cannot be copied at all (see the next test)."""
    monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    p, link, stack, spy = await running(world, POLICY_WRITE)

    def boom(*a, **k):
        raise confine.SnapshotError("disk full")
    monkeypatch.setattr(confine, "take_snapshot", boom)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    # under force the worker still runs (the test knob hands the decision to the kernel); the file is plain so it WAS grantable: the status check
    # then refuses a write grant nobody has a before-image for
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed" and (world.w / "a.md").read_text() == "OLD CONTENT\n"


async def test_a_file_swapped_after_the_snapshot_is_a_different_inode_and_call_tool_is_never_sent(world, monkeypatch):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    real = confine.take_snapshot

    def swap_after(*a, **k):
        snap = real(*a, **k)
        (world.w / "tmp.md").write_text("A DIFFERENT FILE\n")            # another inode now answers to the name
        os.replace(world.w / "tmp.md", world.w / "a.md")
        return snap
    monkeypatch.setattr(confine, "take_snapshot", swap_after)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed"
    assert spy.calls == [] and (world.w / "a.md").read_text() == "A DIFFERENT FILE\n"
    assert link.results[-1][1:3] == ("error", "confine_failed")


async def test_a_second_name_created_after_the_snapshot_is_refused_by_the_worker_and_call_tool_is_never_sent(world, monkeypatch):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    real = confine.take_snapshot

    def link_after(*a, **k):
        snap = real(*a, **k)
        os.link(world.w / "a.md", world.w / "alias.md")
        return snap
    monkeypatch.setattr(confine, "take_snapshot", link_after)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed" and spy.calls == []
    assert (world.w / "a.md").read_text() == "OLD CONTENT\n"


async def test_a_status_without_the_write_grant_is_not_enough(world, monkeypatch):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    monkeypatch.setattr(confine, "write_status_ok", lambda st, snaps: False)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed" and spy.calls == []
    assert Path(world.undo).exists() is True and not [p_ for p_ in Path(world.undo).rglob("*") if p_.is_file()]      # the copy of a call that never ran is removed


# --------------------------------------------------------------------------- failures: what is reported for a write that may have happened


async def test_a_tool_error_after_a_write_still_reports_the_write(world):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("tool_error", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error
    _, status, _, writes = link.results[0]
    assert status == "error" and len(writes) == 1 and writes[0]["sha256_after"] == writes[0]["sha256_before"] == sha(b"OLD CONTENT\n")


@pytest.mark.parametrize("lifecycle", ["session", "per_call"])
async def test_a_timed_out_write_worker_is_an_error_run_once_with_the_write_reported(world, lifecycle):
    p, link, stack, spy = await running(world, POLICY_WRITE, lifecycle=lifecycle, call_timeout_s=4)
    try:
        res = await p.call("hang", {"path": str(world.w / "a.md"), "content": "x", "seconds": 60})
    finally:
        await stack.aclose()
    assert res.is_error and "timed out" in text(res) and not text(res).startswith("Denied")
    assert spy.calls == ["hang"] and len(link.results) == 1
    _, status, summary, writes = link.results[0]
    assert (status, summary) == ("error", "worker timed out") and writes[0]["replaced"] is False and writes[0]["sha256_after"] == sha(b"OLD CONTENT\n")


async def test_a_crashed_write_worker_is_an_error_run_once_with_the_write_reported_and_the_next_call_is_fresh(world):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("crash", {"path": str(world.w / "a.md"), "content": "x"})
        res2 = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and not text(res).startswith("Denied by SENTINEL")
    assert spy.calls == ["crash", "try_write"] and len(link.results) == 2
    assert link.results[0][1] == "error" and len(link.results[0][3]) == 1 and link.results[1][1] == "ok"
    assert text(res2) == "write:ok" and (world.w / "a.md").read_text() == "x"


async def test_every_confined_write_is_one_decision_one_worker_one_call_tool_one_result_and_nothing_is_retried(world):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert len(link.frames) == 1 and len(spy.specs) == 1 and spy.calls == ["try_write"] and len(link.results) == 1


async def test_a_denied_write_takes_no_snapshot_and_starts_nothing(world):
    p, link, stack, spy = await running(world, Decision(False, "human"))
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and spy.specs == [] and spy.calls == [] and not list(world.undo.rglob("*"))
    assert (world.w / "a.md").read_text() == "OLD CONTENT\n"


# --------------------------------------------------------------------------- the force knob and the kernel


async def test_force_true_on_a_hard_linked_file_still_writes_nothing(world, monkeypatch):
    monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    os.link(world.w / "a.md", world.w / "alias.md")
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert link.frames[0]["write_confinable"] is True                    # forced: the precheck said yes
    assert res.is_error and (world.w / "a.md").read_text() == "OLD CONTENT\n" and spy.calls == []        # the worker refused the second name


async def test_force_true_on_a_symlink_name_reaches_the_kernel_and_the_credential_is_untouched(world, monkeypatch):
    monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    (world.w / "lnk.md").symlink_to(world.w / ".env")
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("try_write", {"path": str(world.w / "lnk.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert (world.w / ".env").read_text() == "SECRET\n"
    assert text(res) in ("write:errno=13", "Denied by SENTINEL: confine_failed")      # kernel EACCES, or the status check first


async def test_force_true_on_a_new_name_creates_nothing(world, monkeypatch):
    monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("try_write", {"path": str(world.w / "new.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert not (world.w / "new.md").exists() and (text(res) == "write:errno=13" or text(res).startswith("Denied by SENTINEL"))


# --------------------------------------------------------------------------- retention: the original before-image cannot be pushed out


async def test_the_original_before_image_survives_any_number_of_later_writes_and_a_full_store_asks_instead(world, monkeypatch):
    """Overwrite F, then keep writing: a count cap that evicts the oldest would let an agent erase F's original with trivial auto-writes. The store
    never evicts by count: when it is full the next write is a card (`no_before_image`), and a forged approval of it is refused."""
    monkeypatch.setattr(confine, "UNDO_MAX_CALLS", 3)
    (world.w / "b.md").write_text("B\n")
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})          # F: the original is "OLD CONTENT"
        original = link.results[0][3][0]["undo"]
        await p.call("try_write", {"path": str(world.w / "b.md"), "content": "x"})
        await p.call("try_write", {"path": str(world.w / "b.md"), "content": "y"})
        await p.call("try_write", {"path": str(world.w / "b.md"), "content": "z"})          # the store holds 3 calls: full
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "wipe"})
    finally:
        await stack.aclose()
    assert Path(original).read_bytes() == b"OLD CONTENT\n"                                    # still there, after more writes than the cap
    f4 = link.frames[3]
    assert f4["write_confinable"] is False and f4["write_why"] == "no_before_image"
    assert res.is_error and text(res) == "Denied by SENTINEL: write_unsupported" and (world.w / "a.md").read_text() == "x"
    assert len(list(Path(world.undo).iterdir())) == 3


async def test_a_store_that_fills_between_the_precheck_and_the_snapshot_denies_the_call(world, monkeypatch):
    p, link, stack, spy = await running(world, POLICY_WRITE)
    monkeypatch.setattr(confine, "write_check", lambda *a, **k: (True, ""))          # the precheck said yes ...
    monkeypatch.setattr(confine, "UNDO_MAX_CALLS", 0)                                  # ... and the store filled up before the snapshot
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed" and spy.calls == [] and (world.w / "a.md").read_text() == "OLD CONTENT\n"


async def test_a_huge_edit_is_reported_unconfinable_with_its_reason_and_a_forged_approval_runs_nothing(world):
    big = [{"oldText": "OLD", "newText": "x" * 10_000_000}]
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p.call("try_write", {"path": str(world.w / "a.md"), "edits": big})
    finally:
        await stack.aclose()
    assert link.frames[0]["write_confinable"] is False and link.frames[0]["write_why"] == "edits_too_large"
    assert res.is_error and text(res) == "Denied by SENTINEL: write_unsupported" and spy.calls == [] and (world.w / "a.md").read_text() == "OLD CONTENT\n"


async def test_before_images_past_the_retention_window_are_removed_at_the_next_write_and_only_those(world):
    import time
    old, fresh = Path(world.undo) / "old-call", Path(world.undo) / "fresh-call"
    for d in (old, fresh):
        d.mkdir(parents=True, mode=0o700, exist_ok=True)
        (d / "0").write_text("x")
    t = time.time() - 40 * 86400
    os.utime(old, (t, t))
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        await p.call("try_write", {"path": str(world.w / "a.md"), "content": "x"})
    finally:
        await stack.aclose()
    assert not old.exists() and fresh.exists()


async def test_the_worker_path_itself_refuses_a_write_decision_that_yields_no_write_grant(world):
    """WW22: the precheck in `call` usually refuses first; `_call_worker` must hold the same line when it is reached directly (a decision whose
    `write` names a path the proxy cannot walk beneath a write directory) and start no worker."""
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        res = await p._call_worker(p.cfg.servers["fs"], "cid-x", "try_write", {"path": "/nonexistent/elsewhere.md", "content": "x"}, [], {"path": "write"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: write_unsupported"
    assert spy.specs == [] and spy.calls == [] and link.results == [("cid-x", "error", "write_unsupported", None)]


async def test_taking_a_before_image_first_removes_the_expired_ones(world):
    """WW48: `_take_snapshots` prunes by itself (the precheck's prune can be a long time before it, or skipped)."""
    import time
    old = Path(world.undo) / "old-call"
    old.mkdir(parents=True, mode=0o700)
    (old / "0").write_text("x")
    t = time.time() - 40 * 86400
    os.utime(old, (t, t))
    p, link, stack, spy = await running(world, POLICY_WRITE)
    try:
        snaps = p._take_snapshots([[str(world.w), "a.md", "write"]], {"path": str(world.w / "a.md")}, "call-new")
    finally:
        await stack.aclose()
    assert snaps and not old.exists()
