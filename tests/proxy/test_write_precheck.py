"""The proxy's precheck for the `write` right (DECISIONS D32), the before-image, and the record of what was written. No worker is started:
this is the SAME walk the confined worker will do, as a hint to the hub (`write_confinable` / `write_why`), plus the snapshot the proxy takes
just before the call. A value that is not exactly "an existing plain file with one name, beneath a write directory of the server, small enough
to copy, in a form the kernel can grant" is `write_confinable: false` and the hub asks a human."""
import hashlib
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel_proxy import confine, sandbox
from tests.no_skip_plugin import sandbox_skipif

pytestmark = sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok(), reason="needs Landlock and openat2")

HERE = Path(__file__).resolve().parent


@pytest.fixture(autouse=True)
def _abi7(monkeypatch):
    monkeypatch.delenv(confine.FORCE_ENV, raising=False)
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 7)


@pytest.fixture
def world(tmp_path):
    w = tmp_path / "w"
    (w / "sub").mkdir(parents=True)
    (w / "notes.md").write_text("NOTES\n")
    (w / "sub" / "deep.txt").write_text("DEEP\n")
    (w / "empty.md").write_text("")
    (w / "run.md").write_text("x")
    os.chmod(w / "run.md", 0o755)
    (w / "hard.md").write_text("H")
    os.link(w / "hard.md", w / "hard2.md")
    (w / "lnk.md").symlink_to(w / "notes.md")
    (w / "sublnk").symlink_to(w / "sub")
    os.mkfifo(w / "fifo.md")
    (w / "big.md").write_bytes(b"x" * (confine.WRITE_MAX_BYTES + 1))
    (w / "edge.md").write_bytes(b"x" * confine.WRITE_MAX_BYTES)
    other = tmp_path / "other"
    other.mkdir()
    (other / "x.md").write_text("OTHER")
    undo = tmp_path / "state" / "undo"
    sc = SimpleNamespace(name="fs", args=[str(w)], cwd=None,
                         sandbox={"read": [str(w)], "write": [str(w)], "runtime": [str(HERE)], "network": "none", "env_allow": [],
                                  "rlimits": {}, "require": True})
    return SimpleNamespace(w=w, other=other, undo=str(undo), sc=sc, tmp=tmp_path)


def check(world, path, **kw):
    return confine.write_check({"path": str(path), "content": "x", **kw}, world.sc, world.undo)


# --------------------------------------------------------------------------- what is a write-shaped call


@pytest.mark.parametrize("args, shaped", [({"path": "/w/a", "content": "x"}, True), ({"path": "/w/a", "edits": []}, True),
                                          ({"path": "/w/a", "content": "x", "mode": "rewrite"}, True), ({"path": "/w/a"}, False),
                                          ({"content": "x"}, False), ({"path": 5, "content": "x"}, False), ({"paths": ["/w/a"], "content": "x"}, False),
                                          ({}, False), (None, False), ("x", False)])
def test_write_shaped_means_a_string_path_and_content_or_edits(args, shaped):
    assert confine.is_write_shaped(args) is shaped


# --------------------------------------------------------------------------- the overwrite that is confinable


def test_an_existing_plain_file_beneath_a_write_directory_is_confinable(world):
    assert check(world, world.w / "notes.md") == (True, "")
    assert check(world, world.w / "sub" / "deep.txt") == (True, "")
    assert check(world, world.w / "empty.md") == (True, "")
    assert check(world, world.w / "edge.md") == (True, "")                  # exactly the size cap


def test_the_largest_write_directory_match_decides_the_base(world):
    world.sc.sandbox["write"] = [str(world.w), str(world.w / "sub")]
    assert confine.write_target(str(world.w / "sub" / "deep.txt"), world.sc) == (str(world.w / "sub"), "deep.txt")
    assert confine.write_target(str(world.w / "notes.md"), world.sc) == (str(world.w), "notes.md")


# --------------------------------------------------------------------------- every row of the "false" table


def test_a_missing_file_is_a_create_and_is_asked(world):
    assert check(world, world.w / "new.md") == (False, "new_file")
    assert check(world, world.w / "sub" / "new.md") == (False, "new_file")
    assert check(world, world.w / "nodir" / "new.md") == (False, "new_file")
    assert check(world, world.w / "notes.md" / "x") == (False, "new_file")      # ENOTDIR: a name beneath a file


def test_a_symlink_on_the_last_component_or_in_the_middle_is_asked(world):
    assert check(world, world.w / "lnk.md") == (False, "symlink")
    assert check(world, world.w / "sublnk" / "deep.txt") == (False, "symlink")


@pytest.mark.parametrize("name, why", [("sub", "not_regular"), ("fifo.md", "not_regular"), ("run.md", "executable"), ("hard.md", "hard_link"),
                                       ("hard2.md", "hard_link"), ("big.md", "too_large")])
def test_the_kind_of_object_decides(world, name, why):
    assert check(world, world.w / name) == (False, why)


def test_a_directory_named_with_a_trailing_slash_is_not_a_file(world):
    assert check(world, str(world.w / "sub") + "/")[0] is False


@pytest.mark.parametrize("value", ["notes.md", "./notes.md", "w/notes.md", "", "~/notes.md", "{w}/../w/notes.md", "/{w}/notes.md", "{w}/./notes.md",
                                   "{w}//notes.md", "{w}/sub/../notes.md", "{w}/notes.md\x00.txt", "{w}/notes.md/", "{w}/notes.md/."])
def test_a_relative_or_unnormalised_or_odd_value_is_asked(world, value):
    ok, why = confine.write_check({"path": value.format(w=world.w), "content": "x"}, world.sc, world.undo)
    assert ok is False and why in ("bad_path", "outside_write_dir"), (value, why)


def test_dotdot_that_would_still_land_on_the_file_is_asked_not_normalised(world):
    assert check(world, str(world.w) + "/sub/../notes.md") == (False, "bad_path")
    assert check(world, str(world.w) + "/./notes.md") == (False, "bad_path")
    assert check(world, str(world.w) + "//notes.md") == (False, "bad_path")


def test_a_file_outside_every_write_directory_is_asked(world):
    assert check(world, world.other / "x.md") == (False, "outside_write_dir")
    assert check(world, "/etc/hostname") == (False, "outside_write_dir")
    assert check(world, str(world.w) + "x/notes.md") == (False, "outside_write_dir")       # same prefix, another directory
    assert check(world, world.w) == (False, "outside_write_dir")                           # the write directory itself is not a file under it


def test_the_walk_starts_at_the_write_directory_so_an_ancestor_symlink_does_not_matter_but_one_beneath_it_does(world):
    link = world.tmp / "wlink"
    link.symlink_to(world.w)
    world.sc.sandbox["write"] = [str(link)]                                # the operator's directory is opened normally (a symlinked base is fine)
    assert check(world, link / "notes.md") == (True, "")
    assert check(world, link / "lnk.md") == (False, "symlink")


def test_no_write_directory_no_sandbox_or_no_runtime_is_unsupported(world):
    world.sc.sandbox["write"] = []
    assert check(world, world.w / "notes.md") == (False, "unsupported")
    world.sc.sandbox = None
    assert check(world, world.w / "notes.md") == (False, "unsupported")


def test_a_server_that_cannot_be_confined_is_unsupported(world):
    world.sc.sandbox["runtime"] = []
    assert check(world, world.w / "notes.md") == (False, "unsupported")


@pytest.mark.parametrize("abi", [0, 1, 2])
def test_landlock_abi_below_3_is_unsupported(world, monkeypatch, abi):
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: abi)
    assert check(world, world.w / "notes.md") == (False, "unsupported")


@pytest.mark.parametrize("abi", [3, 4, 5, 6, 7, 9])
def test_landlock_abi_3_and_above_is_supported(world, monkeypatch, abi):
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: abi)
    assert check(world, world.w / "notes.md") == (True, "")


def test_no_openat2_is_unsupported(world, monkeypatch):
    monkeypatch.setattr(sandbox, "openat2_ok", lambda: False)
    assert check(world, world.w / "notes.md") == (False, "unsupported")


@pytest.mark.parametrize("args", [{"content": "x"}, {"path": 5, "content": "x"}, {"path": ["/w/notes.md"], "content": "x"}, {"path": None}, "x", None, []])
def test_args_that_are_not_a_write_of_one_string_path_are_asked_without_raising(world, args):
    ok, why = confine.write_check(args, world.sc, world.undo)
    assert ok is False and why in confine.WRITE_WHYS


def test_the_check_never_raises(world, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(sandbox, "open_beneath", boom)
    assert check(world, world.w / "notes.md")[0] is False


# --------------------------------------------------------------------------- no before-image, no auto-allow


def test_the_check_does_not_change_anything_on_disk_except_creating_the_undo_directory(world):
    before = {p.name: p.read_bytes() for p in world.w.iterdir() if p.is_file() and not p.is_fifo()}
    assert check(world, world.w / "notes.md")[0] is True
    assert {p.name: p.read_bytes() for p in world.w.iterdir() if p.is_file() and not p.is_fifo()} == before
    assert os.path.isdir(world.undo) and stat.S_IMODE(os.stat(world.undo).st_mode) == 0o700


def test_an_undo_directory_that_cannot_be_created_is_no_before_image(world):
    (world.tmp / "state").write_text("a file where the state directory should be")
    assert check(world, world.w / "notes.md") == (False, "no_before_image")


def test_an_undo_directory_that_is_not_writable_is_no_before_image(world):
    os.makedirs(world.undo, mode=0o700)
    os.chmod(world.undo, 0o500)
    try:
        if os.access(world.undo, os.W_OK):
            pytest.skip("running as a user that ignores directory modes (root)")
        assert check(world, world.w / "notes.md") == (False, "no_before_image")
    finally:
        os.chmod(world.undo, 0o700)


def test_a_full_disk_is_no_before_image(world, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "disk_usage", lambda p: SimpleNamespace(total=100, used=100, free=10))
    assert check(world, world.w / "notes.md") == (False, "no_before_image")


def test_an_undo_directory_inside_a_write_directory_is_no_before_image(world):
    """The before-image must live where the worker's server could never reach it, and a copy inside a write directory would be overwritable."""
    assert confine.write_check({"path": str(world.w / "notes.md"), "content": "x"}, world.sc, str(world.w / ".undo")) == (False, "no_before_image")
    assert confine.write_check({"path": str(world.w / "notes.md"), "content": "x"}, world.sc, str(world.tmp)) == (False, "no_before_image")


def test_a_file_the_proxy_cannot_read_is_no_before_image(world):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    os.chmod(world.w / "notes.md", 0o000)
    try:
        assert check(world, world.w / "notes.md")[1] == "no_before_image"
    finally:
        os.chmod(world.w / "notes.md", 0o644)


def test_force_true_makes_the_precheck_say_yes_for_everything_the_kernel_will_still_decide(world, monkeypatch):
    monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    for name in ("notes.md", "new.md", "lnk.md", "hard.md", "run.md", "fifo.md", "big.md"):
        assert check(world, world.w / name) == (True, ""), name
    assert check(world, world.other / "x.md") == (True, "")


# --------------------------------------------------------------------------- the before-image


def snap_of(world, name="notes.md", call_id="c1", n=0):
    base, rel = confine.write_target(str(world.w / name), world.sc)
    return confine.take_snapshot(base, rel, str(world.w / name), world.undo, call_id, n)


def test_a_snapshot_copies_the_bytes_hashes_them_and_records_the_inode(world):
    s = snap_of(world)
    o = os.stat(world.w / "notes.md")
    assert (s["dev"], s["ino"], s["nlink"], s["size_before"]) == (o.st_dev, o.st_ino, 1, 6)
    assert s["sha256_before"] == hashlib.sha256(b"NOTES\n").hexdigest()
    assert s["path"] == str(world.w / "notes.md") and s["value"] == "notes.md"
    assert s["undo"] == os.path.join(world.undo, "c1", "0")
    assert Path(s["undo"]).read_bytes() == b"NOTES\n"
    assert stat.S_IMODE(os.stat(s["undo"]).st_mode) == 0o600 and stat.S_IMODE(os.stat(os.path.dirname(s["undo"])).st_mode) == 0o700


def test_a_snapshot_of_an_empty_file_is_an_empty_copy_with_the_empty_hash(world):
    s = snap_of(world, "empty.md")
    assert s["size_before"] == 0 and s["sha256_before"] == hashlib.sha256(b"").hexdigest() and Path(s["undo"]).read_bytes() == b""


@pytest.mark.parametrize("name", ["missing.md", "lnk.md", "sub", "fifo.md", "big.md"])
def test_a_snapshot_of_anything_but_a_plain_small_file_fails_and_leaves_no_copy(world, name):
    with pytest.raises(confine.SnapshotError):
        snap_of(world, name)
    assert not os.path.exists(os.path.join(world.undo, "c1", "0"))


def test_a_snapshot_refuses_a_second_name_and_an_exec_bit_too(world):
    with pytest.raises(confine.SnapshotError):
        snap_of(world, "hard.md")
    with pytest.raises(confine.SnapshotError):
        snap_of(world, "run.md")


def test_a_snapshot_never_overwrites_an_existing_copy(world):
    snap_of(world)
    with pytest.raises(confine.SnapshotError):
        snap_of(world)


# --------------------------------------------------------------------------- the after-image and the wire record


def test_the_after_image_of_an_unchanged_file_has_the_same_hash_and_is_not_replaced(world):
    s = snap_of(world)
    a = confine.after_image(s)
    assert a == {"size_after": 6, "sha256_after": s["sha256_before"], "replaced": False}


def test_the_after_image_of_an_overwritten_file_has_the_new_hash_and_the_same_inode(world):
    s = snap_of(world)
    (world.w / "notes.md").write_text("NEW CONTENT\n")                 # in place: same inode
    a = confine.after_image(s)
    assert a["sha256_after"] == hashlib.sha256(b"NEW CONTENT\n").hexdigest() and a["size_after"] == 12 and a["replaced"] is False


def test_the_after_image_says_replaced_when_the_name_now_leads_to_another_inode(world):
    s = snap_of(world)
    (world.w / "tmp.md").write_text("ANOTHER FILE\n")                     # both exist at once, so the inode number cannot be reused
    os.replace(world.w / "tmp.md", world.w / "notes.md")
    a = confine.after_image(s)
    assert a["replaced"] is True and a["sha256_after"] == hashlib.sha256(b"ANOTHER FILE\n").hexdigest()


@pytest.mark.parametrize("how", ["unlink", "symlink", "dir"])
def test_the_after_image_when_the_name_is_gone_or_not_a_file_is_replaced_with_no_hash(world, how):
    s = snap_of(world)
    os.unlink(world.w / "notes.md")
    if how == "symlink":
        (world.w / "notes.md").symlink_to(world.other / "x.md")
    elif how == "dir":
        (world.w / "notes.md").mkdir()
    a = confine.after_image(s)
    assert a == {"size_after": None, "sha256_after": None, "replaced": True}


def test_the_wire_record_has_exactly_the_audit_fields_and_no_content(world):
    s = snap_of(world)
    rec = confine.write_record(s, confine.after_image(s))
    assert set(rec) == {"path", "dev", "ino", "size_before", "sha256_before", "size_after", "sha256_after", "replaced", "undo"}
    assert "NOTES" not in repr(rec)


# --------------------------------------------------------------------------- retention: by AGE, and a full store asks (never evicts evidence)


def mk_calls(world, n, size=100, age_s=0):
    import time
    os.makedirs(world.undo, mode=0o700, exist_ok=True)
    for i in range(n):
        d = Path(world.undo) / f"call{i}"
        d.mkdir()
        (d / "0").write_bytes(b"x" * size)
        t = time.time() - age_s + i
        os.utime(d, (t, t))


def test_prune_removes_only_what_is_older_than_the_retention_window(world):
    import time
    mk_calls(world, 2, age_s=40 * 86400)
    os.rename(Path(world.undo) / "call0", Path(world.undo) / "old0")
    os.rename(Path(world.undo) / "call1", Path(world.undo) / "old1")
    mk_calls(world, 3, age_s=0)
    confine.prune_undo(world.undo, max_age_s=30 * 86400)
    assert sorted(p.name for p in Path(world.undo).iterdir()) == ["call0", "call1", "call2"]
    assert time.time()


def test_prune_never_removes_by_count_so_the_original_before_image_of_a_path_survives_any_number_of_later_calls(world):
    mk_calls(world, 50, age_s=60)
    confine.prune_undo(world.undo, max_age_s=30 * 86400)
    assert len(list(Path(world.undo).iterdir())) == 50


def test_prune_never_removes_the_protected_call_and_never_follows_a_symlink_and_never_raises(world):
    mk_calls(world, 1, age_s=90 * 86400)
    victim = world.tmp / "victim"
    victim.mkdir()
    (victim / "keep").write_text("K")
    (Path(world.undo) / "evil").symlink_to(victim)
    confine.prune_undo(world.undo, max_age_s=0, protect="call0")
    assert (Path(world.undo) / "call0").exists() and (victim / "keep").read_text() == "K"
    confine.prune_undo("/nonexistent/undo")


def test_the_defaults_are_a_30_day_window_and_a_store_of_1000_calls_or_64_mib():
    assert (confine.UNDO_MAX_AGE_S, confine.UNDO_MAX_CALLS, confine.UNDO_MAX_BYTES) == (30 * 86400, 1000, 64 * 1024 * 1024)


def test_a_store_with_too_many_calls_is_full_and_the_write_asks_instead_of_evicting(world, monkeypatch):
    monkeypatch.setattr(confine, "UNDO_MAX_CALLS", 3)
    mk_calls(world, 2)
    assert check(world, world.w / "notes.md") == (True, "")
    mk_calls_more = Path(world.undo) / "call9"
    mk_calls_more.mkdir()
    assert check(world, world.w / "notes.md") == (False, "no_before_image")
    assert len(list(Path(world.undo).iterdir())) == 3                      # nothing was removed to make room


def test_a_store_with_too_many_bytes_is_full_too(world, monkeypatch):
    monkeypatch.setattr(confine, "UNDO_MAX_BYTES", 1000)
    mk_calls(world, 2, size=400)
    assert check(world, world.w / "notes.md") == (True, "")                  # 800 + this 6-byte file fits
    mk_calls_more = Path(world.undo) / "call9"
    mk_calls_more.mkdir()
    (mk_calls_more / "0").write_bytes(b"x" * 400)
    assert check(world, world.w / "notes.md") == (False, "no_before_image")


def test_a_snapshot_into_a_full_store_fails_even_if_the_precheck_said_yes(world, monkeypatch):
    monkeypatch.setattr(confine, "UNDO_MAX_CALLS", 1)
    mk_calls(world, 1)
    with pytest.raises(confine.SnapshotError, match="full"):
        snap_of(world)
    assert not (Path(world.undo) / "c1").exists()


# --------------------------------------------------------------------------- the undo directory belongs to the proxy user and nobody else


def test_an_undo_directory_that_is_group_or_world_writable_is_no_before_image(world):
    os.makedirs(world.undo, mode=0o700)
    for mode in (0o770, 0o707, 0o777, 0o720):
        os.chmod(world.undo, mode)
        assert check(world, world.w / "notes.md") == (False, "no_before_image"), oct(mode)
    os.chmod(world.undo, 0o700)
    assert check(world, world.w / "notes.md") == (True, "")
    os.chmod(world.undo, 0o755)                                              # readable by others is not writable by them
    assert check(world, world.w / "notes.md") == (True, "")


def test_an_undo_directory_owned_by_someone_else_is_no_before_image(world, monkeypatch):
    os.makedirs(world.undo, mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(world.undo).st_uid + 1)
    assert check(world, world.w / "notes.md") == (False, "no_before_image")


# --------------------------------------------------------------------------- the size of an edit is bounded (the policy can only count them)


def test_edits_whose_text_is_huge_are_not_confinable_even_in_one_edit(world):
    big = [{"oldText": "NOTES", "newText": "x" * 10_000_000}]
    assert confine.write_check({"path": str(world.w / "notes.md"), "edits": big}, world.sc, world.undo) == (False, "edits_too_large")


def test_edits_within_the_bound_are_confinable_and_the_bound_counts_every_string(world):
    ok = [{"oldText": "a" * 5000, "newText": "b" * 5000}] * 2
    assert confine.write_check({"path": str(world.w / "notes.md"), "edits": ok}, world.sc, world.undo) == (True, "")
    over = [{"oldText": "a" * 5000, "newText": "b" * 5000}] * 2 + [{"oldText": "c", "newText": "d" * 100}]
    assert confine.write_check({"path": str(world.w / "notes.md"), "edits": over}, world.sc, world.undo) == (False, "edits_too_large")
    assert confine.WRITE_EDITS_MAX_CHARS == 20000


@pytest.mark.parametrize("edits", ["x" * 30000, [["y" * 30000]], [{"a": {"b": "z" * 30000}}]])
def test_edits_of_any_shape_are_measured_by_their_strings(world, edits):
    assert confine.write_check({"path": str(world.w / "notes.md"), "edits": edits}, world.sc, world.undo) == (False, "edits_too_large")


# --------------------------------------------------------------------------- the grants a write decision produces


def test_a_write_grant_spec_is_the_write_directory_and_the_relative_name(world):
    assert confine.grant_specs({"path": str(world.w / "sub" / "deep.txt"), "content": "x"}, {"path": "write"}, world.sc) == \
        [[str(world.w), "sub/deep.txt", "write"]]


def test_a_write_confine_on_a_key_other_than_path_gets_no_grant(world):
    assert confine.grant_specs({"destination": str(world.w / "notes.md")}, {"destination": "write"}, world.sc) == []
    assert confine.grant_specs({"paths": [str(world.w / "notes.md")]}, {"paths": "write"}, world.sc) == []


def test_a_write_value_that_is_not_one_string_gets_no_grant(world):
    for v in (["/w/x"], 5, None, ""):
        assert confine.grant_specs({"path": v}, {"path": "write"}, world.sc) == []


# --------------------------------------------------------------------------- PINNED GAP: post-write races


def test_gap_post_write_race_the_after_image_records_whoever_wrote_last_not_what_the_worker_wrote(world):
    """The after-image is taken by the proxy AFTER the worker is gone, by name: a file another process (same uid) changes between the worker's last byte and
    that read is recorded as the call's result, and nothing in the record says who wrote it. The before-image only proves what was there BEFORE (and not even
    that if someone changed the file between the snapshot and the worker's start). DECISIONS D32, docs/boundary.md."""
    s = snap_of(world)
    (world.w / "notes.md").write_text("WHAT THE WORKER WROTE\n")                      # the confined worker's write
    (world.w / "notes.md").write_text("WHAT A CONCURRENT PROCESS WROTE AFTER IT\n")     # same inode, someone else, before the proxy looks
    a = confine.after_image(s)
    assert a["sha256_after"] == hashlib.sha256(b"WHAT A CONCURRENT PROCESS WROTE AFTER IT\n").hexdigest() and a["replaced"] is False


def test_gap_a_change_between_the_snapshot_and_the_call_is_not_in_the_before_image(world):
    s = snap_of(world)
    (world.w / "notes.md").write_text("CHANGED AFTER THE COPY\n")
    assert Path(s["undo"]).read_bytes() == b"NOTES\n" and s["sha256_before"] == hashlib.sha256(b"NOTES\n").hexdigest()      # the undo restores a stale version
    assert confine.after_image(s)["sha256_after"] != s["sha256_before"]
