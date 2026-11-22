"""THE KERNEL WRITE MATRIX through the REAL trampoline (DECISIONS D32): what a confined worker holding ONE `write` grant can do.

The grant is READ_FILE | WRITE_FILE | TRUNCATE on the O_PATH fd of one existing plain file, found by walking its name beneath the operator's write
directory, with no directory right of any kind. The answer, checked from OUTSIDE after every run (bytes, names, inodes, link counts, modes: a worker
could lie), is: it can overwrite, truncate, append to and read THAT inode, and nothing else. Not a neighbour (write, truncate, unlink), not a new name
(create, mkdir, mkfifo, symlink, a hard link to the granted inode or to a neighbour, into the directory, a subdirectory or its HOME), not a rename of the
granted file, not an unlink of it. A grant it cannot get (a second name, an exec bit, a symlink, a directory, a FIFO, a file past the size cap, a name that
is not there) is NO grant: every write is then denied.

Pinned GAPS (they assert the BAD outcome, so they stay visible; docs/boundary.md, D32): chmod of the granted file works (not mediated), a hard link
created by another process after the worker's fstat lets the granted inode be reached under a second name, a bind mount of a sensitive file under a
harmless name is granted like any file. The positive controls prove the probe can write at all."""
import atexit
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

import pytest

from sentinel_proxy import sandbox
from tests.no_skip_plugin import sandbox_skipif

pytestmark = [pytest.mark.slow,  # GATE_TIER=pr: real trampoline processes (docs/TESTING_REALITY.md "CI tiers")
              sandbox_skipif(sandbox.landlock_abi() < sandbox.WRITE_MIN_ABI or not sandbox.openat2_ok(),
                             reason="a write grant needs Landlock ABI >= 3 and openat2 on this host")]

TMPROOT = tempfile.mkdtemp(prefix="sbx-wgrant-homes-")
atexit.register(shutil.rmtree, TMPROOT, ignore_errors=True)
DENIED = {errno.EACCES, errno.EXDEV}           # a hard link out of the directory is EXDEV (no REFER), anything else EACCES

PROBE = r"""
import json, os, sys
def attempt(fn):
    try:
        r = fn()
        return "ok" if r is None else r
    except OSError as e:
        return e.errno
def wr(path, mode, data="WRITTEN"):
    def f():
        with open(path, mode) as fh:
            fh.write(data)
    return f
def mk(path, mode=os.O_WRONLY):
    def f():
        os.close(os.open(path, mode, 0o644))
    return f
OPS = {
    "create": lambda a, b: wr(a, "x"),
    "create_creat": lambda a, b: mk(a, os.O_WRONLY | os.O_CREAT),
    "overwrite": lambda a, b: wr(a, "w"),
    "overwrite_rplus": lambda a, b: wr(a, "r+"),
    "append": lambda a, b: wr(a, "a"),
    "open_wronly": lambda a, b: mk(a, os.O_WRONLY),
    "truncate": lambda a, b: (lambda: os.truncate(a, 0)),
    "ftruncate_open": lambda a, b: (lambda: os.ftruncate(os.open(a, os.O_RDWR), 0)),
    "rename": lambda a, b: (lambda: os.rename(a, b)),
    "rename_over": lambda a, b: (lambda: os.rename(b, a)),
    "unlink": lambda a, b: (lambda: os.unlink(a)),
    "mkdir": lambda a, b: (lambda: os.mkdir(a)),
    "symlink": lambda a, b: (lambda: os.symlink(b, a)),
    "link": lambda a, b: (lambda: os.link(b, a)),
    "mkfifo": lambda a, b: (lambda: os.mkfifo(a)),
    "chmod": lambda a, b: (lambda: os.chmod(a, 0o755)),
    "read": lambda a, b: (lambda: open(a).read()),
    "list": lambda a, b: (lambda: os.listdir(a)),
}
if os.environ.get("WAIT_FOR_GO"):
    sys.stdin.readline()
for op, a, b in json.loads(sys.argv[1]):
    print(json.dumps([op, attempt(OPS[op](a, b))]), flush=True)
"""


def confined(grants):
    return {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True,
            "grants": [list(g) for g in grants]}


def status_of(stderr):
    return json.loads([ln for ln in stderr.splitlines() if ln.startswith("SENTINEL_SANDBOX_STATUS ")][0].split(" ", 1)[1])


def run(grants, ops, swap=None):
    """ops: [(op, a, b)] -> ([result], status). A result is "ok" or an errno. `swap()` runs in the test process AFTER the worker has applied its
    ruleset (its status line is out) and BEFORE the first op: a change another process makes inside the window."""
    spec = confined(grants)
    cmd, argv, env = sandbox.sandbox_params(spec, sys.executable, ["-c", PROBE, json.dumps(ops)],
                                            {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT, **({"WAIT_FOR_GO": "1"} if swap else {})})
    p = subprocess.Popen([cmd, *argv], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    head = ""
    try:
        if swap:
            for line in iter(p.stderr.readline, ""):
                head += line
                if line.startswith("SENTINEL_SANDBOX_STATUS "):
                    break
            swap()
            p.stdin.write("go\n")
            p.stdin.flush()
        out, err = p.communicate(timeout=60)
    finally:
        if p.poll() is None:
            p.kill()
    assert p.returncode == 0, (p.returncode, out, err)
    res = [json.loads(ln) for ln in out.splitlines()]
    assert [o for o, _ in res] == [o for o, _a, _b in ops]
    return [r for _, r in res], status_of(head + err)


def snapshot(d):
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(root, n)
            s = os.lstat(p)
            kind = "dir" if stat.S_ISDIR(s.st_mode) else "link" if stat.S_ISLNK(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other"
            data = open(p, "rb").read() if kind == "file" else os.readlink(p) if kind == "link" else None
            out[os.path.relpath(p, d)] = (kind, s.st_ino, s.st_nlink, stat.S_IMODE(s.st_mode), data)
    return out


@pytest.fixture
def tree(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a.md").write_text("GRANTED")
    (d / "neighbour.md").write_text("NEIGHBOUR")
    (d / ".env").write_text("SECRET-CREDENTIAL")
    (d / "sub").mkdir()
    (d / "sub" / "inner.md").write_text("INNER")
    return d


def ops_for(w, home=TMPROOT):
    f = lambda t: t.format(w=w, home=home)           # noqa: E731
    return [(o, f(a), f(b)) for o, a, b in [
        # a neighbour, a secret, a file in a subdirectory: no write of any kind
        ("overwrite", "{w}/neighbour.md", ""), ("overwrite_rplus", "{w}/neighbour.md", ""), ("append", "{w}/neighbour.md", ""),
        ("open_wronly", "{w}/neighbour.md", ""), ("truncate", "{w}/neighbour.md", ""), ("ftruncate_open", "{w}/neighbour.md", ""),
        ("unlink", "{w}/neighbour.md", ""), ("overwrite", "{w}/.env", ""), ("truncate", "{w}/.env", ""), ("unlink", "{w}/.env", ""),
        ("overwrite", "{w}/sub/inner.md", ""), ("truncate", "{w}/sub/inner.md", ""),
        # the granted file: every way but the content
        ("rename", "{w}/a.md", "{w}/renamed.md"), ("rename", "{w}/a.md", "{w}/sub/moved.md"), ("rename", "{w}/a.md", "{home}/away.md"),
        ("rename_over", "{w}/a.md", "{w}/neighbour.md"), ("rename_over", "{w}/neighbour.md", "{w}/a.md"), ("rename_over", "{w}/.env", "{w}/a.md"),
        ("unlink", "{w}/a.md", ""),
        # a name that does not exist
        ("create", "{w}/new.md", ""), ("create_creat", "{w}/new2.md", ""), ("create", "{w}/sub/new.md", ""), ("create", "{w}/a.md.bak", ""),
        ("mkdir", "{w}/newdir", ""), ("mkfifo", "{w}/fifo", ""),
        ("symlink", "{w}/lnk", "{w}/.env"), ("symlink", "{w}/lnk2", "a.md"), ("symlink", "{w}/sub/lnk3", "{w}/a.md"),
        # a new name for the granted inode, a neighbour, the secret
        ("link", "{w}/hard.md", "{w}/a.md"), ("link", "{w}/sub/hard2.md", "{w}/a.md"), ("link", "{home}/hard3.md", "{w}/a.md"),
        ("link", "{w}/hard4.md", "{w}/.env"), ("link", "{w}/hard5.md", "{w}/neighbour.md"),
    ]]


def test_the_granted_file_can_be_overwritten_truncated_appended_and_read_and_nothing_else_changes(tree):
    before = snapshot(tree)
    ino = os.stat(tree / "a.md").st_ino
    ops = [("read", f"{tree}/a.md", ""), ("overwrite", f"{tree}/a.md", ""), ("overwrite_rplus", f"{tree}/a.md", ""), ("append", f"{tree}/a.md", ""),
           ("open_wronly", f"{tree}/a.md", ""), ("truncate", f"{tree}/a.md", ""), ("ftruncate_open", f"{tree}/a.md", ""), ("read", f"{tree}/a.md", "")]
    res, st = run([(str(tree), "a.md", "write")], ops)
    assert [r for (op, _a, _b), r in zip(ops, res) if op != "read"] == ["ok"] * 6 and res[0] == "GRANTED" and res[-1] == "", res
    after = snapshot(tree)
    assert os.stat(tree / "a.md").st_ino == ino and os.stat(tree / "a.md").st_nlink == 1          # in place: the same inode, still one name
    changed = {k for k in after if after[k] != before.get(k)}
    assert changed == {"a.md"}, changed                                                          # no other byte, name, inode, link count or mode
    assert set(after) == set(before)
    assert after["a.md"][4] == b""                                                                # the last ops truncated it: its content is the only change


def test_what_the_worker_wrote_is_exactly_what_the_ops_say(tree):
    ops = [("overwrite", f"{tree}/a.md", "")]
    run([(str(tree), "a.md", "write")], ops)
    assert (tree / "a.md").read_text() == "WRITTEN"
    run([(str(tree), "a.md", "write")], [("truncate", f"{tree}/a.md", "")])
    assert (tree / "a.md").read_bytes() == b""


def test_every_other_way_to_change_the_tree_is_denied_and_nothing_changes(tree):
    before = snapshot(tree)
    ops = ops_for(tree)
    res, _ = run([(str(tree), "a.md", "write")], ops)
    bad = [(op, a, b, r) for (op, a, b), r in zip(ops, res) if r not in DENIED]
    assert not bad, bad
    assert snapshot(tree) == before


def test_the_denials_are_the_same_with_a_second_unrelated_read_and_list_grant_next_to_the_write_grant(tree):
    before = snapshot(tree)
    ops = ops_for(tree)
    res, _ = run([(str(tree), "a.md", "write"), ("/", str(tree / "neighbour.md"), "read"), ("/", str(tree / "sub"), "list")], ops)
    bad = [(op, a, b, r) for (op, a, b), r in zip(ops, res) if r not in DENIED and not (op in ("read", "list"))]
    # a read grant gives READ only: no write op is allowed through it either
    assert not bad, bad
    assert snapshot(tree) == before


def test_the_write_grant_names_one_file_so_a_grant_for_a_neighbour_does_not_cover_a_a_md(tree):
    before = snapshot(tree)
    res, _ = run([(str(tree), "neighbour.md", "write")], [("overwrite", f"{tree}/a.md", ""), ("overwrite", f"{tree}/neighbour.md", "")])
    assert res[0] in DENIED and res[1] == "ok"
    assert (tree / "a.md").read_text() == "GRANTED" and (tree / "neighbour.md").read_text() == "WRITTEN"
    assert {k for k, v in snapshot(tree).items() if v != before[k]} == {"neighbour.md"}


def test_a_nested_name_is_walked_beneath_the_base_and_grants_only_that_file(tree):
    before = snapshot(tree)
    res, _ = run([(str(tree), "sub/inner.md", "write")], [("overwrite", f"{tree}/sub/inner.md", ""), ("overwrite", f"{tree}/a.md", ""),
                                                          ("create", f"{tree}/sub/new.md", ""), ("unlink", f"{tree}/sub/inner.md", "")])
    assert res[0] == "ok" and all(r in DENIED for r in res[1:])
    assert {k for k, v in snapshot(tree).items() if v != before.get(k)} == {"sub/inner.md"}


# --------------------------------------------------------------------------- a grant that cannot be had is no grant


def granted_of(grants, ops):
    """(results, status) with the status line parsed."""
    spec = confined(grants)
    cmd, argv, env = sandbox.sandbox_params(spec, sys.executable, ["-c", PROBE, json.dumps(ops)], {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT})
    p = subprocess.run([cmd, *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return [json.loads(ln)[1] for ln in p.stdout.splitlines()], status_of(p.stderr)


def test_a_write_grant_reports_the_device_inode_and_link_count_it_granted_in_the_status(tree):
    _, st = granted_of([(str(tree), "a.md", "write")], [("read", f"{tree}/a.md", "")])
    o = os.stat(tree / "a.md")
    assert st["confined"] is True and "landlock_fs" in st["layers"] and not st["missing"]
    assert st["granted"] == ["a.md"] and st["write_granted"] == [{"value": "a.md", "dev": o.st_dev, "ino": o.st_ino, "nlink": 1}]


@pytest.fixture
def awkward(tree):
    os.link(tree / "a.md", tree / "second.md")                      # a second name for the inode
    (tree / "run.md").write_text("#!/bin/sh")
    os.chmod(tree / "run.md", 0o755)
    (tree / "lnk.md").symlink_to(tree / "a.md")
    os.mkfifo(tree / "fifo.md")
    (tree / "big.md").write_bytes(b"x" * (sandbox.WRITE_MAX_BYTES + 1))
    (tree / "cred-link.md").write_text("x")
    os.link(tree / ".env", tree / "linked-to-env.md")               # the real danger: a harmless name for a credential's inode
    return tree


@pytest.mark.parametrize("name", ["second.md", "a.md", "run.md", "lnk.md", "fifo.md", "big.md", "missing.md", "sub", "linked-to-env.md", ".env"])
def test_a_write_grant_the_worker_may_not_have_is_no_grant_so_not_a_byte_is_written(awkward, name):
    """`a.md`/`second.md` are two names of one inode (nlink 2): the grant is refused under EITHER name, which is the point of the link-count rule.
    `linked-to-env.md` and `.env` are two names of the credential: refused as well."""
    before = snapshot(awkward)
    ops = [("overwrite", f"{awkward}/{name}", ""), ("truncate", f"{awkward}/{name}", ""), ("overwrite", f"{awkward}/a.md", ""),
           ("overwrite", f"{awkward}/.env", "")]
    res, st = granted_of([(str(awkward), name, "write")], ops)
    assert "ok" not in res and all(isinstance(r, int) for r in res), res
    assert st["granted"] == [] and "write_granted" not in st
    assert snapshot(awkward) == before


def test_an_absolute_or_dotdot_write_value_is_never_walked_from_slash_or_out_of_its_base(tree):
    """The spec rejects these before any process starts (tests/proxy/test_sandbox_grants_spec.py); even a worker that somehow got one grants nothing."""
    assert sandbox.open_grant(str(tree / "sub"), str(tree / "a.md"), "write") is None
    assert sandbox.open_grant(str(tree / "sub"), "../a.md", "write") is None


# --------------------------------------------------------------------------- a change another process makes after the grant


def test_a_name_swapped_to_another_file_after_the_grant_is_denied_and_the_other_file_is_unchanged(tree):
    before_env = (tree / ".env").read_bytes()

    def swap():
        os.rename(tree / "a.md", tree / "old.md")                          # the granted inode now lives under another name
        (tree / "a.md").write_text("A NEW FILE AT THE NAME")

    res, _ = run([(str(tree), "a.md", "write")], [("overwrite", f"{tree}/a.md", "")], swap=swap)
    assert res == [errno.EACCES]
    assert (tree / "a.md").read_text() == "A NEW FILE AT THE NAME" and (tree / ".env").read_bytes() == before_env


def test_a_symlink_put_at_the_name_after_the_grant_is_not_followed_into_the_credential(tree):
    def swap():
        os.rename(tree / "a.md", tree / "old.md")
        (tree / "a.md").symlink_to(tree / ".env")

    res, _ = run([(str(tree), "a.md", "write")], [("overwrite", f"{tree}/a.md", ""), ("truncate", f"{tree}/a.md", "")], swap=swap)
    assert all(r == errno.EACCES for r in res), res
    assert (tree / ".env").read_text() == "SECRET-CREDENTIAL"


def test_the_granted_inode_stays_writable_under_the_name_it_was_renamed_to_by_someone_else(tree):
    """The grant is the INODE: if another process renames it, the old name no longer reaches it (open with O_CREAT of a missing name needs MAKE_REG:
    EACCES) while the inode itself stays writable under its new name. Nobody can rename it from inside (EACCES above), so this is not an escape."""
    def swap():
        os.rename(tree / "a.md", tree / "moved.md")

    res, _ = run([(str(tree), "a.md", "write")], [("overwrite", f"{tree}/a.md", ""), ("overwrite", f"{tree}/moved.md", "")], swap=swap)
    assert res[0] == errno.EACCES and res[1] == "ok" and (tree / "moved.md").read_text() == "WRITTEN"


# --------------------------------------------------------------------------- PINNED GAPS (the bad outcome is the assertion)


def test_gap_hard_link_created_after_status_the_granted_inode_is_then_reachable_under_a_second_name(tree):
    """Landlock has no link-count rule and the worker's fstat is one instant: a hard link another process of the SAME uid makes between that fstat and the
    server's open names the granted inode a second time (a build step, an approved shell). The write goes through, and the content is then visible (and,
    if the link sits at an executable path such as a hook, RUN) under the other name. The proxy checks the link count before the worker starts and the
    worker at its fstat; this window (one worker start, ~0.2-1 s) cannot be closed. DECISIONS D32."""
    (tree / "sub").mkdir(exist_ok=True)

    def swap():
        os.link(tree / "a.md", tree / "sub" / "hook")

    res, _ = run([(str(tree), "a.md", "write")], [("overwrite", f"{tree}/a.md", "")], swap=swap)
    assert res == ["ok"]
    assert (tree / "sub" / "hook").read_text() == "WRITTEN" and os.stat(tree / "a.md").st_nlink == 2


def test_gap_chmod_on_the_granted_file_works_because_landlock_does_not_mediate_it(tree):
    """chmod, chown, utimes and xattrs on a file the uid owns are not Landlock rights. A server could add +x to the granted file; ours have no such tool
    (the filesystem server and Desktop Commander's write path never chmod an existing file). The exec BIT is refused when the grant is made, not after."""
    res, _ = run([(str(tree), "a.md", "write")], [("chmod", f"{tree}/a.md", ""), ("chmod", f"{tree}/neighbour.md", "")])
    assert res[0] == "ok"
    assert stat.S_IMODE(os.stat(tree / "a.md").st_mode) == 0o755
    assert res[1] == "ok" and stat.S_IMODE(os.stat(tree / "neighbour.md").st_mode) == 0o755          # not even limited to the granted file


def _can_bind_mount(tmp_path) -> bool:
    if os.geteuid() != 0 or shutil.which("mount") is None or shutil.which("umount") is None:
        return False
    a, b = tmp_path / "bm_a", tmp_path / "bm_b"
    a.write_text("x")
    b.write_text("y")
    if subprocess.run(["mount", "--bind", str(a), str(b)], capture_output=True).returncode != 0:
        return False
    subprocess.run(["umount", str(b)], capture_output=True)
    return True


def test_gap_a_bind_mount_of_a_credential_under_a_harmless_name_is_granted_like_any_file(tree, tmp_path):
    """A bind mount makes ONE inode appear at a second path without raising its link count. `notes.md` is then the credential: it is a plain file with
    one name, so the grant is given and the credential is overwritten. Only an operator-made mount can do this (it needs CAP_SYS_ADMIN); the proxy
    cannot see mounts. Skipped where the host does not let this test mount. DECISIONS D32."""
    if not _can_bind_mount(tmp_path):
        pytest.skip("needs root and permission to bind-mount (the gap is documented in docs/boundary.md)")
    bound = tree / "notes.md"
    bound.write_text("HARMLESS")
    subprocess.run(["mount", "--bind", str(tree / ".env"), str(bound)], check=True)
    try:
        res, _ = run([(str(tree), "notes.md", "write")], [("overwrite", f"{tree}/notes.md", "")])
        assert res == ["ok"]
        assert (tree / ".env").read_text() == "WRITTEN"                    # the credential file was overwritten through a harmless name
    finally:
        subprocess.run(["umount", str(bound)], capture_output=True)
