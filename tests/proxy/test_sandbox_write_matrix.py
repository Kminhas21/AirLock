"""WRITE MATRIX through the REAL trampoline (phase 1 of the "narrow write right" plan): what a confined worker can do to the filesystem when
it holds only `read` / `list` grants. TODAY the answer is: nothing. Create, overwrite, append, truncate, rename (from, onto, away), unlink,
mkdir, symlink, hard link, a neighbour's content, a name the grant was not for: every one is denied by the kernel, and after each run the
test re-reads the tree from OUTSIDE and compares bytes, names, link counts and inodes, which is the strongest assertion (a worker could lie).

This pins CURRENT behaviour. When a `write` right is added, the cases that become allowed must be flipped on purpose, and these stay as the
negative control for every grant that is NOT `write`. The positive control (the private HOME is writable) proves the probe can write at all."""
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
              sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok(),
                             reason="exact grants need Landlock and openat2 on this host")]

TMPROOT = tempfile.mkdtemp(prefix="sbx-wmatrix-homes-")
atexit.register(shutil.rmtree, TMPROOT, ignore_errors=True)
EACCES = errno.EACCES
DENIED = {errno.EACCES, errno.EXDEV}           # a hard link out of the grant's directory is EXDEV (no REFER), anything else EACCES

PROBE = r"""
import json, os, sys
def attempt(fn):
    try:
        fn()
        return "ok"
    except OSError as e:
        return e.errno
def wr(path, mode, data="X"):
    def f():
        with open(path, mode) as fh:
            fh.write(data)
    return f
def mk(path, mode=os.O_WRONLY):
    def f():
        os.close(os.open(path, mode, 0o644))
    return f
OPS = {
    "create": lambda a, b: wr(a, "x"),                                  # O_CREAT|O_EXCL of a new name
    "create_creat": lambda a, b: mk(a, os.O_WRONLY | os.O_CREAT),
    "overwrite": lambda a, b: wr(a, "w"),                               # open(O_WRONLY|O_TRUNC)
    "overwrite_rplus": lambda a, b: wr(a, "r+"),                        # open(O_RDWR)
    "append": lambda a, b: wr(a, "a"),
    "open_wronly": lambda a, b: mk(a, os.O_WRONLY),
    "truncate": lambda a, b: (lambda: os.truncate(a, 0)),
    "rename": lambda a, b: (lambda: os.rename(a, b)),
    "rename_over": lambda a, b: (lambda: os.rename(b, a)),
    "unlink": lambda a, b: (lambda: os.unlink(a)),
    "mkdir": lambda a, b: (lambda: os.mkdir(a)),
    "symlink": lambda a, b: (lambda: os.symlink(b, a)),
    "link": lambda a, b: (lambda: os.link(b, a)),                       # a NEW name for the existing inode b
    "mkfifo": lambda a, b: (lambda: os.mkfifo(a)),
    "read": lambda a, b: (lambda: open(a).read()),
    "list": lambda a, b: (lambda: os.listdir(a)),
}
for op, a, b in json.loads(sys.argv[1]):
    print(json.dumps([op, attempt(OPS[op](a, b))]), flush=True)
"""


def confined(grants):
    return {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True,
            "grants": [list(g) for g in grants]}


def run(grants, ops):
    """ops: [(op, a, b)] -> {op: result} (a result is "ok" or an errno). Several ops with the same name use op#n labels."""
    spec = confined(grants)
    cmd, argv, env = sandbox.sandbox_params(spec, sys.executable, ["-c", PROBE, json.dumps(ops)], {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT})
    p = subprocess.run([cmd, *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    st = json.loads([ln for ln in p.stderr.splitlines() if ln.startswith("SENTINEL_SANDBOX_STATUS ")][0].split(" ", 1)[1])
    assert st["confined"] is True and "landlock_fs" in st["layers"] and not st["missing"]
    out = [json.loads(ln) for ln in p.stdout.splitlines()]
    assert [o for o, _ in out] == [o for o, _a, _b in ops]
    return [r for _, r in out], st


def snapshot(d):
    """name -> (kind, inode, nlink, mode, bytes) for the whole tree: the ground truth, read from OUTSIDE the sandbox."""
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
    (d / "a.txt").write_text("GRANTED")
    (d / "neighbour.txt").write_text("NEIGHBOUR")
    (d / "secret").write_text("SECRET")
    (d / "sub").mkdir()
    (d / "sub" / "inner.txt").write_text("INNER")
    return d


# every way to change something that is not a read, aimed at the granted file, a neighbour, a new name, a directory
FILE_OPS = [("overwrite", "{w}/a.txt", ""), ("overwrite_rplus", "{w}/a.txt", ""), ("append", "{w}/a.txt", ""),
            ("open_wronly", "{w}/a.txt", ""), ("truncate", "{w}/a.txt", ""),
            ("rename", "{w}/a.txt", "{w}/renamed.txt"), ("rename", "{w}/a.txt", "{w}/sub/moved.txt"), ("rename_over", "{w}/a.txt", "{w}/neighbour.txt"),
            ("unlink", "{w}/a.txt", ""),
            ("overwrite", "{w}/neighbour.txt", ""), ("truncate", "{w}/neighbour.txt", ""), ("unlink", "{w}/neighbour.txt", ""),
            ("overwrite", "{w}/secret", ""), ("overwrite", "{w}/sub/inner.txt", ""),
            ("create", "{w}/new.txt", ""), ("create_creat", "{w}/new2.txt", ""), ("create", "{w}/sub/new.txt", ""),
            ("mkdir", "{w}/newdir", ""), ("mkfifo", "{w}/fifo", ""),
            ("symlink", "{w}/lnk", "{w}/secret"), ("symlink", "{w}/lnk2", "a.txt"),
            ("link", "{w}/hard.txt", "{w}/a.txt"), ("link", "{w}/hard2.txt", "{w}/secret"), ("link", "{w}/sub/hard3.txt", "{w}/a.txt"),
            ("link", "{home}/hard4.txt", "{w}/a.txt")]


def expand(ops, w, home=TMPROOT):
    return [(o, a.format(w=w, home=home), b.format(w=w, home=home)) for o, a, b in ops]


def test_a_read_grant_on_a_file_allows_the_read_and_every_write_op_is_denied(tree):
    before = snapshot(tree)
    ops = [("read", f"{tree}/a.txt", "")] + expand(FILE_OPS, tree)
    res, st = run([("/", str(tree / "a.txt"), "read")], ops)
    assert res[0] == "ok"
    bad = [(op, r) for (op, a, b), r in zip(ops[1:], res[1:]) if r not in DENIED]
    assert not bad, bad
    assert snapshot(tree) == before                   # no byte, name, inode, link count or mode changed; nothing new exists
    assert st["granted"] == [str(tree / "a.txt")]


def test_a_list_grant_on_a_directory_lists_it_and_every_write_op_is_denied(tree):
    before = snapshot(tree)
    ops = [("list", str(tree), "")] + expand(FILE_OPS, tree)
    res, st = run([("/", str(tree), "list")], ops)
    assert res[0] == "ok"
    bad = [(op, r) for (op, a, b), r in zip(ops[1:], res[1:]) if r not in DENIED]
    assert not bad, bad
    assert snapshot(tree) == before
    assert st["granted"] == [str(tree)]


def test_a_read_grant_and_a_list_grant_together_still_deny_every_write_op(tree):
    before = snapshot(tree)
    ops = expand(FILE_OPS, tree)
    res, _ = run([("/", str(tree / "a.txt"), "read"), ("/", str(tree), "list")], ops)
    assert [(op, r) for (op, _a, _b), r in zip(ops, res) if r not in DENIED] == []
    assert snapshot(tree) == before


def test_a_list_grant_on_a_subdirectory_gives_no_write_to_its_parent_or_itself(tree):
    before = snapshot(tree)
    ops = expand([("create", "{w}/sub/new.txt", ""), ("overwrite", "{w}/sub/inner.txt", ""), ("unlink", "{w}/sub/inner.txt", ""),
                  ("rename", "{w}/sub/inner.txt", "{w}/sub/other.txt"), ("create", "{w}/top.txt", ""), ("mkdir", "{w}/sub/d", "")], tree)
    res, _ = run([("/", str(tree / "sub"), "list"), ("/", str(tree / "sub" / "inner.txt"), "read")], ops)
    assert [(op, r) for (op, _a, _b), r in zip(ops, res) if r not in DENIED] == []
    assert snapshot(tree) == before


def test_a_hard_link_to_the_granted_inode_is_denied_and_the_link_count_stays_one(tree):
    res, _ = run([("/", str(tree / "a.txt"), "read")],
                 expand([("link", "{w}/hard.txt", "{w}/a.txt"), ("link", "{home}/h.txt", "{w}/a.txt")], tree, TMPROOT))
    assert all(r in DENIED for r in res)
    assert os.stat(tree / "a.txt").st_nlink == 1 and not (tree / "hard.txt").exists()


def test_a_write_through_a_second_name_of_the_inode_is_a_pinned_read_only_fact(tree):
    """A hard link that already existed when the grant was made names the same inode: the grant is READ_FILE on it, so reading works under
    either name and writing through either name is denied (the write right will have to refuse nlink > 1; today nothing can write)."""
    os.link(tree / "a.txt", tree / "second.txt")
    before = snapshot(tree)
    ops = [("read", f"{tree}/second.txt", ""), ("overwrite", f"{tree}/second.txt", ""), ("overwrite", f"{tree}/a.txt", ""),
           ("truncate", f"{tree}/second.txt", ""), ("unlink", f"{tree}/second.txt", "")]
    res, _ = run([("/", str(tree / "a.txt"), "read")], ops)
    assert res[0] == "ok" and all(r in DENIED for r in res[1:])
    assert snapshot(tree) == before


def test_a_symlink_named_as_a_grant_gives_no_grant_so_neither_read_nor_write(tree):
    (tree / "lnk").symlink_to(tree / "a.txt")
    before = snapshot(tree)
    ops = [("read", f"{tree}/lnk", ""), ("overwrite", f"{tree}/lnk", ""), ("overwrite", f"{tree}/a.txt", ""), ("unlink", f"{tree}/lnk", "")]
    res, st = run([("/", str(tree / "lnk"), "read")], ops)
    assert all(r in DENIED for r in res) and st["granted"] == []
    assert snapshot(tree) == before


def test_positive_control_the_private_home_is_the_one_writable_place(tree):
    """The probe CAN write: into the worker's own HOME (created by the trampoline). Without this the matrix above could pass vacuously."""
    code = ("import os,json;h=os.environ['HOME'];"
            "open(h+'/x','w').write('ok');os.rename(h+'/x',h+'/y');os.symlink('y',h+'/z');os.unlink(h+'/z');os.mkdir(h+'/d');"
            "print(json.dumps(sorted(os.listdir(h))))")
    cmd, argv, env = sandbox.sandbox_params(confined([("/", str(tree / "a.txt"), "read")]), sys.executable, ["-c", code],
                                            {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT})
    p = subprocess.run([cmd, *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.splitlines()[-1]) == ["d", "y"]
    assert (tree / "a.txt").read_text() == "GRANTED"


def test_an_unconfined_worker_with_a_write_directory_can_write_so_the_matrix_measures_the_grants(tree):
    """Second control: with the operator's `write` directory (not a grant) the same ops that were denied DO succeed, so the denials above come
    from the grant model and not from a broken probe or a read-only tree."""
    spec = {"read": [], "write": [str(tree)], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}
    ops = expand([("overwrite", "{w}/a.txt", ""), ("create", "{w}/new.txt", ""), ("rename", "{w}/new.txt", "{w}/moved.txt"),
                  ("unlink", "{w}/moved.txt", "")], tree)
    cmd, argv, env = sandbox.sandbox_params(spec, sys.executable, ["-c", PROBE, json.dumps(ops)], {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT})
    p = subprocess.run([cmd, *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert [json.loads(ln)[1] for ln in p.stdout.splitlines()] == ["ok"] * 4
    assert (tree / "a.txt").read_text() == "X" and not (tree / "new.txt").exists()
