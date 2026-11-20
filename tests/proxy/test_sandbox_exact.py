"""Exact grants through the REAL trampoline (DECISIONS D31): a confined worker may read only the objects named in `grants`, each found by
walking the written string beneath its base with openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS). Everything else is EACCES."""
import atexit
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from sentinel_proxy import sandbox
from tests.no_skip_plugin import sandbox_skipif

pytestmark = [pytest.mark.slow,  # GATE_TIER=pr: real trampoline processes (docs/TESTING_REALITY.md "CI tiers")
              sandbox_skipif(sandbox.landlock_abi() < 1 or not sandbox.openat2_ok(),
                             reason="exact grants need Landlock and openat2 on this host")]

TMPROOT = tempfile.mkdtemp(prefix="sbx-exact-homes-")
atexit.register(shutil.rmtree, TMPROOT, ignore_errors=True)
EACCES = errno.EACCES

READER = r"""
import json, os, sys
def t(op, p):
    try:
        if op == "read":
            with open(p) as f:
                return ["ok", f.read()]
        return ["ok", sorted(os.listdir(p))]
    except OSError as e:
        return ["err", e.errno]
steps = json.loads(sys.argv[1])
for i, batch in enumerate(steps):
    if i:
        sys.stdin.readline()
    print(json.dumps([t(op, p) for op, p in batch]), flush=True)
"""


def confined(grants, runtime=()):
    return {"read": [], "write": [], "runtime": list(runtime), "network": "none", "env_allow": [], "rlimits": {}, "require": True,
            "grants": [list(g) for g in grants]}


def start(spec, *batches):
    cmd, argv, env = sandbox.sandbox_params(spec, sys.executable, ["-c", READER, json.dumps(batches)],
                                            {"PATH": "/usr/bin:/bin", "TMPDIR": TMPROOT})
    return subprocess.Popen([cmd, *argv], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def run(spec, *ops):
    p = start(spec, list(ops))
    out, err = p.communicate(timeout=60)
    assert p.returncode == 0, (p.returncode, out, err)
    return json.loads(out.splitlines()[-1]), status(err)


def status(err):
    line = [ln for ln in err.splitlines() if ln.startswith("SENTINEL_SANDBOX_STATUS ")]
    assert len(line) == 1, err
    return json.loads(line[0].split(" ", 1)[1])


@pytest.fixture
def tree(tmp_path):
    d = tmp_path / "w"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / "sibling.txt").write_text("SIBLING")
    (d / "sub" / "inner.txt").write_text("INNER")
    (d / "secret").write_text("SECRET")
    (d / "lnk").symlink_to(d / "sibling.txt")
    return d


def test_a_read_grant_reads_exactly_that_file_and_nothing_next_to_it(tree):
    (a, sib, parent, inner), st = run(confined([("/", str(tree / "a.txt"), "read")]),
                                      ("read", str(tree / "a.txt")), ("read", str(tree / "sibling.txt")), ("list", str(tree)),
                                      ("read", str(tree / "sub" / "inner.txt")))
    assert a == ["ok", "A"]
    assert sib == parent == inner == ["err", EACCES]
    assert st["confined"] is True and st["granted"] == [str(tree / "a.txt")] and "landlock_fs" in st["layers"] and not st["missing"]


def test_a_relative_value_is_walked_from_its_base(tree):
    (a,), st = run(confined([(str(tree), "a.txt", "read")]), ("read", str(tree / "a.txt")))
    assert a == ["ok", "A"] and st["granted"] == ["a.txt"]


def test_a_symlink_anywhere_in_the_name_gives_no_grant(tree):
    (via_link, target), st = run(confined([("/", str(tree / "lnk"), "read")]),
                                 ("read", str(tree / "lnk")), ("read", str(tree / "sibling.txt")))
    assert via_link == target == ["err", EACCES] and st["granted"] == []


def test_a_symlinked_directory_component_gives_no_grant(tree):
    (tree / "dlnk").symlink_to(tree / "sub")
    (r,), st = run(confined([("/", str(tree / "dlnk" / "inner.txt"), "read")]), ("read", str(tree / "sub" / "inner.txt")))
    assert r == ["err", EACCES] and st["granted"] == []


def test_dotdot_cannot_leave_the_base(tree):
    base = tree / "sub"
    (r,), st = run(confined([(str(base), "../secret", "read")]), ("read", str(tree / "secret")))
    assert r == ["err", EACCES] and st["granted"] == []


def test_a_file_swapped_in_after_the_grant_is_not_readable(tree):
    (tree / "other.txt").write_text("SWAPPED")
    p = start(confined([("/", str(tree / "a.txt"), "read")]), [("read", str(tree / "a.txt"))], [("read", str(tree / "a.txt"))])
    first = json.loads(p.stdout.readline())
    os.replace(tree / "other.txt", tree / "a.txt")             # the name now points at another inode
    p.stdin.write("go\n")
    p.stdin.flush()
    second = json.loads(p.stdout.readline())
    p.communicate(timeout=30)
    assert first == [["ok", "A"]] and second == [["err", EACCES]]


def test_a_list_grant_lists_names_and_reads_no_file(tree):
    (ls, a, inner), st = run(confined([("/", str(tree), "list")]),
                             ("list", str(tree)), ("read", str(tree / "a.txt")), ("read", str(tree / "sub" / "inner.txt")))
    assert ls[0] == "ok" and "a.txt" in ls[1] and "secret" in ls[1]
    assert a == inner == ["err", EACCES] and st["granted"] == [str(tree)]


def test_a_read_grant_on_a_directory_and_a_list_grant_on_a_file_give_nothing(tree):
    (ls, a), st = run(confined([("/", str(tree), "read"), ("/", str(tree / "a.txt"), "list")]),
                      ("list", str(tree)), ("read", str(tree / "a.txt")))
    assert ls == a == ["err", EACCES] and st["granted"] == []


def test_a_hard_link_under_a_harmless_name_is_readable_a_pinned_gap(tree):
    os.link(tree / "secret", tree / "harmless.txt")
    (r,), _ = run(confined([("/", str(tree / "harmless.txt"), "read")]), ("read", str(tree / "harmless.txt")))
    assert r == ["ok", "SECRET"]                     # the grant is what was NAMED; the ask rules judge whether the name is sensitive


def test_runtime_is_readable_and_the_server_data_dirs_are_not(tree, tmp_path):
    rt = tmp_path / "rt"
    rt.mkdir()
    (rt / "lib.txt").write_text("CODE")
    spec = confined([], runtime=[str(rt)])
    (code, data), st = run(spec, ("read", str(rt / "lib.txt")), ("read", str(tree / "a.txt")))
    assert code == ["ok", "CODE"] and data == ["err", EACCES] and st["granted"] == []


def test_a_missing_name_gives_no_grant_and_the_worker_still_runs(tree):
    (r,), st = run(confined([("/", str(tree / "missing.txt"), "read")]), ("read", str(tree / "missing.txt")))
    assert r == ["err", errno.ENOENT] and st["granted"] == []


def test_an_unconfined_spec_reports_no_grants(tree):
    plain = {k: v for k, v in confined([]).items() if k != "grants"} | {"read": [str(tree)]}
    (a,), st = run(plain, ("read", str(tree / "a.txt")))
    assert a == ["ok", "A"] and "confined" not in st and "granted" not in st
