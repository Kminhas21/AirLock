"""The `write` grant (DECISIONS D32), everything that needs no Landlock ruleset: what kind of object may carry it (`sandbox.write_grant_ok`,
`open_grant`), the confined spec's resource limits, the trampoline refusing it below ABI 3, and the status the proxy checks.
The kernel side (what a worker holding the grant can and cannot do) is tests/proxy/test_sandbox_write.py."""
import os
import stat
import sys
from types import SimpleNamespace

import pytest

from sentinel_proxy import confine, sandbox, sandbox_exec
from tests.no_skip_plugin import sandbox_skipif

BASE = {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}


def st(mode=0o100644, nlink=1, size=10):
    return SimpleNamespace(st_mode=mode, st_nlink=nlink, st_size=size)


# --------------------------------------------------------------------------- the kind of object a write grant may cover (pure)


def test_a_plain_file_qualifies():
    assert sandbox.write_grant_ok(st()) is True
    assert sandbox.write_grant_ok(st(size=0)) is True
    assert sandbox.write_grant_ok(st(size=sandbox.WRITE_MAX_BYTES)) is True


@pytest.mark.parametrize("bad", [
    st(mode=stat.S_IFDIR | 0o755), st(mode=stat.S_IFIFO | 0o644), st(mode=stat.S_IFLNK | 0o777), st(mode=stat.S_IFCHR | 0o644),
    st(mode=stat.S_IFBLK | 0o644), st(mode=stat.S_IFSOCK | 0o644),                                     # not a regular file
    st(nlink=2), st(nlink=0), st(nlink=7),                                                              # another name exists (or a deleted file)
    st(mode=0o100755), st(mode=0o100744), st(mode=0o100654), st(mode=0o100645), st(mode=0o100001),     # an exec bit for owner, group or other
    st(size=sandbox.WRITE_MAX_BYTES + 1), st(size=10 ** 9),
])
def test_everything_else_does_not(bad):
    assert sandbox.write_grant_ok(bad) is False


def test_the_size_cap_is_256_kib():
    assert sandbox.WRITE_MAX_BYTES == 256 * 1024


# --------------------------------------------------------------------------- open_grant on real files (openat2 only, no ruleset)

needs_openat2 = sandbox_skipif(not sandbox.openat2_ok(), reason="openat2 needed")


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a.md").write_text("A")
    (d / "x.sh").write_text("#!/bin/sh")
    os.chmod(d / "x.sh", 0o755)
    (d / "sub").mkdir()
    (d / "hard.md").write_text("H")
    os.link(d / "hard.md", d / "hard2.md")
    (d / "lnk.md").symlink_to(d / "a.md")
    os.mkfifo(d / "fifo.md")
    (d / "big.md").write_bytes(b"x" * (sandbox.WRITE_MAX_BYTES + 1))
    return d


@needs_openat2
def test_open_grant_write_gives_an_fd_for_a_plain_file_beneath_its_base(w):
    fd = sandbox.open_grant(str(w), "a.md", "write")
    assert fd is not None
    assert stat.S_ISREG(os.fstat(fd).st_mode)
    os.close(fd)


@needs_openat2
@pytest.mark.parametrize("name", ["sub", "x.sh", "hard.md", "hard2.md", "lnk.md", "fifo.md", "big.md", "missing.md", "sub/missing.md", "a.md/x"])
def test_open_grant_write_gives_nothing_for_anything_else(w, name):
    assert sandbox.open_grant(str(w), name, "write") is None


@needs_openat2
@pytest.mark.parametrize("value", ["../a.md", "sub/../../w/a.md", "/etc/hostname"])
def test_open_grant_write_never_leaves_its_base_even_if_the_spec_check_were_skipped(w, value):
    """The spec rejects these; `open_grant` refuses them as well (defence in depth: an absolute value would be walked from `/`, which would
    lose the ceiling, and `..` is an escape the kernel walk would stop anyway)."""
    assert sandbox.open_grant(str(w / "sub"), value, "write") is None


@needs_openat2
def test_open_grant_write_walks_a_relative_value_from_the_base_not_from_slash(w):
    assert sandbox.open_grant(str(w / "sub"), "a.md", "write") is None            # a.md is in w, not in w/sub


@needs_openat2
def test_read_and_list_grants_are_unchanged(w):
    assert sandbox.open_grant("/", str(w / "x.sh"), "read") is not None           # a read grant has no kind rule beyond "not a directory"
    assert sandbox.open_grant("/", str(w / "hard.md"), "read") is not None
    assert sandbox.open_grant("/", str(w / "sub"), "list") is not None
    assert sandbox.open_grant("/", str(w / "a.md"), "list") is None


# --------------------------------------------------------------------------- the confined spec


def cspec(grants, **kw):
    return confine.confined_spec({**BASE, "write": ["/w"], "read": ["/r"], **kw}, grants)


def test_a_confined_spec_with_a_write_grant_caps_file_size_at_8_mib():
    assert cspec([["/w", "a.md", "write"]])["rlimits"]["fsize_mb"] == 8
    assert cspec([["/w", "a.md", "write"]], rlimits={"fsize_mb": 100, "cpu_s": 5})["rlimits"] == {"fsize_mb": 8, "cpu_s": 5}
    assert cspec([["/w", "a.md", "write"]], rlimits={"fsize_mb": 2})["rlimits"]["fsize_mb"] == 2        # never raised, only lowered


def test_a_confined_spec_without_a_write_grant_keeps_the_operators_limits():
    assert cspec([["/", "/w/a.md", "read"]])["rlimits"] == {}
    assert cspec([["/", "/w/a.md", "read"]], rlimits={"fsize_mb": 100})["rlimits"] == {"fsize_mb": 100}


def test_a_confined_spec_still_has_no_data_directory_rule_with_a_write_grant():
    s = cspec([["/w", "a.md", "write"]])
    assert s["read"] == [] and s["write"] == [] and s["grants"] == [["/w", "a.md", "write"]]


# --------------------------------------------------------------------------- the trampoline refuses a write grant below ABI 3


def spec_with(grant):
    return {**BASE, "grants": [list(grant)]}


def test_below_abi_3_the_trampoline_never_adds_a_ruleset_and_never_runs_the_command(monkeypatch, capfd, tmp_path):
    (tmp_path / "a.md").write_text("A")
    monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 2, "unshare_net": True})
    monkeypatch.setattr(sandbox, "restrict_landlock", lambda *a, **k: pytest.fail("a ruleset was built for a write grant on ABI 2"))
    called = []
    rc = sandbox_exec.main(["--spec", sandbox.encode_spec(spec_with((str(tmp_path), "a.md", "write"))), "--", "/bin/true"],
                           execve=lambda *a: called.append(a))
    err = capfd.readouterr().err
    assert rc == 126 and called == [] and "landlock_fs" in err and "ABI 3" in err


@pytest.mark.slow          # a real trampoline process (GATE_TIER=pr)
@sandbox_skipif(sandbox.landlock_abi() < 3 or not sandbox.openat2_ok(), reason="needs Landlock ABI >= 3 to apply a ruleset")
def test_the_status_of_a_write_worker_reports_device_inode_and_link_count_of_what_it_granted(tmp_path):
    import json
    import subprocess
    (tmp_path / "a.md").write_text("A")
    s = tmp_path / "a.md"
    cmd, argv, env = sandbox.sandbox_params(spec_with((str(tmp_path), "a.md", "write")), sys.executable, ["-c", "pass"],
                                            {"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp_path)})
    p = subprocess.run([cmd, *argv], env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    status = json.loads([ln for ln in p.stderr.splitlines() if ln.startswith("SENTINEL_SANDBOX_STATUS ")][0].split(" ", 1)[1])
    o = os.stat(s)
    assert status["write_granted"] == [{"value": "a.md", "dev": o.st_dev, "ino": o.st_ino, "nlink": 1}]
    assert status["granted"] == ["a.md"]


# --------------------------------------------------------------------------- the proxy's check of that status


def good_status(snaps, **kw):
    return {"confined": True, "layers": ["landlock_fs"], "missing": [], "granted": [s["value"] for s in snaps],
            "write_granted": [{"value": s["value"], "dev": s["dev"], "ino": s["ino"], "nlink": 1} for s in snaps], **kw}


SNAP = {"value": "a.md", "dev": 7, "ino": 99}


def test_the_write_status_check_accepts_the_matching_status():
    assert confine.write_status_ok(good_status([SNAP]), [SNAP]) is True
    assert confine.write_status_ok(good_status([]), []) is True


@pytest.mark.parametrize("mut", [
    lambda s: s.update(write_granted=[]),                                                                                    # grant missing
    lambda s: s.pop("write_granted"),
    lambda s: s.update(write_granted=[{**s["write_granted"][0], "ino": 100}]),                                               # another inode
    lambda s: s.update(write_granted=[{**s["write_granted"][0], "dev": 8}]),
    lambda s: s.update(write_granted=[{**s["write_granted"][0], "nlink": 2}]),                                               # a second name
    lambda s: s.update(write_granted=[{**s["write_granted"][0], "nlink": True}]),
    lambda s: s.update(write_granted=s["write_granted"] * 2),                                                                # an extra grant
    lambda s: s.update(write_granted="x"),
    lambda s: s.update(write_granted=[None]),
    lambda s: s.update(write_granted=[{"value": "a.md", "dev": "7", "ino": "99", "nlink": 1}]),
    lambda s: s.update(write_granted=[{**s["write_granted"][0], "value": "b.md"}]),
])
def test_the_write_status_check_refuses_any_difference_from_the_snapshot(mut):
    s = good_status([SNAP])
    mut(s)
    assert confine.write_status_ok(s, [SNAP]) is False


def test_a_status_with_a_write_grant_nobody_asked_for_is_refused():
    assert confine.write_status_ok(good_status([SNAP]), []) is False
