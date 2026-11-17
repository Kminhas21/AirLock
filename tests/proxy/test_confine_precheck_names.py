"""Precheck and grant walk for names that do not (or not simply) exist: phase 1 of the "narrow write right" plan, pinned as TODAY's behaviour.

A create names something that is not there yet, so "a missing name is confinable and grants nothing" is the NORMAL case for it. These tests pin
what `confine.precheck`, `confine.grant_specs` and `sandbox.open_grant` say for: a name under a missing parent, under a symlinked directory,
beneath a file, with `..`, with a trailing slash, a dangling or existing symlink, a hard link, a NUL byte, a magic link. When a write right
is added, each row that changes must change on purpose.

A NUL byte in a value makes the call not confinable (the precheck checks for it explicitly, the walk would truncate the name at the NUL);
the worker's own spec validation (`_grants`) refuses it too, as a second line."""
import os

import pytest

from sentinel_proxy import confine, sandbox
from sentinel_proxy.config import parse_config
from tests.no_skip_plugin import sandbox_skipif

pytestmark = sandbox_skipif(not sandbox.openat2_ok(), reason="openat2 is unavailable on this host")


def server(*args, **kw):
    return parse_config({"servers": {"fs": {"command": "/bin/true", "args": list(args), **kw}}}).servers["fs"]


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / ".env").write_text("SECRET")
    (d / "sub" / "inner.txt").write_text("I")
    (d / "to_env").symlink_to(d / ".env")
    (d / "dangling").symlink_to(d / "nothing")
    (d / "dlnk").symlink_to(d / "sub")
    os.link(d / ".env", d / "harmless.txt")
    os.mkfifo(d / "fifo")
    return d


def pre(sc, **args):
    return confine.precheck(args, sc)


# --------------------------------------------------------------------------- names that are not there (the normal case of a create)


@pytest.mark.parametrize("rel", ["new.txt", "sub/new.txt", "missing_dir/new.txt", "missing/a/b/c/new.txt", "new.txt/", "sub/../new.txt",
                                 "a.txt/x", "a.txt/x/y", "./new.txt", "sub/./new.txt", "new name with spaces.md", ".env.new", "ünï.txt"])
def test_a_name_that_does_not_exist_is_confinable_for_both_spellings(w, rel):
    sc = server(str(w))
    assert pre(sc, path=rel) == (True, {}, {}), rel
    assert pre(sc, path=str(w / rel)) == (True, {}, {}), rel


def test_a_missing_name_gets_a_grant_spec_but_never_a_grant(w):
    """The proxy hands the worker every (base, value, right); the WORKER decides (sandbox.open_grant), and a missing name gets no fd."""
    sc = server(str(w))
    specs = confine.grant_specs({"path": "new.txt"}, {"path": "read"}, sc)
    assert specs == [[str(w), "new.txt", "read"]]
    assert sandbox.open_grant(*specs[0]) is None
    assert sandbox.open_grant("/", str(w / "missing_dir" / "new.txt"), "read") is None
    assert sandbox.open_grant("/", str(w / "a.txt") + "/x", "read") is None


@pytest.mark.parametrize("value", ["dlnk/new.txt", "dlnk/inner.txt", "to_env", "dangling", "dlnk", "to_env/x"])
def test_a_symlink_on_the_way_is_never_confinable_even_when_the_name_is_new(w, value):
    ok, links, _lex = pre(server(str(w)), path=value)
    assert ok is False and links == {"path": os.path.realpath(w / value)}, value
    assert sandbox.open_grant(str(w), value, "read") is None and sandbox.open_grant("/", str(w / value), "read") is None


def test_an_existing_symlink_to_a_new_name_reports_where_a_create_would_land(w):
    (w / "newlink").symlink_to(w / "does_not_exist_yet")
    ok, links, _ = pre(server(str(w)), path="newlink")
    assert ok is False and links == {"path": str(w / "does_not_exist_yet")}      # a server that creates through the link would write THERE


# --------------------------------------------------------------------------- `..`


@pytest.mark.parametrize("value", ["../x", "../w/new.txt", "sub/../../new.txt", "..", "sub/../.."])
def test_dotdot_that_leaves_the_base_is_not_confinable(w, value):
    assert pre(server(str(w)), path=value)[0] is False
    assert sandbox.open_grant(str(w), value, "read") is None and sandbox.open_grant(str(w), value, "list") is None


def test_dotdot_that_stays_beneath_the_base_is_fine_and_grants_the_named_object(w):
    sc = server(str(w))
    assert pre(sc, path="sub/../a.txt") == (True, {}, {})
    fd = sandbox.open_grant(str(w), "sub/../a.txt", "read")
    assert fd is not None and os.fstat(fd).st_ino == os.stat(w / "a.txt").st_ino
    os.close(fd)
    assert sandbox.open_grant(str(w / "sub"), "../a.txt", "read") is None            # leaves ITS base: no grant


def test_dotdot_through_a_link_is_not_confinable_and_both_resolutions_are_reported(w, tmp_path):
    (tmp_path / "far").mkdir()
    (w / "far").symlink_to(tmp_path / "far")
    ok, links, lexical = pre(server(str(w)), path="far/../a.txt")
    assert ok is False and links == {"path": str(tmp_path / "a.txt")} and lexical == {"path": str(w / "a.txt")}


# --------------------------------------------------------------------------- hard links, special files, magic links


def test_a_second_name_of_a_sensitive_inode_is_confinable_a_pinned_gap(w):
    """The grant is on the INODE. `harmless.txt` is a hard link of `.env`: nothing here can tell (st_nlink is not consulted today), so the
    precheck says confinable and the worker opens it. A write right must refuse nlink > 1 (see docs/plans, section 3)."""
    sc = server(str(w))
    assert pre(sc, path="harmless.txt") == (True, {}, {})
    fd = sandbox.open_grant(str(w), "harmless.txt", "read")
    assert fd is not None
    st = os.fstat(fd)
    os.close(fd)
    assert st.st_nlink == 2 and st.st_ino == os.stat(w / ".env").st_ino


def test_a_fifo_and_a_directory_are_walked_like_any_object_and_only_the_right_kind_gets_a_grant(w):
    sc = server(str(w))
    assert pre(sc, path="fifo") == (True, {}, {}) and pre(sc, path="sub") == (True, {}, {})
    fd = sandbox.open_grant(str(w), "fifo", "read")                     # not a directory: a `read` grant (today)
    assert fd is not None
    os.close(fd)
    assert sandbox.open_grant(str(w), "sub", "read") is None            # a read grant never covers a directory
    assert sandbox.open_grant(str(w), "a.txt", "list") is None          # a list grant never covers a file
    fd = sandbox.open_grant(str(w), "sub", "list")
    assert fd is not None
    os.close(fd)


def test_a_failed_or_wrong_kind_grant_leaks_no_file_descriptor(w):
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(20):
        assert sandbox.open_grant(str(w), "sub", "read") is None
        assert sandbox.open_grant(str(w), "a.txt", "list") is None
        assert sandbox.open_grant(str(w), "missing", "read") is None
        assert sandbox.open_grant(str(w), "to_env", "read") is None
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("value", ["/proc/self/root/etc/passwd", "/proc/self/cwd/x", "/proc/self/fd/0", "/proc/self/exe"])
def test_a_proc_magic_link_is_not_confinable(w, value):
    assert pre(server(str(w)), path=value)[0] is False
    assert sandbox.open_grant("/", value, "read") is None


# --------------------------------------------------------------------------- NUL bytes


@pytest.mark.parametrize("value", ["\x00", "a.txt\x00", "a.txt\x00.md", "\x00a.txt", "sub/\x00/x", ".env\x00.md"])
def test_a_nul_in_a_value_is_refused_by_the_worker_spec_whatever_the_precheck_says(w, value):
    """The grant that would be handed to the worker is rejected by `sandbox.validate_spec` (the trampoline's own check): fail closed."""
    sc = server(str(w))
    specs = confine.grant_specs({"path": value}, {"path": "read"}, sc)
    assert specs
    with pytest.raises(sandbox.SandboxSpecError, match="NUL"):
        sandbox.validate_spec(confine.confined_spec({"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [],
                                                     "rlimits": {}, "require": True}, specs), internal=True)


@pytest.mark.parametrize("value", ["a.txt\x00.md", ".env\x00.md", "a.txt\x00", "\x00", "\x00a.txt", "sub/\x00/x"])
def test_a_nul_in_a_value_is_not_confinable_so_the_call_gets_a_card(w, value):
    """FIXED: the walk would truncate at the NUL, so the precheck looks for NUL itself: the hub asks instead of auto-allowing."""
    sc = server(str(w))
    assert pre(sc, path=value)[0] is False
    assert pre(sc, paths=[value])[0] is False


# --------------------------------------------------------------------------- shapes


@pytest.mark.parametrize("args", [None, [], "path", 5, ("path", "x")])
def test_a_call_whose_arguments_are_not_an_object_is_never_confinable(w, args):
    assert confine.precheck(args, server(str(w))) == (False, {}, {})
    assert confine.grant_specs(args, {"path": "read"}, server(str(w))) == []
    assert confine.has_path_values(args) is False


def test_non_string_values_are_not_paths_and_list_entries_are_judged_one_by_one(w):
    sc = server(str(w))
    assert pre(sc, path=5) == (True, {}, {}) and pre(sc, path=None) == (True, {}, {}) and pre(sc, path={"x": 1}) == (True, {}, {})
    assert pre(sc, paths=["a.txt", 5, None, "to_env"]) == (False, {"paths.3": str(w / ".env")}, {})
    assert confine.grant_specs({"paths": ["a.txt", 5, "b"]}, {"paths": "read"}, sc) == [[str(w), "a.txt", "read"], [str(w), "b", "read"]]


def test_an_empty_or_home_relative_value_is_never_confinable_and_gets_no_grant_spec(w):
    sc = server(str(w))
    for v in ("", "~", "~/x", "~root/.ssh"):
        assert pre(sc, path=v)[0] is False, v
        assert confine.grant_specs({"path": v}, {"path": "read"}, sc) == [], v


def test_every_slot_is_walked_not_only_the_confined_one(w):
    """A value in ANY path slot that cannot be confined makes the call unconfinable, even one the rule's `confine` does not list."""
    sc = server(str(w))
    assert pre(sc, path="a.txt", destination="to_env")[0] is False
    assert confine.grant_specs({"path": "a.txt", "destination": "new.txt"}, {"path": "read"}, sc) == [[str(w), "a.txt", "read"]]


def test_the_precheck_never_raises(w, monkeypatch):
    sc = server(str(w))

    def boom(*a, **k):
        raise RuntimeError("kernel on fire")
    monkeypatch.setattr(sandbox, "open_beneath", boom)
    assert confine.precheck({"path": "a.txt"}, sc) == (False, {}, {})


# --------------------------------------------------------------------------- the host probes and a failing fstat


def test_openat2_ok_is_false_on_an_unsupported_architecture_or_when_the_syscall_fails(monkeypatch):
    sandbox.openat2_ok.cache_clear()
    try:
        monkeypatch.setattr(sandbox, "_arch_ok", lambda: False)
        assert sandbox.openat2_ok() is False
        sandbox.openat2_ok.cache_clear()
        monkeypatch.setattr(sandbox, "_arch_ok", lambda: True)
        monkeypatch.setattr(sandbox, "open_beneath", lambda *a: (_ for _ in ()).throw(OSError(38, "ENOSYS")))
        assert sandbox.openat2_ok() is False
    finally:
        monkeypatch.undo()
        sandbox.openat2_ok.cache_clear()
    assert sandbox.openat2_ok() is True                           # the real host again (this module is skipped without it)


def test_a_grant_whose_fstat_fails_gives_no_grant_and_leaks_no_descriptor(w, monkeypatch):
    before = set(os.listdir("/proc/self/fd"))

    def broken(fd):
        raise OSError(5, "EIO")
    monkeypatch.setattr(sandbox.os, "fstat", broken)
    assert sandbox.open_grant(str(w), "a.txt", "read") is None
    monkeypatch.undo()
    assert set(os.listdir("/proc/self/fd")) == before
