"""policy_writer error paths (phase 1 of the "narrow write right" plan): every way `append_rule` can fail must report a reason from the closed
set (`invalid_policy | write_failed | not_found`), leave the policy file byte-identical, and never leave a side file behind. These are the
branches that were uncovered (a race between lstat and open, an unreadable file, a PathLike that lies, a result that does not round-trip,
a lock that cannot be released). The standing rule from an "Always allow" card goes through exactly these (see test_policy_writer_write_calls.py)."""
import errno
import json
import os
import stat

import pytest

import policy as P
import policy_writer as W
from policy_writer import PolicyWriteError, append_rule, build_rule

BASE = {"version": 1, "default": "ask", "rules": [
    {"id": "read-project", "verdict": "allow", "when": {"tool": "read_*", "arg_keys": ["path"]}, "confine": {"path": "read"}}]}


@pytest.fixture
def pfile(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(BASE, indent=1))
    return str(f)


def rule():
    return build_rule("allow", "tool_under", "fs", "write_file", {"path": "/project/a/b.txt", "content": "x"})


def fails(path, **kw):
    with pytest.raises(PolicyWriteError) as ei:
        append_rule(path, kw.get("rule") or rule())
    return ei.value


def side_files(path):
    d = os.path.dirname(path)
    return sorted(f for f in os.listdir(d) if f.startswith(os.path.basename(path) + ".") and f != os.path.basename(path) + ".lock")


def untouched(pfile, before):
    assert open(pfile, "rb").read() == before and side_files(pfile) == []


# --------------------------------------------------------------------------- _path


class LyingPath:
    def __init__(self, value):
        self.value = value

    def __fspath__(self):
        return self.value


def test_a_pathlike_whose_fspath_is_not_text_is_refused_as_a_non_path():
    e = fails(LyingPath(5))
    assert (e.reason, e.detail) == ("write_failed", "path must be str or PathLike")


def test_a_pathlike_that_returns_bytes_is_an_invalid_path():
    e = fails(LyingPath(b"/tmp/policy.json"))
    assert (e.reason, e.detail) == ("write_failed", "invalid path")


# --------------------------------------------------------------------------- _read_regular


def test_a_file_that_cannot_be_stat_ed_after_the_existence_check_is_write_failed(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real, n = os.lstat, []

    def flaky(path, *a, **k):
        if path == pfile:
            n.append(1)
            if len(n) == 2:                                    # the first lstat is os.path.lexists; the second is _read_regular's
                raise PermissionError(errno.EACCES, "denied", path)
        return real(path, *a, **k)
    monkeypatch.setattr(W.os, "lstat", flaky)
    e = fails(pfile)
    assert e.reason == "write_failed" and e.detail.startswith("cannot stat:")
    untouched(pfile, before)


def test_a_file_deleted_after_the_existence_check_is_not_found(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real, n = os.lstat, []

    def gone(path, *a, **k):
        if path == pfile:
            n.append(1)
            if len(n) == 2:
                raise FileNotFoundError(errno.ENOENT, "gone", path)
        return real(path, *a, **k)
    monkeypatch.setattr(W.os, "lstat", gone)
    e = fails(pfile)
    assert (e.reason, e.detail) == ("not_found", pfile)
    untouched(pfile, before)


def test_a_file_that_vanishes_between_lstat_and_open_is_not_found(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real = os.open

    def vanish(path, flags, *a, **k):
        if path == pfile:
            raise FileNotFoundError(errno.ENOENT, "gone", path)
        return real(path, flags, *a, **k)
    monkeypatch.setattr(W.os, "open", vanish)
    e = fails(pfile)
    assert (e.reason, e.detail) == ("not_found", pfile)
    untouched(pfile, before)


def test_a_file_that_cannot_be_opened_is_write_failed(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real = os.open

    def deny(path, flags, *a, **k):
        if path == pfile:
            raise PermissionError(errno.EACCES, "denied", path)
        return real(path, flags, *a, **k)
    monkeypatch.setattr(W.os, "open", deny)
    e = fails(pfile)
    assert e.reason == "write_failed" and e.detail.startswith("cannot open:")
    untouched(pfile, before)


def test_a_path_that_turns_into_something_else_after_the_open_is_refused(pfile, monkeypatch):
    """lstat saw a regular file, the opened descriptor is not one (swapped in between): refused, and the descriptor is closed."""
    before = open(pfile, "rb").read()
    fds_before = set(os.listdir("/proc/self/fd"))
    real = os.fstat

    class FifoStat:
        st_mode = stat.S_IFIFO | 0o600

    def swapped(fd):
        return FifoStat() if os.readlink(f"/proc/self/fd/{fd}") == pfile else real(fd)
    monkeypatch.setattr(W.os, "fstat", swapped)
    e = fails(pfile)
    assert (e.reason, e.detail) == ("write_failed", "not a regular file")
    assert set(os.listdir("/proc/self/fd")) == fds_before
    untouched(pfile, before)


def test_a_read_error_is_write_failed_and_closes_the_descriptor(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    fds_before = set(os.listdir("/proc/self/fd"))

    def eio(fd, n):
        raise OSError(errno.EIO, "disk on fire")
    monkeypatch.setattr(W.os, "read", eio)
    e = fails(pfile)
    assert e.reason == "write_failed" and e.detail.startswith("cannot read:")
    assert set(os.listdir("/proc/self/fd")) == fds_before
    untouched(pfile, before)


# --------------------------------------------------------------------------- append_rule's catch-alls


def test_an_unexpected_exception_is_reported_as_write_failed_with_only_its_type(pfile, monkeypatch):
    before = open(pfile, "rb").read()

    def boom(p, r):
        raise KeyError("/secret/path/from/the/exception")
    monkeypatch.setattr(W, "_append", boom)
    e = fails(pfile)
    assert (e.reason, e.detail) == ("write_failed", "KeyError") and "secret" not in str(e.detail) + str(e)
    untouched(pfile, before)


def test_an_os_error_escaping_the_append_is_write_failed_with_its_text(pfile, monkeypatch):
    def boom(p, r):
        raise OSError(errno.ENOSPC, "no space left")
    monkeypatch.setattr(W, "_append", boom)
    e = fails(pfile)
    assert e.reason == "write_failed" and "no space left" in e.detail


def test_a_lock_descriptor_that_cannot_be_closed_does_not_fail_the_write(pfile, monkeypatch):
    real_open, real_close, locks = os.open, os.close, []

    def spy_open(path, *a, **k):
        fd = real_open(path, *a, **k)
        if str(path).endswith(".lock"):
            locks.append(fd)
        return fd

    def close(fd):
        real_close(fd)
        if fd in locks:
            raise OSError(errno.EIO, "close failed")
    monkeypatch.setattr(W.os, "open", spy_open)
    monkeypatch.setattr(W.os, "close", close)
    out = append_rule(pfile, rule())
    assert out["digest_before"] != out["digest_after"] and len(locks) == 1
    assert len(json.loads(open(pfile).read())["rules"]) == 2


# --------------------------------------------------------------------------- the result must load and round-trip


def test_a_result_too_large_for_the_policy_size_limit_is_invalid_policy_and_changes_nothing(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    monkeypatch.setattr(P, "MAX_FILE_BYTES", len(before) + 5)                    # the old file fits, the old file plus one rule does not
    e = fails(pfile)
    assert (e.reason, e.detail) == ("invalid_policy", "resulting policy file would be too large")
    untouched(pfile, before)


def test_a_result_that_does_not_reload_to_the_same_digest_is_invalid_policy_and_changes_nothing(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real, calls = P._parse_bytes, []

    def lossy(raw, key):
        data = real(raw, key)
        calls.append(1)
        if len(calls) == 2:                                    # the round-trip parse of the text about to be written
            data = dict(data, default="allow")
        return data
    monkeypatch.setattr(P, "_parse_bytes", lossy)
    e = fails(pfile)
    assert (e.reason, e.detail) == ("invalid_policy", "round trip changed the policy")
    untouched(pfile, before)


def test_a_result_that_does_not_reload_at_all_is_invalid_policy_and_changes_nothing(pfile, monkeypatch):
    before = open(pfile, "rb").read()
    real, calls = P._parse_bytes, []

    def broken(raw, key):
        calls.append(1)
        if len(calls) == 2:
            raise P.PolicyError(["rules[1]: confine.'path': nonsense", "second", "third", "fourth"])
        return real(raw, key)
    monkeypatch.setattr(P, "_parse_bytes", broken)
    e = fails(pfile)
    assert e.reason == "invalid_policy" and e.detail == "rules[1]: confine.'path': nonsense; second; third"      # at most three messages
    untouched(pfile, before)


def test_a_rule_that_would_write_a_write_right_is_refused_before_anything_is_written(pfile):
    """Even handed a hand-made rule (not from build_rule), the real validator is the gate: `write` in confine never reaches the file."""
    before = open(pfile, "rb").read()
    bad = {"id": "ui-allow-evil", "verdict": "allow", "when": {"server": "fs", "tool": "write_file", "arg_keys": ["path"]},
           "confine": {"path": "write"}}
    e = fails(pfile, rule=bad)
    assert e.reason == "invalid_policy" and "confine" in e.detail
    untouched(pfile, before)
