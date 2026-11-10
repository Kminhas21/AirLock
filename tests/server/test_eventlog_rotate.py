"""Tests for `eventlog_cli rotate` and `verify --previous` (retention by rotation; GitHub issue #4)."""
import glob
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys

import eventlog as EL
from eventlog import EventStore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER_DIR = os.path.join(ROOT, "server")
KEY = "rotate-test-key-0123456789"
ENV = {"SENTINEL_LOG_KEY": KEY}


def run(*argv, env=ENV):
    e = dict(os.environ, PYTHONPATH=SERVER_DIR)
    e.pop("SENTINEL_LOG_KEY", None)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "eventlog_cli", *argv], capture_output=True, text=True, env=e, cwd=SERVER_DIR)


def build(d, name="e.db", n=3, key=KEY):
    path = str(d / name)
    s = EventStore(path, key=key.encode() if key else None, checkpoint_every=5)
    s.open()
    for i in range(n):
        s.append("proxy_hello", session_id="s1", payload={"servers": [f"fs{i}"], "auto_approve": False})
    s.close()
    return path


def events(path):
    s = EventStore.open_readonly(path, key=KEY.encode())
    try:
        return list(s.events())
    finally:
        s.close()


def archives(d, name="e"):
    return sorted(p for p in glob.glob(str(d / f"{name}-*.db")))


def rotate(db, *extra, env=ENV):
    return run("rotate", db, *extra, env=env)


def test_rotate_archives_and_starts_new_log(tmp_path):
    db = build(tmp_path)
    head = events(db)[-1]
    r = rotate(db)
    assert r.returncode == 0, r.stderr + r.stdout
    arch = archives(tmp_path)
    assert len(arch) == 1
    assert re.fullmatch(rf"e-\d{{8}}T\d{{6}}-seq{head.seq}\.db", os.path.basename(arch[0]))
    assert os.path.exists(arch[0] + ".anchor")
    assert not os.path.exists(arch[0] + "-wal")
    evs = events(db)
    assert [e.kind for e in evs[:2]] == ["log_open", "log_continues"]
    assert evs[1].payload == {"previous_file": os.path.basename(arch[0]), "head_seq": head.seq, "head_hash": head.hash}
    assert run("verify", db).returncode == 0
    assert run("verify", arch[0]).returncode == 0
    assert len(r.stdout.strip().splitlines()) == 1


def test_verify_previous_passes(tmp_path):
    db = build(tmp_path)
    assert rotate(db).returncode == 0
    arch = archives(tmp_path)[0]
    v = run("verify", db, "--previous", arch)
    assert v.returncode == 0, v.stdout + v.stderr


def test_verify_without_previous_notes_the_link(tmp_path):
    db = build(tmp_path)
    rotate(db)
    v = run("verify", db)
    assert v.returncode == 0
    assert "earlier history is in" in v.stdout and "--previous" in v.stdout


def test_tampered_archive_fails_previous(tmp_path):
    db = build(tmp_path)
    rotate(db)
    arch = archives(tmp_path)[0]
    c = sqlite3.connect(arch)
    c.execute("UPDATE events SET payload = '{\"servers\": [\"evil\"]}' WHERE seq = 2")
    c.commit()
    c.close()
    v = run("verify", db, "--previous", arch)
    assert v.returncode == 1
    assert "PROBLEM" in v.stdout


def test_different_valid_archive_is_a_mismatch(tmp_path):
    db = build(tmp_path)
    rotate(db)
    arch = archives(tmp_path)[0]
    other_dir = tmp_path / "o"
    other_dir.mkdir()
    other = build(other_dir, n=6)
    rotate(other)
    oarch = archives(other_dir)[0]
    shutil.copy(oarch, arch)
    shutil.copy(oarch + ".anchor", arch + ".anchor")
    assert run("verify", arch).returncode == 0          # valid on its own
    v = run("verify", db, "--previous", arch)
    assert v.returncode == 1
    assert "does not match" in v.stdout


def test_missing_archive_is_reported(tmp_path):
    db = build(tmp_path)
    rotate(db)
    arch = archives(tmp_path)[0]
    os.remove(arch)
    v = run("verify", db, "--previous", arch)
    assert v.returncode == 1
    assert "PROBLEM" in v.stdout


def test_previous_without_log_continues_is_a_problem(tmp_path):
    db = build(tmp_path)
    other = build(tmp_path, name="x.db")
    v = run("verify", db, "--previous", other)
    assert v.returncode == 1
    assert "log_continues" in v.stdout


def test_rotate_refuses_tampered_log_and_moves_nothing(tmp_path):
    db = build(tmp_path)
    c = sqlite3.connect(db)
    c.execute("UPDATE events SET payload = '{\"servers\": [\"evil\"]}' WHERE seq = 2")
    c.commit()
    c.close()
    r = rotate(db)
    assert r.returncode == 1
    assert os.path.exists(db) and os.path.exists(db + ".anchor")
    assert archives(tmp_path) == []


def test_rotate_refuses_while_db_is_in_use(tmp_path):
    db = build(tmp_path)
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        r = rotate(db)
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert r.returncode == 1
    assert "stop the hub" in (r.stdout + r.stderr)
    assert archives(tmp_path) == []
    assert len(events(db)) > 0 and not any(e.kind == "log_continues" for e in events(db))


def test_rotate_never_overwrites_an_archive(tmp_path, monkeypatch):
    db = build(tmp_path)
    r = rotate(db, "--archive-dir", str(tmp_path / "a"))   # missing dir: refused, nothing moved
    assert r.returncode != 0 and os.path.exists(db)
    (tmp_path / "a").mkdir()
    import eventlog_cli as C
    import datetime as dt

    class FixedDT(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2030, 1, 2, 3, 4, 5, tzinfo=tz)
    head = events(db)[-1]
    name = f"e-20300102T030405-seq{head.seq}.db"
    (tmp_path / "a" / name).write_text("precious")
    monkeypatch.setattr(C.datetime, "datetime", FixedDT)
    monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
    rc = C.main(["rotate", db, "--archive-dir", str(tmp_path / "a")])
    assert rc == 1
    assert (tmp_path / "a" / name).read_text() == "precious"
    assert os.path.exists(db) and os.path.exists(db + ".anchor")
    assert not os.path.exists(str(tmp_path / "a" / name) + ".anchor")


def test_rotate_keyed_log_without_key_is_refused(tmp_path):
    db = build(tmp_path)
    r = rotate(db, env={})
    assert r.returncode == 1 and "key" in r.stderr
    assert os.path.exists(db) and os.path.exists(db + ".anchor") and archives(tmp_path) == []
    assert run("verify", db).returncode == 0


def test_rotate_unkeyed_log_with_key_is_refused(tmp_path):
    db = build(tmp_path, key=None)
    r = rotate(db, env=ENV)
    assert r.returncode == 1 and "key" in r.stderr
    assert os.path.exists(db) and os.path.exists(db + ".anchor") and archives(tmp_path) == []
    assert run("verify", db, env={}).returncode == 0


def test_log_is_locked_while_rotate_verifies_and_the_head_is_the_verified_one(tmp_path, monkeypatch):
    import eventlog_cli as C
    db = build(tmp_path)
    head = events(db)[-1]
    seen = []
    real = C.EL.verify_file

    def spy(path, **kw):
        r = real(path, **kw)
        c = sqlite3.connect(path, timeout=0.1, isolation_level=None)
        try:                                              # what a hub appending now would do
            c.execute("BEGIN IMMEDIATE")
            seen.append("writable")
        except sqlite3.OperationalError:
            seen.append("locked")
        finally:
            c.close()
        return r
    monkeypatch.setattr(C.EL, "verify_file", spy)
    monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
    assert C.main(["rotate", db]) == 0
    assert seen == ["locked"]
    assert events(db)[1].payload["head_seq"] == head.seq and events(db)[1].payload["head_hash"] == head.hash


def test_anchor_move_failure_rolls_back_everything(tmp_path, monkeypatch):
    import eventlog_cli as C
    db = build(tmp_path)
    before = open(db + ".anchor").read()
    real, calls = shutil.move, []

    def flaky(src, dst, *a, **kw):
        calls.append(src)
        if len(calls) == 2:
            raise OSError("disk says no")
        return real(src, dst, *a, **kw)
    monkeypatch.setattr(C.shutil, "move", flaky)
    monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
    assert C.main(["rotate", db]) != 0
    assert archives(tmp_path) == [] and glob.glob(str(tmp_path / "*.anchor")) == [db + ".anchor"]
    assert open(db + ".anchor").read() == before
    assert not any(e.kind == "log_continues" for e in events(db))
    assert run("verify", db).returncode == 0


def test_new_log_creation_failure_says_so(tmp_path, monkeypatch, capsys):
    import eventlog_cli as C
    db = build(tmp_path)

    def boom(*a, **kw):
        raise C.EL.EventLogError("cannot create")
    monkeypatch.setattr(C.EL, "EventStore", boom)
    monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
    assert C.main(["rotate", db]) != 0
    err = capsys.readouterr().err
    arch = archives(tmp_path)
    assert len(arch) == 1 and os.path.exists(arch[0] + ".anchor")
    assert "no log_continues" in err and arch[0] in err


def test_after_rotation_hub_can_append_and_pipeline_works(tmp_path):
    db = build(tmp_path)
    rotate(db)
    s = EventStore(db, key=KEY.encode())
    s.open()
    s.append("proxy_hello", session_id="s9", payload={"servers": ["fs"], "auto_approve": False})
    s.close()
    arch = archives(tmp_path)[0]
    assert run("verify", db, "--previous", arch).returncode == 0
    sh = run("show", db, "--session", "s9")
    assert sh.returncode == 0 and "SESSION START" in sh.stdout
    ex = run("export", db, "--jsonl")
    assert any(json.loads(l)["kind"] == "log_continues" for l in ex.stdout.splitlines())


def test_archive_and_anchor_are_mode_0600(tmp_path):
    db = build(tmp_path)
    os.chmod(db, 0o644)
    os.chmod(db + ".anchor", 0o644)
    assert rotate(db).returncode == 0
    arch = archives(tmp_path)[0]
    for p in (arch, arch + ".anchor"):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_archive_dir_option_and_unkeyed(tmp_path):
    db = build(tmp_path, key=None)
    (tmp_path / "arch").mkdir()
    r = rotate(db, "--archive-dir", str(tmp_path / "arch"), env={})
    assert r.returncode == 0, r.stderr + r.stdout
    assert len(archives(tmp_path / "arch")) == 1
    assert run("verify", db, "--previous", archives(tmp_path / "arch")[0], env={}).returncode == 0
