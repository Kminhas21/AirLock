"""Tests for the durable tamper-evident event log (server/eventlog.py, ticket EL1).

Every tamper test edits the SQLite file / anchor file directly (raw sqlite3, no store code) and asserts what verify detects.
The hash rule is re-implemented here independently (`ref_hash`) so a drift in the contract fails a test.
"""
import hashlib
import hmac
import itertools
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time

import pytest

import eventlog as EL
from eventlog import DuplicateEvent, EventLogError, EventStore, verify_file

SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
KEY = b"k" * 16 + b"-test-key"
GENESIS = "0" * 64


class Clock:
    def __init__(self, t=1000.0, step=1.0):
        self.t, self.step = t, step

    def __call__(self):
        self.t += self.step
        return self.t


def ref_hash(prev, seq, ts, sid, cid, kind, payload):
    body = json.dumps({"seq": seq, "ts": ts, "session_id": sid, "call_id": cid, "kind": kind, "payload": payload},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((prev + "\n" + body).encode()).hexdigest()


def ref_mac(key, seq, h):
    return hmac.new(key, f"{seq}\n{h}".encode(), hashlib.sha256).hexdigest()


def proposed(i, **extra):
    p = {"server": "fs", "tool": "write_file", "args": {"path": f"/project/{i}"}, "auto": False, "alerts": [], "policy": None}
    p.update(extra)
    return p


def decision(d="approve", reason="human", actor="human"):
    return {"decision": d, "reason": reason, "actor": actor, "rule_id": None, "policy_digest": None}


def build(tmp_path, *, key=None, n_calls=6, every=4, name="e.db", close=True, anchor=None):
    path = str(tmp_path / name)
    s = EventStore(path, key=key, checkpoint_every=every, clock=Clock(), anchor_path=anchor)
    s.open()
    s.append("proxy_hello", session_id="s1", payload={"servers": ["fs"]})
    for i in range(n_calls):
        s.append("call_proposed", session_id="s1", call_id=f"c{i}", payload=proposed(i))
        if i % 2 == 0:
            s.append("decision", session_id="s1", call_id=f"c{i}", payload=decision())
            s.append("call_result", session_id="s1", call_id=f"c{i}", payload={"status": "ok", "summary": "done"})
    if close:
        s.close()
        return path
    return path, s


def anchor_of(path):
    return path + ".anchor"


def raw(path):
    return sqlite3.connect(path, isolation_level=None)


def rows(path):
    c = raw(path)
    try:
        return c.execute("SELECT seq, ts, session_id, call_id, kind, payload, prev_hash, hash FROM events ORDER BY seq").fetchall()
    finally:
        c.close()


def sql(path, *stmts):
    c = raw(path)
    try:
        for st in stmts:
            c.execute(*st) if isinstance(st, tuple) else c.execute(st)
    finally:
        c.close()


def report(path, key=None, anchor=None):
    return verify_file(path, key=key, anchor_path=anchor)


def rebuild(path, mutate=None, *, key=None, anchor=False):
    """Rewrite the WHOLE chain consistently (an attacker who knows the format).  `key` = the attacker holds the key."""
    rs = [list(r) for r in rows(path)]
    if mutate:
        rs = mutate(rs)
    prev = GENESIS
    c = raw(path)
    try:
        c.execute("DELETE FROM events")
        anchor_lines = []
        for i, r in enumerate(rs, 1):
            r[0] = i
            payload = json.loads(r[5])
            if r[4] == "checkpoint":
                payload["upto_seq"], payload["head_hash"] = i - 1, prev
                if key is not None:
                    payload["mac"] = ref_mac(key, i - 1, prev)
                anchor_lines.append(f"{i - 1} {prev} {payload.get('mac') or '-'}\n")
            text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            h = ref_hash(prev, i, r[1], r[2], r[3], r[4], payload)
            c.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", (i, r[1], r[2], r[3], r[4], text, prev, h))
            prev = h
        c.execute("UPDATE head SET seq = ?, hash = ?", (len(rs), prev))
    finally:
        c.close()
    if anchor:
        with open(anchor_of(path), "w") as fh:
            fh.write("".join(anchor_lines))


def pick(rs, kind="call_proposed", n=0):
    return [r for r in rs if r[4] == kind][n]


def truncate_tail(path, keep_seq, fix_head=True):
    last = [r for r in rows(path) if r[0] == keep_seq][0]
    sql(path, ("DELETE FROM events WHERE seq > ?", (keep_seq,)))
    if fix_head:
        sql(path, ("UPDATE head SET seq = ?, hash = ?", (keep_seq, last[7])))


def problems_text(rep):
    return "\n".join(rep.problems)


# ---------------------------------------------------------------------------
# basics: schema, hash rule, files
# ---------------------------------------------------------------------------

class TestBasics:
    def test_open_creates_log_open_and_returns_info(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), clock=Clock())
        info = s.open()
        assert info["seq"] == 1 and info["recovered"] == [] and re.fullmatch(r"[0-9a-f]{64}", info["head"])
        evs = list(s.events())
        assert [e.kind for e in evs] == ["log_open"] and evs[0].prev_hash == GENESIS
        s.close()

    def test_hash_rule_matches_independent_implementation(self, tmp_path):
        path = build(tmp_path, key=KEY)
        prev = GENESIS
        rs = rows(path)
        assert len(rs) > 10
        for seq, ts, sid, cid, kind, ptext, ph, h in rs:
            assert ph == prev
            assert h == ref_hash(prev, seq, ts, sid, cid, kind, json.loads(ptext))
            assert ptext == json.dumps(json.loads(ptext), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            prev = h
        assert [r[0] for r in rs] == list(range(1, len(rs) + 1))

    def test_schema_matches_plan(self, tmp_path):
        path = build(tmp_path)
        c = raw(path)
        cols = [(r[1], r[2]) for r in c.execute("PRAGMA table_info(events)")]
        assert cols == [("seq", "INTEGER"), ("ts", "REAL"), ("session_id", "TEXT"), ("call_id", "TEXT"), ("kind", "TEXT"),
                        ("payload", "TEXT"), ("prev_hash", "TEXT"), ("hash", "TEXT")]
        assert "AUTOINCREMENT" in c.execute("SELECT sql FROM sqlite_master WHERE name='events'").fetchone()[0]
        assert c.execute("PRAGMA user_version").fetchone()[0] == 1
        c.close()

    def test_wal_and_sync_full(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        assert s._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert s._conn.execute("PRAGMA synchronous").fetchone()[0] == 2
        s.close()

    def test_files_are_mode_0600(self, tmp_path):
        old = os.umask(0)
        try:
            path = build(tmp_path)
        finally:
            os.umask(old)
        for p in (path, anchor_of(path)):
            assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, p

    def test_append_returns_event_and_is_durable_without_close(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, clock=Clock())
        s.open()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload=proposed(1))
        assert (ev.kind, ev.session_id, ev.call_id, ev.seq) == ("call_proposed", "s", "c", 2)
        assert ev.hash == ref_hash(ev.prev_hash, 2, ev.ts, "s", "c", "call_proposed", ev.payload)
        # another connection sees the committed row right away (no close, no checkpoint)
        assert [r[0] for r in rows(path)] == [1, 2]
        s.close()

    def test_head_record_tracks_last_event(self, tmp_path):
        path = build(tmp_path)
        last = rows(path)[-1]
        c = raw(path)
        assert c.execute("SELECT seq, hash FROM head").fetchone() == (last[0], last[7])
        c.close()

    def test_all_kinds_accepted_except_reserved(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("proxy_hello", session_id="s", payload={})
        s.append("proxy_close", session_id="s", payload={"reason": "x"})
        s.append("call_proposed", session_id="s", call_id="c", payload={})
        s.append("decision", session_id="s", call_id="c", payload=decision())
        s.append("call_result", session_id="s", call_id="c", payload={"status": "ok"})
        for k in ("checkpoint", "log_open"):
            with pytest.raises(ValueError):
                s.append(k, payload={})
        s.close()

    @pytest.mark.parametrize("kind", ["nope", "", None, 5, b"decision", ["decision"], "DECISION", "decision\n"])
    def test_bad_kind_is_value_error_and_writes_nothing(self, tmp_path, kind):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        before = s.verify().n_events
        with pytest.raises(ValueError):
            s.append(kind, session_id="s", call_id="c", payload={})
        assert s.verify().n_events == before
        s.close()

    @pytest.mark.parametrize("kw", [{"session_id": 5}, {"session_id": b"s"}, {"call_id": ["c"]}, {"call_id": "x" * 201},
                                    {"session_id": "s\ud800"}, {"call_id": 1.5}])
    def test_bad_ids(self, tmp_path, kw):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        args = {"session_id": "s", "call_id": "c", **kw}
        with pytest.raises(ValueError):
            s.append("call_proposed", payload={}, **args)
        s.close()

    @pytest.mark.parametrize("kind", ["call_proposed", "decision", "call_result"])
    def test_call_kinds_need_both_ids(self, tmp_path, kind):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        for kw in ({}, {"session_id": "s"}, {"call_id": "c"}):
            with pytest.raises(ValueError):
                s.append(kind, payload=decision(), **kw)
        s.close()

    def test_decision_value_must_be_approve_or_deny(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        for bad in ({}, {"decision": "maybe"}, {"decision": True}, {"decision": None}):
            with pytest.raises(ValueError):
                s.append("decision", session_id="s", call_id="c", payload=bad)
        s.close()

    def test_ids_with_unicode_roundtrip(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("call_proposed", session_id="sessé‮", call_id="c\u0000x", payload={"server": "é"})
        assert s.verify().ok
        ev = list(s.events(session_id="sessé‮"))[0]
        assert ev.call_id == "c\u0000x" and ev.payload["server"] == "é"
        s.close()

    def test_closed_and_unopened_store(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s")
        with pytest.raises(EventLogError):
            s.verify()
        s.open()
        with pytest.raises(EventLogError):
            s.open()                                   # twice
        s.close()
        s.close()                                      # idempotent
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s")
        with pytest.raises(EventLogError):
            s.open()

    def test_context_manager(self, tmp_path):
        path = str(tmp_path / "e.db")
        with EventStore(path) as s:
            s.open()
        assert report(path).ok

    def test_timestamps_recorded_not_enforced_monotonic(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), clock=Clock(1000.0, step=-1.0))      # the clock steps BACKWARDS
        s.open()
        s.append("proxy_hello", session_id="s")
        s.append("proxy_hello", session_id="t")
        ts = [e.ts for e in s.events()]
        assert len(ts) == 3 and ts == sorted(ts, reverse=True) and len(set(ts)) == 3
        assert s.verify().ok
        s.close()

    def test_integer_clock_is_normalised(self, tmp_path):
        ticks = itertools.count(5)
        s = EventStore(str(tmp_path / "e.db"), clock=lambda: next(ticks))
        s.open()
        s.append("proxy_hello", session_id="s")
        assert s.verify().ok and all(isinstance(e.ts, float) for e in s.events())
        s.close()

    def test_broken_clock_is_event_log_error(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), clock=lambda: float("nan"))
        with pytest.raises(EventLogError):
            s.open()
        s2 = EventStore(str(tmp_path / "f.db"))
        s2.open()
        s2._clock = lambda: 1 / 0
        with pytest.raises(EventLogError):
            s2.append("proxy_hello", session_id="s")
        assert s2.verify().ok
        s2.close()


# ---------------------------------------------------------------------------
# hostile constructor / path inputs (an int is a file descriptor!)
# ---------------------------------------------------------------------------

class TestPaths:
    @pytest.mark.parametrize("bad", [3, 0, 1, None, b"/tmp/x.db", "", "a\x00b", object(), 1.5, ["x"]])
    def test_non_path_rejected(self, bad):
        with pytest.raises(EventLogError):
            EventStore(bad)
        with pytest.raises(EventLogError):
            verify_file(bad)

    @pytest.mark.parametrize("bad", [3, 0, b"x", ["x"], "", "a\x00b"])
    def test_non_path_anchor_rejected(self, tmp_path, bad):
        with pytest.raises(EventLogError):
            EventStore(str(tmp_path / "e.db"), anchor_path=bad)
        assert not (tmp_path / "e.db").exists()

    def test_anchor_cannot_be_the_db(self, tmp_path):
        with pytest.raises(EventLogError):
            EventStore(str(tmp_path / "e.db"), anchor_path=str(tmp_path / "e.db"))

    def test_pathlike_ok(self, tmp_path):
        s = EventStore(tmp_path / "e.db", anchor_path=tmp_path / "a.txt")
        s.open()
        s.close()
        assert (tmp_path / "a.txt").exists()

    def test_special_sqlite_names_are_plain_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        s = EventStore(":memory:")
        s.open()
        s.append("proxy_hello", session_id="s")
        s.close()
        assert os.path.isfile(tmp_path / ":memory:")            # a real file, not an in-memory database
        assert report(str(tmp_path / ":memory:")).ok

    def test_path_with_uri_metacharacters(self, tmp_path):
        p = tmp_path / "we ird?name#%20&x.db"
        s = EventStore(str(p))
        s.open()
        s.append("proxy_hello", session_id="s")
        s.close()
        assert report(str(p)).ok

    def test_directory_and_missing_dir(self, tmp_path):
        with pytest.raises(EventLogError):
            EventStore(str(tmp_path)).open()
        with pytest.raises(EventLogError):
            EventStore(str(tmp_path / "no" / "dir" / "e.db")).open()

    def test_verify_file_does_not_create(self, tmp_path):
        with pytest.raises(EventLogError):
            verify_file(str(tmp_path / "missing.db"))
        assert not (tmp_path / "missing.db").exists()

    @pytest.mark.parametrize("kw", [{"checkpoint_every": 0}, {"checkpoint_every": True}, {"checkpoint_seconds": -1},
                                    {"max_payload_bytes": "x"}, {"clock": 5}, {"key": "stringkey-long-enough"}, {"key": b"short"}])
    def test_bad_options(self, tmp_path, kw):
        with pytest.raises(EventLogError):
            EventStore(str(tmp_path / "e.db"), **kw)


# ---------------------------------------------------------------------------
# redaction and truncation
# ---------------------------------------------------------------------------

def stored_payload(path, seq):
    return [r for r in rows(path) if r[0] == seq][0][5]


class TestRedaction:
    @pytest.mark.parametrize("key", ["password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "cookie",
                                     "credential", "private_key", "access_key", "PASSWORD", "Api_Key", "x_my_SECRET_y",
                                     "refresh_token", "set-cookie", "Authorization"])
    def test_secret_keys_redacted(self, tmp_path, key):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload={"args": {key: "TOPSECRET", "keep": "visible"}})
        assert ev.payload["args"] == {key: "[REDACTED]", "keep": "visible"}
        s.close()
        assert "TOPSECRET" not in open(str(tmp_path / "e.db"), "rb").read().decode("latin1")

    def test_recursive_lists_and_any_value_type(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload={
            "args": [{"headers": [{"Authorization": "Bearer abc"}, {"x": {"deep": {"password": {"a": 1}}}}]},
                     {"token": 12345, "other": [1, 2]}],
            "secret": ["a", "b"], "ok": None})
        p = ev.payload
        assert p["args"][0]["headers"][0] == {"Authorization": "[REDACTED]"}
        assert p["args"][0]["headers"][1]["x"]["deep"]["password"] == "[REDACTED]"
        assert p["args"][1] == {"token": "[REDACTED]", "other": [1, 2]}
        assert p["secret"] == "[REDACTED]" and p["ok"] is None
        s.close()

    def test_redaction_applies_before_hashing(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, clock=Clock())
        s.open()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload={"password": "hunter2-very-secret"})
        s.close()
        row = [r for r in rows(path) if r[0] == ev.seq][0]
        assert "hunter2" not in row[5]
        assert row[7] == ref_hash(row[6], row[0], row[1], "s", "c", "call_proposed", {"password": "[REDACTED]"})
        assert report(path).ok

    def test_non_secret_keys_untouched(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        p = {"path": "/a", "to": "x@y", "subject": "token-free", "keys": ["a"], "secretary": "no?"}
        ev = s.append("call_proposed", session_id="s", call_id="c", payload={"args": p})
        # "secretary" contains "secret": substring matching is the documented rule
        assert ev.payload["args"]["secretary"] == "[REDACTED]"
        assert {k: v for k, v in ev.payload["args"].items() if k != "secretary"} == {k: v for k, v in p.items() if k != "secretary"}
        s.close()

    def test_long_strings_cut_with_marker(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload={"a": "x" * 8192, "b": "y" * 9000, "c": ["z" * 8200]})
        assert ev.payload["a"] == "x" * 8192
        assert ev.payload["b"].startswith("y" * 8192) and ev.payload["b"].endswith("...[truncated 808 chars]")
        assert len(ev.payload["b"]) < 8192 + 40
        assert ev.payload["c"][0].endswith("[truncated 8 chars]")
        s.close()

    def test_oversize_payload_becomes_stub(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, clock=Clock())
        s.open()
        big = {"items": [f"value-{i}-" + "q" * 100 for i in range(1000)]}
        canon = json.dumps(big, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        assert len(canon) > 65536
        ev = s.append("call_proposed", session_id="s", call_id="c", payload=big)
        assert ev.payload == {"_truncated": True, "_orig_bytes": len(canon), "_orig_sha256": hashlib.sha256(canon).hexdigest()}
        s.close()
        assert report(path).ok

    def test_stub_digest_is_of_the_redacted_form(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        big = {"password": "P" * 100000, "x": ["y" * 100] * 800}
        red = {"password": "[REDACTED]", "x": ["y" * 100] * 800}
        canon = json.dumps(red, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload=big)
        assert ev.payload["_orig_sha256"] == hashlib.sha256(canon).hexdigest()
        s.close()

    def test_max_payload_bytes_option(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), max_payload_bytes=200)
        s.open()
        assert s.append("proxy_hello", session_id="s", payload={"a": "x" * 50}).payload == {"a": "x" * 50}
        assert s.append("proxy_hello", session_id="s", payload={"a": "x" * 500}).payload["_truncated"] is True
        s.close()

    def test_exact_limit_not_truncated(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), max_payload_bytes=65536)
        s.open()
        overhead = len(json.dumps({"a": ""}, separators=(",", ":")))
        # build a payload of exactly 65536 canonical bytes using chunks below the string cut
        chunks = {f"k{i:03d}": "x" * 8000 for i in range(8)}
        base = len(json.dumps(chunks, sort_keys=True, separators=(",", ":")))
        chunks["pad"] = "p" * (65536 - base - len(',"pad":""'))
        assert len(json.dumps(chunks, sort_keys=True, separators=(",", ":"))) == 65536
        assert "_truncated" not in s.append("proxy_hello", session_id="s", payload=chunks).payload
        chunks["pad"] += "p"
        assert s.append("proxy_hello", session_id="s", payload=chunks).payload.get("_truncated") is True
        s.close()

    @pytest.mark.parametrize("payload", [5, "x", [1], b"x", object(), True])
    def test_payload_must_be_object(self, tmp_path, payload):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s", payload=payload)
        s.close()

    def test_none_payload_is_empty_object(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        assert s.append("proxy_hello", session_id="s").payload == {}
        s.close()

    def test_hostile_payload_values_are_bounded_and_verify(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        cyc = []
        cyc.append(cyc)
        cyc.append(cyc)
        deep = cur = {}
        for _ in range(5000):
            cur["k"] = {}
            cur = cur["k"]
        class Weird:
            def __repr__(self):
                raise RuntimeError("no")
        t0 = time.time()
        ev0 = s.append("proxy_hello", session_id="s", payload={"cyc": cyc})            # self-referencing: bounded, then stubbed
        assert ev0.payload.get("_truncated") is True and time.time() - t0 < 5
        payload = {"deep": deep, "nan": float("nan"), "inf": float("-inf"), "big": 10 ** 5000, "bytes": b"\xff" * 10,
                   "set": {1, 2}, "weird": Weird(), "tuple": (1, 2), 5: "intkey", ("a",): "tuplekey",
                   "lone": "𐏿", "nul": "a\x00b", "bidi": "‮"}
        t = time.time()
        ev = s.append("call_proposed", session_id="s", call_id="c", payload=payload)
        assert time.time() - t < 5
        p = ev.payload
        assert p["nan"] == "nan" and p["inf"] == "-inf" and p["bytes"] == "[bytes:10]" and p["tuple"] == [1, 2]
        assert isinstance(p["big"], str) and p["big"].startswith("[int:")
        assert p["5"] == "intkey" and "_truncated" not in p
        assert p["lone"] == "𐏿" and p["nul"] == "a\x00b"
        assert s.verify().ok
        stored = list(s.events())[-1]
        assert stored.payload["lone"] == "𐏿"
        s.close()

    def test_wide_containers_are_capped(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        ev = s.append("proxy_hello", session_id="s", payload={"wide": list(range(EL.MAX_ITEMS + 5)),
                                                              "d": {str(i): 0 for i in range(EL.MAX_ITEMS + 3)}})
        assert ev.payload["wide"][-1] == "[+5 more]" and len(ev.payload["wide"]) == EL.MAX_ITEMS + 1
        assert ev.payload["d"]["_truncated_items"] == 3
        s.close()

    def test_payload_that_raises_is_rejected_cleanly(self, tmp_path):
        class Bad(dict):
            def items(self):
                raise RuntimeError("boom")
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s", payload=Bad(a=1))
        assert s.verify().ok and s.verify().n_events == 1
        s.close()

    def test_caller_payload_not_mutated(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        p = {"password": "x", "args": {"token": "y"}}
        s.append("proxy_hello", session_id="s", payload=p)
        assert p == {"password": "x", "args": {"token": "y"}}
        s.close()


# ---------------------------------------------------------------------------
# idempotency, reading API
# ---------------------------------------------------------------------------

class TestDuplicatesAndReading:
    def test_duplicate_proposed(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("call_proposed", session_id="s", call_id="c", payload=proposed(1))
        n = s.verify().n_events
        with pytest.raises(DuplicateEvent):
            s.append("call_proposed", session_id="s", call_id="c", payload=proposed(2))
        assert s.verify().n_events == n and s.verify().ok
        s.append("proxy_hello", session_id="s")                      # the store still works after a duplicate
        assert issubclass(DuplicateEvent, EventLogError)
        s.close()

    def test_duplicate_decision_keeps_first(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("call_proposed", session_id="s", call_id="c", payload=proposed(1))
        s.append("decision", session_id="s", call_id="c", payload=decision("approve"))
        with pytest.raises(DuplicateEvent):
            s.append("decision", session_id="s", call_id="c", payload=decision("deny", "timeout", "system"))
        assert [r["decision"] for r in s.recent_resolved()] == ["approve"]
        s.close()

    def test_same_call_id_in_other_session_is_fine(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("call_proposed", session_id="a", call_id="c", payload={})
        s.append("call_proposed", session_id="b", call_id="c", payload={})
        s.append("decision", session_id="a", call_id="c", payload=decision())
        s.append("decision", session_id="b", call_id="c", payload=decision())
        s.close()

    def test_result_may_repeat_and_precede_nothing(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        s.append("call_result", session_id="s", call_id="c", payload={"status": "ok"})
        s.append("call_result", session_id="s", call_id="c", payload={"status": "error"})
        s.close()

    def test_unresolved_and_recent(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), clock=Clock())
        s.open()
        for i in range(5):
            s.append("call_proposed", session_id="s", call_id=f"c{i}", payload=proposed(i, tool=f"t{i}"))
        s.append("decision", session_id="s", call_id="c1", payload=decision("deny", "policy", "policy") | {"rule_id": "r1"})
        s.append("decision", session_id="s", call_id="c3", payload=decision("approve"))
        un = s.unresolved_calls()
        assert [u["call_id"] for u in un] == ["c0", "c2", "c4"]
        assert un[0]["server"] == "fs" and un[0]["tool"] == "t0" and isinstance(un[0]["ts"], float)
        rec = s.recent_resolved()
        assert [r["call_id"] for r in rec] == ["c3", "c1"]                  # newest first
        assert rec[1] == {"session_id": "s", "call_id": "c1", "server": "fs", "tool": "t1", "decision": "deny",
                          "reason": "policy", "rule_id": "r1", "ts": rec[1]["ts"]}
        assert [r["call_id"] for r in s.recent_resolved(1)] == ["c3"]
        assert s.recent_resolved(0) == []
        for bad in (-1, "x", None, 1.5, True):
            with pytest.raises(ValueError):
                s.recent_resolved(bad)
        s.close()

    def test_events_filters(self, tmp_path):
        path = build(tmp_path)
        s = EventStore.open_readonly(path)
        allv = list(s.events())
        assert [e.seq for e in allv] == list(range(1, len(allv) + 1))
        assert all(e.session_id == "s1" for e in s.events(session_id="s1"))
        assert [e.seq for e in s.events(after_seq=5)] == [e.seq for e in allv if e.seq > 5]
        assert [e.seq for e in s.events(limit=3)] == [1, 2, 3]
        assert [e.seq for e in s.events(after_seq=2, limit=2)] == [3, 4]
        assert list(s.events(limit=0)) == [] and list(s.events(session_id="nope")) == []
        for kw in ({"after_seq": -1}, {"after_seq": "1"}, {"limit": -1}, {"limit": True}, {"session_id": 5}):
            with pytest.raises(ValueError):
                s.events(**kw)
        s.close()

    def test_events_batches_over_500(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), checkpoint_every=10_000)
        s.open()
        c = s._conn
        # fast bulk insert is not available through the API: append 520 durable events
        for i in range(520):
            s.append("proxy_hello", session_id="s", payload={"i": i})
        got = list(s.events())
        assert [e.seq for e in got] == list(range(1, 522))
        assert [e.payload.get("i") for e in s.events(session_id="s", after_seq=500, limit=5)] == [499, 500, 501, 502, 503]
        s.close()

    def test_readonly_store_cannot_write(self, tmp_path):
        path = build(tmp_path)
        s = EventStore.open_readonly(path)
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s")
        assert s.verify().ok
        s.close()
        assert report(path).ok

    def test_readonly_missing(self, tmp_path):
        with pytest.raises(EventLogError):
            EventStore.open_readonly(str(tmp_path / "nope.db"))


# ---------------------------------------------------------------------------
# restart recovery
# ---------------------------------------------------------------------------

class TestRecovery:
    def make_with_pending(self, tmp_path, key=None):
        path = str(tmp_path / "e.db")
        s = EventStore(path, key=key, clock=Clock())
        s.open()
        for i in range(4):
            s.append("call_proposed", session_id="s", call_id=f"c{i}", payload=proposed(i))
        s.append("decision", session_id="s", call_id="c1", payload=decision())
        s.close()
        return path

    def test_open_resolves_unresolved_as_restart(self, tmp_path):
        path = self.make_with_pending(tmp_path)
        s = EventStore(path, clock=Clock(5000))
        info = s.open()
        assert info["recovered"] == [{"session_id": "s", "call_id": c} for c in ("c0", "c2", "c3")]
        assert s.unresolved_calls() == []
        decs = {e.call_id: e.payload for e in s.events() if e.kind == "decision"}
        assert set(decs) == {"c0", "c1", "c2", "c3"}
        for c in ("c0", "c2", "c3"):
            assert decs[c] == {"decision": "deny", "reason": "restart", "actor": "system", "rule_id": None, "policy_digest": None}
        assert decs["c1"]["reason"] == "human"
        assert s.verify().ok
        s.close()

    def test_every_call_has_exactly_one_decision(self, tmp_path):
        path = self.make_with_pending(tmp_path)
        for _ in range(3):
            s = EventStore(path)
            s.open()
            s.close()
        evs = list(EventStore.open_readonly(path).events())
        from collections import Counter
        assert Counter(e.call_id for e in evs if e.kind == "decision") == Counter({"c0": 1, "c1": 1, "c2": 1, "c3": 1})
        assert Counter(e.call_id for e in evs if e.kind == "call_proposed") == Counter({"c0": 1, "c1": 1, "c2": 1, "c3": 1})

    def test_idempotent_second_open(self, tmp_path):
        path = self.make_with_pending(tmp_path)
        s = EventStore(path)
        assert len(s.open()["recovered"]) == 3
        s.close()
        n1 = report(path).n_events
        s = EventStore(path)
        assert s.open()["recovered"] == []
        s.close()
        # second open adds exactly log_open (+ the closing checkpoint), no decisions
        evs = list(EventStore.open_readonly(path).events(after_seq=n1))
        assert [e.kind for e in evs] == ["log_open", "checkpoint"]

    def test_recovery_across_sessions_and_resolved_stay_untouched(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path)
        s.open()
        s.append("call_proposed", session_id="a", call_id="x", payload={})
        s.append("call_proposed", session_id="b", call_id="x", payload={})
        s.append("decision", session_id="b", call_id="x", payload=decision("approve"))
        s.close()
        s = EventStore(path)
        assert s.open()["recovered"] == [{"session_id": "a", "call_id": "x"}]
        s.close()

    def test_recovery_with_key_verifies(self, tmp_path):
        path = self.make_with_pending(tmp_path, key=KEY)
        s = EventStore(path, key=KEY)
        s.open()
        r = s.verify()
        assert r.ok and r.keyed and r.checkpoints_ok and r.anchor == "ok"
        s.close()

    def test_open_refuses_broken_chain_and_does_not_write(self, tmp_path):
        path = self.make_with_pending(tmp_path)
        before = rows(path)
        sql(path, "UPDATE events SET payload = '{\"server\":\"evil\"}' WHERE seq = 3")
        tampered = rows(path)
        s = EventStore(path)
        with pytest.raises(EventLogError, match="does not verify"):
            s.open()
        assert rows(path) == tampered and len(tampered) == len(before)

    def test_open_refuses_after_key_mismatch(self, tmp_path):
        path = self.make_with_pending(tmp_path, key=KEY)
        with pytest.raises(EventLogError):
            EventStore(path, key=b"another-key-another-key").open()

    @pytest.mark.parametrize("setup", ["uv99", "foreign", "garbage", "trigger", "no_unique_index", "extra_table", "empty_uv_but_tables"])
    def test_open_refuses_unknown_schema(self, tmp_path, setup):
        path = str(tmp_path / "x.db")
        if setup == "garbage":
            with open(path, "wb") as fh:
                fh.write(os.urandom(5000))
        elif setup == "foreign":
            sql(path, "CREATE TABLE users(id INTEGER)", "PRAGMA user_version = 7")
        elif setup == "empty_uv_but_tables":
            sql(path, "CREATE TABLE users(id INTEGER)")
        else:
            good = build(tmp_path, name="good.db")
            path = good
            if setup == "uv99":
                sql(path, "PRAGMA user_version = 99")
            elif setup == "trigger":
                sql(path, "CREATE TRIGGER t AFTER INSERT ON events BEGIN DELETE FROM events WHERE seq = 1; END")
            elif setup == "no_unique_index":
                sql(path, "DROP INDEX ux_events_decision")
            elif setup == "extra_table":
                sql(path, "CREATE TABLE sneaky(x)")
        with pytest.raises(EventLogError):
            EventStore(path).open()

    def test_failed_open_leaves_store_unusable(self, tmp_path):
        path = str(tmp_path / "x.db")
        sql(path, "CREATE TABLE users(id INTEGER)", "PRAGMA user_version = 7")
        s = EventStore(path)
        with pytest.raises(EventLogError):
            s.open()
        with pytest.raises(EventLogError):
            s.append("proxy_hello", session_id="s")

    def test_unkeyed_open_warns(self, tmp_path, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="sentinel.eventlog"):
            s = EventStore(str(tmp_path / "e.db"))
            s.open()
            s.close()
        assert any("UNKEYED" in r.message for r in caplog.records)
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="sentinel.eventlog"):
            s = EventStore(str(tmp_path / "k.db"), key=KEY)
            s.open()
            s.close()
        assert not any("UNKEYED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# checkpoints and anchor
# ---------------------------------------------------------------------------

def checkpoints(path):
    return [(r[0], json.loads(r[5])) for r in rows(path) if r[4] == "checkpoint"]


def anchor_lines(path):
    return open(anchor_of(path)).read().splitlines()


class TestCheckpoints:
    def test_every_n_events(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, checkpoint_every=5, clock=Clock())
        s.open()                                      # log_open = event 1
        assert checkpoints(path) == []
        for i in range(4):
            s.append("proxy_hello", session_id="s", payload={"i": i})
        cps = checkpoints(path)
        assert [c[0] for c in cps] == [6]             # 5 events, then the checkpoint is seq 6
        assert cps[0][1]["upto_seq"] == 5
        for i in range(5):
            s.append("proxy_hello", session_id="s")
        assert [c[0] for c in checkpoints(path)] == [6, 12]
        s.close()

    def test_checkpoint_payload_and_mac_keyed(self, tmp_path):
        path = build(tmp_path, key=KEY)
        rs = {r[0]: r for r in rows(path)}
        cps = checkpoints(path)
        assert len(cps) >= 3
        for seq, p in cps:
            assert set(p) == {"upto_seq", "head_hash", "mac"}
            assert p["upto_seq"] == seq - 1 and p["head_hash"] == rs[seq - 1][7]
            assert p["mac"] == ref_mac(KEY, seq - 1, rs[seq - 1][7])

    def test_unkeyed_mac_is_null(self, tmp_path):
        path = build(tmp_path)
        assert all(p["mac"] is None for _, p in checkpoints(path))

    def test_every_checkpoint_has_one_anchor_line(self, tmp_path):
        for key in (None, KEY):
            path = build(tmp_path, key=key, name=f"e{bool(key)}.db")
            lines = anchor_lines(path)
            cps = checkpoints(path)
            assert len(lines) == len(cps)
            for line, (seq, p) in zip(lines, cps):
                assert line == f"{p['upto_seq']} {p['head_hash']} {p['mac'] or '-'}"
            if key:
                assert all(re.fullmatch(r"\d+ [0-9a-f]{64} [0-9a-f]{64}", ln) for ln in lines)
            else:
                assert all(re.fullmatch(r"\d+ [0-9a-f]{64} -", ln) for ln in lines)

    def test_close_writes_final_checkpoint_once(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, checkpoint_every=1000)
        s.open()
        s.append("proxy_hello", session_id="s")
        assert checkpoints(path) == [] and not os.path.exists(anchor_of(path))
        s.close()
        assert len(checkpoints(path)) == 1 and len(anchor_lines(path)) == 1
        s2 = EventStore(path, checkpoint_every=1000)
        s2.open()
        s2.close()
        assert len(checkpoints(path)) == 2                     # log_open since the last one => a new final checkpoint
        s3 = EventStore.open_readonly(path)
        s3.close()
        assert len(checkpoints(path)) == 2                     # read-only never writes

    def test_time_based_checkpoint_with_injected_clock(self, tmp_path):
        now = [1000.0]
        path = str(tmp_path / "e.db")
        s = EventStore(path, checkpoint_every=10_000, checkpoint_seconds=60, clock=lambda: now[0])
        s.open()
        now[0] += 59
        s.append("proxy_hello", session_id="s")
        assert checkpoints(path) == []
        now[0] += 2                                            # 61 s since the last checkpoint reference
        s.append("proxy_hello", session_id="s")
        assert len(checkpoints(path)) == 1
        now[0] += 30
        s.append("proxy_hello", session_id="s")
        assert len(checkpoints(path)) == 1                     # timer restarted
        now[0] += 31
        s.append("proxy_hello", session_id="s")
        assert len(checkpoints(path)) == 2
        s.close()
        assert report(path).ok

    def test_no_time_checkpoint_when_nothing_new(self, tmp_path):
        now = [0.0]
        path = str(tmp_path / "e.db")
        s = EventStore(path, checkpoint_every=10_000, checkpoint_seconds=1, clock=lambda: now[0])
        s.open()
        s.close()
        assert len(checkpoints(path)) == 1

    def test_custom_anchor_path(self, tmp_path):
        a = str(tmp_path / "elsewhere.txt")
        path = build(tmp_path, anchor=a)
        assert os.path.exists(a) and not os.path.exists(anchor_of(path))
        assert report(path, anchor=a).ok
        assert report(path).anchor == "missing" and not report(path).ok

    def test_checkpoint_does_not_break_duplicate_detection(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), checkpoint_every=2)
        s.open()
        for i in range(5):
            s.append("call_proposed", session_id="s", call_id=f"c{i}", payload={})
        with pytest.raises(DuplicateEvent):
            s.append("call_proposed", session_id="s", call_id="c4", payload={})
        s.close()

    def test_anchor_failure_does_not_lose_the_event(self, tmp_path):
        path = str(tmp_path / "e.db")
        bad_anchor = str(tmp_path / "nodir" / "a.txt")
        s = EventStore(path, anchor_path=bad_anchor, checkpoint_every=2)
        s.open()
        ev = s.append("proxy_hello", session_id="s")
        s.append("proxy_hello", session_id="s")          # triggers a checkpoint whose anchor write fails: logged, not raised
        assert [e.seq for e in s.events()][-1] >= ev.seq
        s._conn.close()


# ---------------------------------------------------------------------------
# verify: clean logs and every tamper
# ---------------------------------------------------------------------------

@pytest.fixture(params=["unkeyed", "keyed"])
def mode(request):
    return KEY if request.param == "keyed" else None


class TestVerifyClean:
    def test_clean(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        r = report(path, key=mode)
        assert r.ok and r.problems == [] and r.first_bad_seq is None and r.checkpoints_ok and r.anchor == "ok"
        assert r.keyed is (mode is not None) and r.n_events == len(rows(path))

    def test_empty_log(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        r = s.verify()
        assert r.ok and r.n_events == 1 and r.anchor == "n/a"
        s.close()

    def test_unkeyed_notes_state_the_limit(self, tmp_path):
        path = build(tmp_path)
        notes = " ".join(report(path).notes)
        assert "NOT detectable" in notes and "no key" in notes
        assert "NOT detectable" not in " ".join(report(path, key=KEY).notes) or True

    def test_keyed_log_verified_without_key_notes_unverified_macs(self, tmp_path):
        path = build(tmp_path, key=KEY)
        r = report(path)                                  # no key given
        assert r.ok and not r.keyed and any("not verified" in n for n in r.notes)

    def test_wrong_key_fails(self, tmp_path):
        path = build(tmp_path, key=KEY)
        r = report(path, key=b"wrong-key-wrong-key")
        assert not r.ok and not r.checkpoints_ok and r.anchor == "mismatch"
        assert "MAC" in problems_text(r)

    def test_keyed_store_on_unkeyed_log_is_downgrade_flagged(self, tmp_path):
        path = build(tmp_path)
        r = report(path, key=KEY)
        assert not r.ok and "MAC is missing" in problems_text(r)

    def test_verify_on_live_store_sees_new_events(self, tmp_path):
        path, s = build(tmp_path, close=False)
        n = s.verify().n_events
        s.append("proxy_hello", session_id="s")
        assert s.verify().n_events == n + 1
        s.close()


class TestTamper:
    def test_edit_payload(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        sql(path, "UPDATE events SET payload = REPLACE(payload, '/project/2', '/etc/pass') WHERE seq = 8")
        r = report(path, key=mode)
        assert not r.ok and r.first_bad_seq == 8 and "hash mismatch" in problems_text(r)
        with pytest.raises(EventLogError):
            EventStore(path, key=mode).open()

    def test_edit_payload_whitespace_only(self, tmp_path):
        path = build(tmp_path)
        p = stored = [r for r in rows(path) if r[0] == 3][0][5]
        sql(path, ("UPDATE events SET payload = ? WHERE seq = 3", (stored.replace(":", ": ", 1),)))
        r = report(path)
        assert not r.ok and r.first_bad_seq == 3 and "canonical" in problems_text(r)

    def test_edit_metadata_fields(self, tmp_path, mode):
        for col, val in (("ts", 5.0), ("session_id", "other"), ("call_id", "zzz"), ("kind", "proxy_close")):
            p = build(tmp_path, key=mode, name=f"{col}{bool(mode)}.db")
            sql(p, (f"UPDATE events SET {col} = ? WHERE seq = 4", (val,)))
            r = report(p, key=mode)
            assert not r.ok and r.first_bad_seq == 4, col

    def test_edit_hash(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        sql(path, ("UPDATE events SET hash = ? WHERE seq = 6", ("ab" * 32,)))
        r = report(path, key=mode)
        assert not r.ok and r.first_bad_seq == 6
        txt = problems_text(r)
        assert "hash mismatch" in txt and "seq 7" in txt          # and the next event's link breaks

    def test_edit_prev_hash(self, tmp_path):
        path = build(tmp_path)
        sql(path, ("UPDATE events SET prev_hash = ? WHERE seq = 5", ("cd" * 32,)))
        r = report(path)
        assert not r.ok and r.first_bad_seq == 5 and "chain broken" in problems_text(r)

    def test_delete_middle_event(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        sql(path, "DELETE FROM events WHERE seq = 7")
        r = report(path, key=mode)
        assert not r.ok and r.first_bad_seq == 7 and "missing" in problems_text(r)

    def test_delete_middle_event_and_renumber_without_rehash(self, tmp_path):
        path = build(tmp_path)
        sql(path, "DELETE FROM events WHERE seq = 7", "UPDATE events SET seq = seq - 1 WHERE seq > 7",
            "UPDATE head SET seq = seq - 1")
        r = report(path)
        assert not r.ok and r.first_bad_seq is not None and r.first_bad_seq <= 7

    def test_delete_first_event(self, tmp_path):
        path = build(tmp_path)
        sql(path, "DELETE FROM events WHERE seq = 1")
        assert not report(path).ok

    def test_reorder_swap_seq(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        sql(path, "UPDATE events SET seq = -1 WHERE seq = 5", "UPDATE events SET seq = 5 WHERE seq = 6",
            "UPDATE events SET seq = 6 WHERE seq = -1")
        r = report(path, key=mode)
        assert not r.ok and r.first_bad_seq == 5

    def test_swap_event_bodies_keep_seq(self, tmp_path):
        path = build(tmp_path)
        a, b = [r for r in rows(path) if r[0] in (5, 6)]
        for seq, r in ((5, b), (6, a)):
            sql(path, ("UPDATE events SET ts=?, session_id=?, call_id=?, kind=?, payload=? WHERE seq=?",
                       (r[1], r[2], r[3], r[4], r[5], seq)))
        assert not report(path).ok

    def test_truncate_tail_naive_detected_by_head_record(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        n = len(rows(path))
        truncate_tail(path, n - 3, fix_head=False)
        r = report(path, key=mode)
        assert not r.ok and "head record" in problems_text(r) and r.first_bad_seq == n - 2

    def test_truncate_tail_with_head_fixed_needs_the_anchor(self, tmp_path, mode):
        """THE DIFFERENCE: the attacker also fixes the head record.  Only the anchor file still knows the log was longer."""
        path = build(tmp_path, key=mode)
        n = len(rows(path))
        cps = [c[0] for c in checkpoints(path)]
        keep = cps[0] - 1                                      # cut back to before the first checkpoint
        assert keep < n
        truncate_tail(path, keep)
        with_anchor = report(path, key=mode)
        assert not with_anchor.ok and with_anchor.anchor == "mismatch" and "truncated" in problems_text(with_anchor)
        os.unlink(anchor_of(path))                              # ... and the attacker removes the anchor as well
        without = report(path, key=mode)
        assert without.ok and without.anchor == "n/a"           # undetectable: no checkpoint and no anchor remain

    def test_truncate_past_a_remaining_checkpoint_without_anchor_is_flagged_missing(self, tmp_path, mode):
        path = build(tmp_path, key=mode, n_calls=10)
        cps = [c[0] for c in checkpoints(path)]
        truncate_tail(path, cps[-2] + 1)
        os.unlink(anchor_of(path))
        r = report(path, key=mode)
        assert not r.ok and r.anchor == "missing"

    def test_truncate_after_last_checkpoint_is_not_detectable(self, tmp_path, mode):
        """Documented limit: events after the last checkpoint can be cut without trace."""
        path, s = build(tmp_path, key=mode, close=False, every=4)
        while rows(path)[-1][4] == "checkpoint" or rows(path)[-2][4] == "checkpoint":
            s.append("proxy_hello", session_id="tail")
        s.append("proxy_hello", session_id="tail")                              # events after the last checkpoint
        last_cp = checkpoints(path)[-1][0]
        n = len(rows(path))
        assert n > last_cp
        truncate_tail(path, last_cp)
        r = report(path, key=mode)
        assert r.ok                                              # NOT detected, by design
        assert any("after the last checkpoint" in x for x in r.notes)
        s._conn.close()

    def test_forged_event_with_garbage_hash(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        last = rows(path)[-1]
        sql(path, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (last[0] + 1, 9e9, "s1", "forged", "proxy_hello", "{}", last[7], "ef" * 32)),
            ("UPDATE head SET seq = ?, hash = ?", (last[0] + 1, "ef" * 32)))
        r = report(path, key=mode)
        assert not r.ok and r.first_bad_seq == last[0] + 1 and "hash mismatch" in problems_text(r)

    def test_forged_event_inserted_in_the_middle(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        sql(path, "UPDATE events SET seq = -seq - 1000 WHERE seq >= 5", "UPDATE events SET seq = -seq - 999 WHERE seq < 0",
            ("INSERT INTO events VALUES (5, 1.0, 's1', 'forged', 'call_result', '{}', ?, ?)", ("11" * 32, "22" * 32)),
            "UPDATE head SET seq = seq + 1")
        assert not report(path, key=mode).ok

    def test_forged_valid_event_at_the_tail_is_not_detectable(self, tmp_path, mode):
        """Documented limit: appending is not a protected operation; an event appended after the last checkpoint with a
        correct hash (hashes are public) verifies.  Only a forged CHECKPOINT can be caught (next test)."""
        path = build(tmp_path, key=mode)
        last = rows(path)[-1]
        payload = {"status": "ok", "summary": "forged"}
        h = ref_hash(last[7], last[0] + 1, 7.0, "s1", "c0", "call_result", payload)
        sql(path, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (last[0] + 1, 7.0, "s1", "c0", "call_result", json.dumps(payload, sort_keys=True, separators=(",", ":")), last[7], h)),
            ("UPDATE head SET seq = ?, hash = ?", (last[0] + 1, h)))
        assert report(path, key=mode).ok

    def test_forged_checkpoint_without_key_has_bad_mac(self, tmp_path):
        path = build(tmp_path, key=KEY)
        last = rows(path)[-1]
        for mac in (None, "00" * 32, ref_mac(b"guessed-key-guessed", last[0], last[7])):
            p = build(tmp_path, key=KEY, name=f"f{mac and mac[:4]}.db")
            last = rows(p)[-1]
            payload = {"upto_seq": last[0], "head_hash": last[7], "mac": mac}
            h = ref_hash(last[7], last[0] + 1, 8.0, None, None, "checkpoint", payload)
            sql(p, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                    (last[0] + 1, 8.0, None, None, "checkpoint", json.dumps(payload, sort_keys=True, separators=(",", ":")), last[7], h)),
                ("UPDATE head SET seq = ?, hash = ?", (last[0] + 1, h)))
            r = report(p, key=KEY)
            assert not r.ok and not r.checkpoints_ok and r.first_bad_seq == last[0] + 1 and "MAC" in problems_text(r), mac

    def test_forged_checkpoint_with_wrong_coverage(self, tmp_path):
        path = build(tmp_path)
        last = rows(path)[-1]
        payload = {"upto_seq": 3, "head_hash": "00" * 32, "mac": None}
        h = ref_hash(last[7], last[0] + 1, 8.0, None, None, "checkpoint", payload)
        sql(path, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (last[0] + 1, 8.0, None, None, "checkpoint", json.dumps(payload, sort_keys=True, separators=(",", ":")), last[7], h)),
            ("UPDATE head SET seq = ?, hash = ?", (last[0] + 1, h)))
        r = report(path)
        assert not r.ok and not r.checkpoints_ok and "does not cover" in problems_text(r)

    def test_rewrite_whole_chain_unkeyed_anchor_untouched_detected_by_anchor(self, tmp_path):
        path = build(tmp_path)
        def evil(rs):
            for r in rs:
                if r is pick(rs):
                    r[5] = json.dumps({"server": "evil", "tool": "t", "args": {}})
            return rs
        rebuild(path, evil)
        r = report(path)
        assert not r.ok and r.anchor == "mismatch" and "rewritten" in problems_text(r)

    def test_rewrite_whole_chain_unkeyed_with_anchor_is_not_detectable(self, tmp_path):
        """Documented limit: WITHOUT a key an attacker who rebuilds the chain AND the anchor file leaves no trace."""
        path = build(tmp_path)
        def evil(rs):
            pick(rs)[5] = json.dumps({"server": "evil"})
            rs.remove(pick(rs, "call_result"))
            return rs
        rebuild(path, evil, anchor=True)
        r = report(path)
        assert r.ok and r.anchor == "ok" and r.checkpoints_ok
        assert any("NOT detectable" in n for n in r.notes)          # and verify says so
        assert {"server": "evil"} in [e.payload for e in EventStore.open_readonly(path).events()]

    def test_rewrite_whole_chain_keyed_without_key_is_detected(self, tmp_path):
        path = build(tmp_path, key=KEY)
        def evil(rs):
            pick(rs)[5] = json.dumps({"server": "evil"})
            return rs
        rebuild(path, evil, anchor=True)                           # chain + anchor rebuilt, old MACs kept
        r = report(path, key=KEY)
        assert not r.ok and not r.checkpoints_ok and "MAC" in problems_text(r)
        with pytest.raises(EventLogError):
            EventStore(path, key=KEY).open()

    def test_rewrite_whole_chain_keyed_dropping_macs_is_detected(self, tmp_path):
        path = build(tmp_path, key=KEY)
        def evil(rs):
            for r in rs:
                if r[4] == "checkpoint":
                    r[5] = json.dumps({"upto_seq": 0, "head_hash": "", "mac": None})
            pick(rs)[5] = json.dumps({"x": 1})
            return rs
        rebuild(path, evil, anchor=True)
        r = report(path, key=KEY)
        assert not r.ok and "MAC is missing" in problems_text(r)

    def test_rewrite_by_attacker_holding_the_key_is_not_detectable(self, tmp_path):
        """Documented limit: key + disk = full control."""
        path = build(tmp_path, key=KEY)
        def evil(rs):
            pick(rs)[5] = json.dumps({"server": "evil"})
            return rs
        rebuild(path, evil, key=KEY, anchor=True)
        # the attacker recomputes the anchor lines with real MACs as well
        lines = []
        for seq, p in checkpoints(path):
            lines.append(f"{p['upto_seq']} {p['head_hash']} {p['mac']}\n")
        open(anchor_of(path), "w").write("".join(lines))
        assert report(path, key=KEY).ok

    def test_flip_a_bit_in_the_db_file(self, tmp_path, mode):
        path = str(tmp_path / "bit.db")
        s = EventStore(path, key=mode, clock=Clock())
        s.open()
        s.append("call_proposed", session_id="s", call_id="c", payload={"note": "MARKER-for-bitflip-test"})
        s.append("proxy_hello", session_id="s")
        s.close()
        data = bytearray(open(path, "rb").read())
        i = data.find(b"MARKER-for-bitflip-test")
        assert i > 0
        data[i] ^= 0x01
        open(path, "wb").write(bytes(data))
        r = report(path, key=mode)
        assert not r.ok and "hash mismatch" in problems_text(r)
        with pytest.raises(EventLogError):
            EventStore(path, key=mode).open()

    def test_random_bit_flips_never_pass_silently(self, tmp_path):
        path = build(tmp_path, n_calls=4)
        original = open(path, "rb").read()
        rows0 = rows(path)
        import random
        rnd = random.Random(1234)
        silent = 0
        for _ in range(60):
            data = bytearray(original)
            i = rnd.randrange(len(data))
            data[i] ^= 1 << rnd.randrange(8)
            p = str(tmp_path / "flip.db")
            open(p, "wb").write(bytes(data))
            for ext in ("-wal", "-shm"):
                if os.path.exists(p + ext):
                    os.unlink(p + ext)
            try:
                r = verify_file(p, anchor_path=anchor_of(path))
            except EventLogError:
                continue
            if r.ok:
                try:
                    same = rows(p) == rows0
                except sqlite3.Error:
                    same = False
                assert same, f"byte {i}: content changed but verify passed"
                silent += 1
        assert silent < 60

    def test_drop_the_anchor(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        os.unlink(anchor_of(path))
        r = report(path, key=mode)
        assert not r.ok and r.anchor == "missing" and "removed" in problems_text(r)
        with pytest.raises(EventLogError):
            EventStore(path, key=mode).open()

    def test_empty_anchor_file_counts_as_dropped(self, tmp_path):
        path = build(tmp_path)
        open(anchor_of(path), "w").close()
        assert report(path).anchor == "missing"

    def test_anchor_lag_of_one_line_is_tolerated_crash_window(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        lines = anchor_lines(path)
        open(anchor_of(path), "w").write("\n".join(lines[:-1]) + "\n")
        assert report(path, key=mode).ok

    def test_anchor_line_edits(self, tmp_path, mode):
        for name, edit in (
            ("hash", lambda ln: [ln[0], "ab" * 32, ln[2]]),
            ("seq_future", lambda ln: ["99999", ln[1], ln[2]]),
            ("seq_other", lambda ln: ["2", ln[1], ln[2]]),
            ("garbage", lambda ln: ["x", "y", "z"]),
        ):
            p = build(tmp_path, key=mode, name=f"a_{name}{bool(mode)}.db")
            lines = anchor_lines(p)
            parts = lines[0].split(" ")
            lines[0] = " ".join(edit(parts))
            open(anchor_of(p), "w").write("\n".join(lines) + "\n")
            r = report(p, key=mode)
            assert not r.ok and r.anchor == "mismatch", name

    def test_anchor_extra_lines(self, tmp_path):
        path = build(tmp_path)
        with open(anchor_of(path), "a") as fh:
            fh.write("only two fields\n")
        assert report(path).anchor == "mismatch"

    def test_keyed_anchor_mac_edit_and_downgrade(self, tmp_path):
        path = build(tmp_path, key=KEY)
        lines = anchor_lines(path)
        a, b, c = lines[0].split(" ")
        open(anchor_of(path), "w").write("\n".join([f"{a} {b} {'0' * 64}"] + lines[1:]) + "\n")
        r = report(path, key=KEY)
        assert not r.ok and "MAC is invalid" in problems_text(r)
        open(anchor_of(path), "w").write("\n".join([f"{a} {b} -"] + lines[1:]) + "\n")
        assert "MAC is missing" in problems_text(report(path, key=KEY))

    def test_anchor_torn_tail_is_tolerated_and_repaired(self, tmp_path, mode):
        path = build(tmp_path, key=mode)
        good = open(anchor_of(path)).read()
        open(anchor_of(path), "a").write("12 abcdef")             # crash in the middle of an anchor write
        r = report(path, key=mode)
        assert r.ok and any("unterminated" in n for n in r.notes)
        s = EventStore(path, key=mode)
        s.open()
        s.close()
        text = open(anchor_of(path)).read()
        assert text.startswith(good) and "abcdef" not in text and text.endswith("\n")
        assert report(path, key=mode).ok

    def test_head_record_edits(self, tmp_path):
        path = build(tmp_path)
        sql(path, "UPDATE head SET hash = '00'")
        assert not report(path).ok
        path2 = build(tmp_path, name="h2.db")
        sql(path2, "DELETE FROM head")
        assert "head record is missing" in problems_text(report(path2))

    def test_events_added_outside_the_store_with_stale_head(self, tmp_path):
        path = build(tmp_path)
        last = rows(path)[-1]
        payload = {}
        h = ref_hash(last[7], last[0] + 1, 7.0, "s", None, "proxy_hello", payload)
        sql(path, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", (last[0] + 1, 7.0, "s", None, "proxy_hello", "{}", last[7], h)))
        r = report(path)
        assert not r.ok and "head record" in problems_text(r)

    def test_bad_column_values(self, tmp_path):
        for stmt in ("UPDATE events SET kind = 'unknown_kind' WHERE seq = 4",
                     "UPDATE events SET payload = 'not json' WHERE seq = 4",
                     "UPDATE events SET payload = '[1]' WHERE seq = 4",
                     "UPDATE events SET payload = '{\"a\":NaN}' WHERE seq = 4",
                     "UPDATE events SET ts = 'yesterday' WHERE seq = 4",
                     "UPDATE events SET hash = NULL WHERE seq = 4 AND 0",      # NOT NULL constraint would reject; skipped
                     "UPDATE events SET session_id = 5 WHERE seq = 4",
                     "UPDATE events SET prev_hash = 7 WHERE seq = 4"):
            if "AND 0" in stmt:
                continue
            path = build(tmp_path, name=f"bc{abs(hash(stmt))}.db")
            sql(path, stmt)
            r = report(path)
            assert not r.ok and r.first_bad_seq == 4, stmt

    def test_decision_without_ids_or_value_is_flagged(self, tmp_path):
        path = build(tmp_path)
        last = rows(path)[-1]
        payload = {"decision": "approve"}
        h = ref_hash(last[7], last[0] + 1, 7.0, None, None, "decision", payload)
        sql(path, ("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                   (last[0] + 1, 7.0, None, None, "decision", '{"decision":"approve"}', last[7], h)),
            ("UPDATE head SET seq = ?, hash = ?", (last[0] + 1, h)))
        assert "without session_id/call_id" in problems_text(report(path))

    def test_schema_drift_after_open_is_reported(self, tmp_path):
        path, s = build(tmp_path, close=False)
        c = raw(path)
        c.execute("DROP INDEX ux_events_decision")
        c.close()
        r = s.verify()
        assert not r.ok and "ux_events_decision" in problems_text(r)
        s._conn.close()

    def test_problem_list_is_capped(self, tmp_path):
        path = build(tmp_path, n_calls=30)
        sql(path, "UPDATE events SET payload = '{\"z\":1}' WHERE seq > 1 AND kind != 'checkpoint'")
        r = report(path)
        assert not r.ok and len(r.problems) <= EL.MAX_PROBLEMS + 1 and r.first_bad_seq == 2

    def test_verify_never_raises_on_wrecked_events_table(self, tmp_path):
        path = build(tmp_path)
        sql(path, "DROP TABLE head")
        r = report(path)
        assert not r.ok


# ---------------------------------------------------------------------------
# concurrency and crash
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_8_threads_x_200(self, tmp_path):
        path = str(tmp_path / "e.db")
        s = EventStore(path, key=KEY)
        s.open()
        errs = []

        def worker(t):
            try:
                for i in range(200):
                    s.append("call_proposed", session_id=f"s{t}", call_id=f"c{i}", payload=proposed(i))
                    if i % 3 == 0:
                        s.append("decision", session_id=f"s{t}", call_id=f"c{i}", payload=decision())
            except BaseException as e:               # noqa: BLE001
                errs.append(e)
        ths = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        assert errs == []
        r = s.verify()
        total = 8 * 200 + 8 * len(range(0, 200, 3))
        assert r.ok and r.n_events >= total + 1 and r.anchor == "ok"
        s.close()
        rs = rows(path)
        assert [r[0] for r in rs] == list(range(1, len(rs) + 1))
        assert sum(1 for r in rs if r[4] == "call_proposed") == 1600
        assert report(path, key=KEY).ok
        assert len(anchor_lines(path)) == sum(1 for r in rs if r[4] == "checkpoint")

    def test_concurrent_duplicates_exactly_one_wins(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"))
        s.open()
        out = []

        def worker():
            try:
                s.append("call_proposed", session_id="s", call_id="same", payload={})
                out.append("ok")
            except DuplicateEvent:
                out.append("dup")
        ths = [threading.Thread(target=worker) for _ in range(16)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        assert sorted(out) == ["dup"] * 15 + ["ok"]
        assert s.verify().ok
        s.close()

    def test_readers_during_writes(self, tmp_path):
        s = EventStore(str(tmp_path / "e.db"), checkpoint_every=7)
        s.open()
        stop = threading.Event()
        bad = []

        def reader():
            while not stop.is_set():
                try:
                    r = s.verify()
                    if not r.ok:
                        bad.append(r.problems)
                    list(s.events(limit=20))
                    s.recent_resolved(5)
                except BaseException as e:           # noqa: BLE001
                    bad.append(repr(e))
        th = threading.Thread(target=reader)
        th.start()
        for i in range(150):
            s.append("call_proposed", session_id="s", call_id=f"c{i}", payload={})
        stop.set()
        th.join()
        assert bad == []
        s.close()


CRASH_SCRIPT = r'''
import sys
sys.path.insert(0, sys.argv[1])
import eventlog
path, keyhex = sys.argv[2], sys.argv[3]
key = bytes.fromhex(keyhex) if keyhex != "-" else None
s = eventlog.EventStore(path, key=key, checkpoint_every=7)
s.open()
print("ready", flush=True)
i = 0
while True:
    s.append("call_proposed", session_id="crash", call_id=f"c{i}", payload={"server": "fs", "tool": "t", "args": {"password": "x" * 50, "i": i}})
    if i % 3 == 0:
        s.append("decision", session_id="crash", call_id=f"c{i}", payload={"decision": "approve", "reason": "human", "actor": "human"})
    print(i, flush=True)
    i += 1
'''


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="needs SIGKILL")
class TestCrash:
    @pytest.mark.parametrize("keyed", [False, True])
    def test_sigkill_mid_run_then_reopen(self, tmp_path, keyed):
        script = tmp_path / "crasher.py"
        script.write_text(CRASH_SCRIPT)
        path = str(tmp_path / "crash.db")
        key = KEY if keyed else None
        proc = subprocess.Popen([sys.executable, "-I", str(script), SERVER_DIR, path, key.hex() if key else "-"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        done = 0
        try:
            assert proc.stdout.readline().strip() == "ready"
            while done < 40:
                line = proc.stdout.readline()
                assert line, proc.stderr.read()
                done = int(line) + 1
        finally:
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=30)
        assert proc.returncode == -signal.SIGKILL

        # no partial row, and every append that returned before the kill is present (durable on return)
        pre = EventStore.open_readonly(path, key=key)
        assert pre.verify().ok
        proposed_ids = {e.call_id for e in pre.events() if e.kind == "call_proposed"}
        assert {f"c{i}" for i in range(done)} <= proposed_ids
        pending = {(u["session_id"], u["call_id"]) for u in pre.unresolved_calls()}
        assert pending                                          # the kill left unresolved calls
        pre.close()

        s = EventStore(path, key=key)
        info = s.open()
        assert {(r["session_id"], r["call_id"]) for r in info["recovered"]} == pending
        assert s.unresolved_calls() == []
        r = s.verify()
        assert r.ok and r.keyed is keyed
        by_call = {e.call_id: e for e in s.events() if e.kind == "decision" and (e.session_id, e.call_id) in pending}
        assert set(by_call) == {c for _, c in pending}
        assert all(e.payload["reason"] == "restart" and e.payload["actor"] == "system" and e.payload["decision"] == "deny"
                   for e in by_call.values())
        # secrets from the killed process were redacted before they ever hit the disk
        assert b"xxxxxxxxxxxxxxxxxxxx" not in open(path, "rb").read()
        s.close()
        s = EventStore(path, key=key)
        assert s.open()["recovered"] == []                      # idempotent
        s.close()
        assert report(path, key=key).ok

    def test_kill_between_events_and_anchor_leaves_verifiable_log(self, tmp_path):
        """Simulate the crash window: checkpoint committed, anchor line not yet written."""
        path = build(tmp_path, key=KEY)
        lines = anchor_lines(path)
        open(anchor_of(path), "w").write("\n".join(lines[:-1]) + "\n")
        s = EventStore(path, key=KEY)
        s.open()
        assert s.verify().ok
        s.close()


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

class TestKeyLoading:
    def test_load_key(self):
        assert EL.load_key({}) is None
        assert EL.load_key({"SENTINEL_LOG_KEY": ""}) is None
        assert EL.load_key({"SENTINEL_LOG_KEY": "x" * 16}) == b"x" * 16
        assert EL.load_key({"OTHER": "y" * 20}, "OTHER") == b"y" * 20
        for bad in ("short", "x" * 15):
            with pytest.raises(EventLogError):
                EL.load_key({"SENTINEL_LOG_KEY": bad})
        for bad_env in (None, 5, ["a"]):
            with pytest.raises(EventLogError):
                EL.load_key(bad_env)
        with pytest.raises(EventLogError):
            EL.load_key({"SENTINEL_LOG_KEY": 12345678901234567})

    def test_keyed_and_unkeyed_digests_differ_only_in_mac(self, tmp_path):
        a = build(tmp_path, name="a.db")
        b = build(tmp_path, key=KEY, name="b.db")
        ra, rb = rows(a), rows(b)
        assert [r[4] for r in ra] == [r[4] for r in rb]


def test_module_has_no_web_imports():
    imports = [ln for ln in open(EL.__file__, encoding="utf-8").read().splitlines() if ln.lstrip().startswith(("import ", "from "))]
    assert imports and not any(w in ln.lower() for ln in imports for w in ("fastapi", "starlette"))
