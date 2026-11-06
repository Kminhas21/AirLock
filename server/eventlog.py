"""Durable, tamper-evident event log (docs/plans/EVENT-LOG.md, tickets EL1).

An append-only, hash-chained SQLite log.  Pure library (sync, thread-safe: one connection per store, every call under one
lock); callers use ``asyncio.to_thread``.  No web imports.

    store = EventStore("/var/lib/sentinel/events.db", key=load_key(os.environ))
    info = store.open()                    # verifies the chain, appends log_open, resolves unresolved calls as "restart"
    store.append("call_proposed", session_id="s", call_id="c", payload={...})
    store.verify()                         # VerifyReport
    store.close()                          # final checkpoint

What it detects (honest threat model; see also VerifyReport.notes):
  * edit / delete / reorder / insert of events by someone who can modify the DB file but does not hold the key;
  * truncation of the tail up to the last ANCHORED checkpoint (anchor file, fsync'd, one line per checkpoint) and a
    rebuilt chain when KEYED (forged checkpoints cannot carry a valid HMAC);
  * it does NOT detect: an attacker holding the key; truncation of the tail after the last checkpoint; and, WITHOUT a key,
    a chain (and anchor file) rebuilt consistently - the hashes are public, so an unkeyed log only proves internal
    consistency plus agreement with the anchor file.
Anchor lines are `seq head_hash mac` (`-` when unkeyed); `seq`/`head_hash` are the checkpoint's `upto_seq`/`head_hash`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping

log = logging.getLogger("sentinel.eventlog")

SCHEMA_VERSION = 1
GENESIS = "0" * 64
KINDS = ("log_open", "proxy_hello", "proxy_close", "call_proposed", "decision", "call_result", "checkpoint")
_RESERVED = ("log_open", "checkpoint")                  # written by the store itself, never by callers
_NEEDS_CALL = ("call_proposed", "decision", "call_result")
SECRET_KEY_PARTS = ("password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "cookie",
                    "credential", "private_key", "access_key")
REDACTED = "[REDACTED]"
MAX_STRING = 8192
MAX_DEPTH = 20
MAX_ITEMS = 2000
MAX_NODES = 100_000
MAX_ID = 200
MIN_KEY_LEN = 16
MAX_ANCHOR_BYTES = 16_000_000
MAX_PROBLEMS = 200
KEY_ENV = "SENTINEL_LOG_KEY"

_HEX64 = re.compile(r"[0-9a-f]{64}")

_SQL_EVENTS = ("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session_id TEXT, call_id TEXT, "
               "kind TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)")
_SQL_HEAD = "CREATE TABLE head(id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL, hash TEXT NOT NULL)"
_SQL_UX_PROPOSED = "CREATE UNIQUE INDEX ux_events_proposed ON events(session_id, call_id) WHERE kind = 'call_proposed'"
_SQL_UX_DECISION = "CREATE UNIQUE INDEX ux_events_decision ON events(session_id, call_id) WHERE kind = 'decision'"
_SQL_IX_SESSION = "CREATE INDEX ix_events_session ON events(session_id, seq)"
_EXPECTED_SCHEMA = {
    ("table", "events"): _SQL_EVENTS, ("table", "head"): _SQL_HEAD, ("index", "ux_events_proposed"): _SQL_UX_PROPOSED,
    ("index", "ux_events_decision"): _SQL_UX_DECISION, ("index", "ix_events_session"): _SQL_IX_SESSION,
}


class EventLogError(Exception):
    pass


class DuplicateEvent(EventLogError):
    """A second call_proposed / decision for the same (session_id, call_id)."""


@dataclass(frozen=True)
class Event:
    seq: int
    ts: float
    session_id: "str | None"
    call_id: "str | None"
    kind: str
    payload: dict
    prev_hash: str
    hash: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    n_events: int
    first_bad_seq: "int | None"
    problems: list
    checkpoints_ok: bool
    anchor: str                     # ok | missing | mismatch | n/a
    keyed: bool
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# canonical form, hashing, redaction
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def compute_hash(prev_hash: str, seq: int, ts: float, session_id, call_id, kind: str, payload: Any) -> str:
    body = canonical_json({"seq": seq, "ts": ts, "session_id": session_id, "call_id": call_id, "kind": kind, "payload": payload})
    return hashlib.sha256((prev_hash + "\n" + body).encode("utf-8")).hexdigest()


def _mac(key: bytes, seq: int, head_hash: str) -> str:
    return hmac.new(key, f"{seq}\n{head_hash}".encode("utf-8"), hashlib.sha256).hexdigest()


class _Budget:
    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n


def _cut(s: str) -> str:
    return s if len(s) <= MAX_STRING else s[:MAX_STRING] + f"...[truncated {len(s) - MAX_STRING} chars]"


def _secret_key(k: str) -> bool:
    kl = k.lower()
    return any(p in kl for p in SECRET_KEY_PARTS)


def _clean(v: Any, b: _Budget, depth: int) -> Any:
    """JSON-safe, redacted, bounded copy of v (never raises for ordinary objects; hostile ones raise and are rejected)."""
    b.n -= 1
    if b.n < 0:
        return "[TRUNCATED]"
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if v.bit_length() <= 63 else f"[int:{v.bit_length()} bits]"
    if isinstance(v, float):
        return v if math.isfinite(v) else repr(v)
    if isinstance(v, str):
        return _cut(v)
    if isinstance(v, (bytes, bytearray)):
        return f"[bytes:{len(v)}]"
    if depth >= MAX_DEPTH:
        return "[DEPTH]"
    if isinstance(v, Mapping):
        out: dict = {}
        for i, (k, val) in enumerate(v.items()):
            if i >= MAX_ITEMS:
                out["_truncated_items"] = len(v) - MAX_ITEMS
                break
            key = k if isinstance(k, str) else str(k)
            key = key[:256]
            out[key] = REDACTED if _secret_key(key) else _clean(val, b, depth + 1)
        return out
    if isinstance(v, (list, tuple)):
        items = [_clean(x, b, depth + 1) for x in v[:MAX_ITEMS]]
        if len(v) > MAX_ITEMS:
            items.append(f"[+{len(v) - MAX_ITEMS} more]")
        return items
    return _cut(f"[{type(v).__name__}]")


def sanitize_payload(payload: Any, max_bytes: int = 65536) -> dict:
    """Redact secret-looking keys, cut long strings, replace an oversize payload by a digest stub.  Applied BEFORE hashing."""
    if payload is None:
        payload = {}
    if not isinstance(payload, Mapping):
        raise EventLogError("payload must be an object (dict) or None")
    try:
        cleaned = _clean(payload, _Budget(MAX_NODES), 0)
        text = canonical_json(cleaned)
    except EventLogError:
        raise
    except Exception as e:                                   # hostile __iter__/__len__, etc.
        raise EventLogError(f"payload cannot be serialised ({type(e).__name__})") from None
    raw = text.encode("utf-8")
    if len(raw) > max_bytes:
        return {"_truncated": True, "_orig_bytes": len(raw), "_orig_sha256": hashlib.sha256(raw).hexdigest()}
    return cleaned


def load_key(env: Any, name: str = KEY_ENV) -> "bytes | None":
    """SENTINEL_LOG_KEY from a mapping (os.environ); None when unset/empty; EventLogError when set but shorter than 16 chars."""
    if not isinstance(env, Mapping):
        raise EventLogError("env must be a mapping")
    raw = env.get(name)
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise EventLogError(f"{name} must be a string")
    if len(raw) < MIN_KEY_LEN:
        raise EventLogError(f"{name} must be at least {MIN_KEY_LEN} characters")
    return raw.encode("utf-8")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fspath(p: Any, what: str) -> str:
    """str path only: NEVER hand a non-path (an int is a file descriptor!) to open()/os.stat()."""
    if not isinstance(p, (str, os.PathLike)):
        raise EventLogError(f"{what} must be a path (str or PathLike), not {type(p).__name__}")
    try:
        s = os.fspath(p)
    except TypeError:
        raise EventLogError(f"{what} must be a path") from None
    if not isinstance(s, str) or not s or "\x00" in s:
        raise EventLogError(f"{what} must be a non-empty string without NUL")
    return s


def _check_id(name: str, v: Any) -> "str | None":
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > MAX_ID:
        raise ValueError(f"{name} must be a string of at most {MAX_ID} characters or None")
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} contains lone surrogates") from None
    return v


def _loads_obj(text: Any) -> dict:
    """Lenient parse for READING: a damaged payload becomes a marker (verify() reports the damage)."""
    try:
        v = json.loads(text)
        if isinstance(v, dict):
            return v
    except (ValueError, TypeError, RecursionError):
        pass
    return {"_invalid_json": True}


def _no_const(name):
    raise ValueError(name)


def _norm_sql(s: Any) -> str:
    return " ".join(str(s).split()).replace(" (", "(").replace("( ", "(").replace(" )", ")")


def _connect(path: str, readonly: bool) -> sqlite3.Connection:
    uri = "file:" + urllib.parse.quote(os.path.abspath(path), safe="/") + ("?mode=ro" if readonly else "?mode=rw")
    try:
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False, isolation_level=None, timeout=30)
    except sqlite3.Error as e:
        raise EventLogError(f"cannot open {path}: {e}") from None
    return conn


def _check_schema(conn: sqlite3.Connection, create: bool) -> list:
    """-> drift problems (strings) at schema v1.  Raises EventLogError for an unknown / foreign / empty database."""
    try:
        uv = conn.execute("PRAGMA user_version").fetchone()[0]
        objs = conn.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'").fetchall()
        if uv == 0 and not objs:
            if not create:
                raise EventLogError("database is empty: not a sentinel event log")
            conn.execute("BEGIN IMMEDIATE")
            try:
                for sql in (_SQL_EVENTS, _SQL_HEAD, _SQL_UX_PROPOSED, _SQL_UX_DECISION, _SQL_IX_SESSION):
                    conn.execute(sql)
                conn.execute("INSERT INTO head(id, seq, hash) VALUES (1, 0, ?)", (GENESIS,))
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            return []
        if uv != SCHEMA_VERSION:
            raise EventLogError(f"unknown database schema (user_version {uv}, expected {SCHEMA_VERSION}"
                                f"{'; not a sentinel event log' if objs and uv == 0 else ''})")
    except sqlite3.Error as e:
        raise EventLogError(f"cannot read database: {e}") from None
    problems = []
    got = {(t, n): s for t, n, s in objs}
    for k in sorted(set(got) - set(_EXPECTED_SCHEMA)):
        problems.append(f"unexpected schema object {k[0]} {k[1]!r}")
    for k, sql in _EXPECTED_SCHEMA.items():
        if k not in got:
            problems.append(f"schema object {k[0]} {k[1]!r} is missing")
        elif _norm_sql(got[k]) != _norm_sql(sql):
            problems.append(f"schema object {k[0]} {k[1]!r} was altered")
    return problems


# ---------------------------------------------------------------------------
# verification (shared by EventStore.verify and the read-only CLI path)
# ---------------------------------------------------------------------------

def _read_anchor(path: str) -> "tuple[list | None, list]":
    """-> (lines | None if the file does not exist, notes).  Each line is (lineno, text)."""
    notes: list = []
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_ANCHOR_BYTES + 1)
    except FileNotFoundError:
        return None, notes
    except OSError as e:
        raise EventLogError(f"cannot read anchor file {path}: {e}") from None
    if len(raw) > MAX_ANCHOR_BYTES:
        raise EventLogError(f"anchor file {path} is larger than {MAX_ANCHOR_BYTES} bytes")
    text = raw.decode("utf-8", errors="replace")
    parts = text.split("\n")
    if parts and parts[-1] != "":                           # unterminated last line = torn write from a crash
        notes.append(f"ignored an unterminated last line in the anchor file ({len(parts[-1])} bytes; crash during write?)")
    lines = [(i + 1, p) for i, p in enumerate(parts[:-1])]
    return lines, notes


def _verify_conn(conn: sqlite3.Connection, key: "bytes | None", anchor_path: str, schema_problems=None) -> VerifyReport:
    problems: list = []
    notes: list = []
    bad: list = []                                          # seqs that carry a problem
    keyed = key is not None
    cp_bad = False
    extra = 0

    def prob(msg: str, seq: "int | None" = None):
        nonlocal extra
        if len(problems) < MAX_PROBLEMS:
            problems.append(msg)
        else:
            extra += 1
        if seq is not None:
            bad.append(seq)

    for m in (schema_problems or []):
        prob(f"schema: {m}")
    n = 0
    last_seq, last_hash = 0, GENESIS
    prev_seen_hash = GENESIS
    expected = 1
    n_cp = 0
    unverified_macs = 0
    try:
        cur = conn.execute("SELECT seq, ts, session_id, call_id, kind, payload, prev_hash, hash FROM events ORDER BY seq")
        for seq, ts, sid, cid, kind, ptext, prev, h in cur:
            n += 1
            where = f"seq {seq}"
            if not isinstance(seq, int) or isinstance(seq, bool):
                prob(f"{where}: seq is not an integer")
                continue
            if seq != expected:
                if seq > expected:
                    prob(f"{where}: events {expected}..{seq - 1} are missing (sequence gap)", expected)
                else:
                    prob(f"{where}: sequence out of order or duplicated (expected {expected})", seq)
            expected = seq + 1
            if not isinstance(prev, str) or not isinstance(h, str):
                prob(f"{where}: hash fields are not text", seq)
                prev_seen_hash = h if isinstance(h, str) else ""
                last_seq, last_hash = seq, prev_seen_hash
                continue
            if prev != prev_seen_hash:
                prob(f"{where}: prev_hash does not match the hash of the previous event (chain broken)", seq)
            if kind not in KINDS:
                prob(f"{where}: unknown kind {str(kind)[:40]!r}", seq)
            if not (isinstance(ts, (int, float)) and not isinstance(ts, bool) and math.isfinite(ts)):
                prob(f"{where}: ts is not a finite number", seq)
                ts_ok = False
            else:
                ts_ok = True
            for nm, v in (("session_id", sid), ("call_id", cid)):
                if v is not None and not isinstance(v, str):
                    prob(f"{where}: {nm} is not text", seq)
            payload = None
            try:
                payload = json.loads(ptext, parse_constant=_no_const)
                if not isinstance(payload, dict):
                    raise ValueError("payload is not an object")
                if canonical_json(payload) != ptext:
                    prob(f"{where}: payload is not in canonical form", seq)
            except (ValueError, TypeError, RecursionError) as e:
                prob(f"{where}: payload is not valid JSON ({type(e).__name__})", seq)
                payload = None
            if payload is not None and ts_ok and kind in KINDS:
                try:
                    exp = compute_hash(prev, seq, float(ts), sid, cid, kind, payload)
                except (ValueError, TypeError, RecursionError):
                    exp = None
                if exp is None or not hmac.compare_digest(exp, h):
                    prob(f"{where}: hash mismatch (event content was modified)", seq)
            elif payload is None or not ts_ok:
                pass
            if kind in _NEEDS_CALL and (not isinstance(sid, str) or not isinstance(cid, str)):
                prob(f"{where}: {kind} without session_id/call_id", seq)
            if kind == "decision" and isinstance(payload, dict) and payload.get("decision") not in ("approve", "deny"):
                prob(f"{where}: decision payload has an invalid decision value", seq)
            if kind == "checkpoint":
                n_cp += 1
                ok_cp = isinstance(payload, dict) and set(payload) == {"upto_seq", "head_hash", "mac"}
                if not ok_cp:
                    prob(f"{where}: malformed checkpoint payload", seq)
                    cp_bad = True
                else:
                    if payload["upto_seq"] != seq - 1 or payload["head_hash"] != prev_seen_hash:
                        prob(f"{where}: checkpoint does not cover the event before it", seq)
                        cp_bad = True
                    mac = payload["mac"]
                    if keyed:
                        if not isinstance(mac, str) or not hmac.compare_digest(_mac(key, seq - 1, prev_seen_hash), mac):
                            prob(f"{where}: checkpoint MAC is {'missing' if mac is None else 'invalid'} (forged or key mismatch)", seq)
                            cp_bad = True
                    elif mac is not None:
                        unverified_macs += 1
            prev_seen_hash = h
            last_seq, last_hash = seq, h
    except sqlite3.Error as e:
        prob(f"cannot read events: {e}")
        return _report(problems, extra, bad, n, False, "n/a", keyed, notes)

    # head record
    try:
        row = conn.execute("SELECT seq, hash FROM head WHERE id = 1").fetchone()
    except sqlite3.Error as e:
        row = None
        prob(f"cannot read head record: {e}")
    else:
        if row is None:
            prob("head record is missing")
        elif row[0] != last_seq or row[1] != last_hash:
            prob(f"head record (seq {row[0]}) does not match the last event (seq {last_seq}): events were removed or "
                 f"appended outside the store", (min(row[0], last_seq) + 1) if isinstance(row[0], int) else last_seq)

    # anchor
    anchor = "n/a"
    try:
        lines, anotes = _read_anchor(anchor_path)
    except EventLogError as e:
        lines, anotes = [], []
        prob(str(e))
        anchor = "mismatch"
    notes.extend(anotes)
    if anchor != "mismatch":
        if not lines:
            if n_cp:
                anchor = "missing"
                prob(f"anchor file {anchor_path} is missing or empty but the log has {n_cp} checkpoint(s): it was removed")
        else:
            anchor = "ok"
            for lineno, text in lines:
                parts = text.split(" ")
                if len(parts) != 3 or not parts[0].isascii() or not parts[0].isdigit() or int(parts[0]) < 1 or \
                        not _HEX64.fullmatch(parts[1]) or not (parts[2] == "-" or _HEX64.fullmatch(parts[2])):
                    prob(f"anchor line {lineno}: malformed")
                    anchor = "mismatch"
                    continue
                aseq, ahash, amac = int(parts[0]), parts[1], parts[2]
                if aseq > last_seq:
                    prob(f"anchor line {lineno}: seq {aseq} is not in the log (the log ends at seq {last_seq}: truncated or rolled back)",
                         last_seq + 1)
                    anchor = "mismatch"
                    continue
                try:
                    r = conn.execute("SELECT hash FROM events WHERE seq = ?", (aseq,)).fetchone()
                except sqlite3.Error as e:
                    prob(f"anchor line {lineno}: cannot read event {aseq}: {e}")
                    anchor = "mismatch"
                    continue
                if r is None or r[0] != ahash:
                    prob(f"anchor line {lineno}: head hash of seq {aseq} differs from the anchored one (log rewritten)", aseq)
                    anchor = "mismatch"
                    continue
                if keyed:
                    if amac == "-" or not hmac.compare_digest(_mac(key, aseq, ahash), amac):
                        prob(f"anchor line {lineno}: MAC is {'missing' if amac == '-' else 'invalid'}", aseq)
                        anchor = "mismatch"
    if not keyed:
        notes.append("no key configured: edits, deletes, reorders and inserts are detected, but a truncated tail or a chain "
                     "rebuilt consistently (together with the anchor file) is NOT detectable")
    if unverified_macs:
        notes.append(f"{unverified_macs} checkpoint MAC(s) were not verified (no key given)")
    notes.append("events appended after the last checkpoint can be truncated undetectably")
    return _report(problems, extra, bad, n, not cp_bad, anchor, keyed, notes)


def _report(problems, extra, bad, n, cp_ok, anchor, keyed, notes) -> VerifyReport:
    if extra:
        problems.append(f"... and {extra} more problem(s)")
    return VerifyReport(ok=not problems, n_events=n, first_bad_seq=min(bad) if bad else None, problems=problems,
                        checkpoints_ok=cp_ok, anchor=anchor, keyed=keyed, notes=notes)


def verify_file(path: Any, *, key: "bytes | None" = None, anchor_path: Any = None) -> VerifyReport:
    """Read-only verification of an event log file (never creates or modifies anything).  Raises EventLogError if the file
    cannot be read or is not a sentinel event log."""
    p = _fspath(path, "path")
    ap = _fspath(anchor_path, "anchor_path") if anchor_path is not None else p + ".anchor"
    if not os.path.isfile(p):
        raise EventLogError(f"cannot read {p}: no such file")
    conn = _connect(p, readonly=True)
    try:
        sp = _check_schema(conn, create=False)
        return _verify_conn(conn, key, ap, sp)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------

class EventStore:
    def __init__(self, path, *, key: "bytes | None" = None, anchor_path=None, checkpoint_every: int = 100,
                 checkpoint_seconds: float = 60, max_payload_bytes: int = 65536, clock=time.time):
        self._path = _fspath(path, "path")
        self._anchor_path = _fspath(anchor_path, "anchor_path") if anchor_path is not None else self._path + ".anchor"
        if os.path.abspath(self._anchor_path) == os.path.abspath(self._path):
            raise EventLogError("anchor_path must differ from the database path")
        if key is not None and (not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_LEN):
            raise EventLogError(f"key must be bytes of at least {MIN_KEY_LEN} bytes")
        self._key = bytes(key) if key is not None else None
        for nm, v in (("checkpoint_every", checkpoint_every), ("checkpoint_seconds", checkpoint_seconds),
                      ("max_payload_bytes", max_payload_bytes)):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not v > 0:
                raise EventLogError(f"{nm} must be a positive number")
        self._every = checkpoint_every
        self._seconds = checkpoint_seconds
        self._max_payload = int(max_payload_bytes)
        if not callable(clock):
            raise EventLogError("clock must be callable")
        self._clock = clock
        self._lock = threading.RLock()
        self._conn: "sqlite3.Connection | None" = None
        self._ro = False
        self._closed = False
        self._since_cp = 0
        self._last_cp_time = 0.0

    # ---- lifecycle ----------------------------------------------------------
    @classmethod
    def open_readonly(cls, path, *, key: "bytes | None" = None, anchor_path=None) -> "EventStore":
        """A read-only view (verify / events / recent_resolved ...); never writes, never creates the file."""
        s = cls(path, key=key, anchor_path=anchor_path)
        if not os.path.isfile(s._path):
            raise EventLogError(f"cannot read {s._path}: no such file")
        conn = _connect(s._path, readonly=True)
        try:
            s._schema_problems = _check_schema(conn, create=False)
            conn.execute("PRAGMA query_only = ON")
        except BaseException:
            conn.close()
            raise
        s._conn, s._ro = conn, True
        return s

    _schema_problems: list = []

    def open(self) -> dict:
        with self._lock:
            if self._conn is not None or self._closed:
                raise EventLogError("event log already opened or closed")
            p = self._path
            try:
                if not os.path.exists(p):
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
                    os.close(fd)
            except OSError as e:
                raise EventLogError(f"cannot create {p}: {e}") from None
            conn = _connect(p, readonly=False)
            try:
                try:
                    mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                    conn.execute("PRAGMA synchronous = FULL")
                    sync = conn.execute("PRAGMA synchronous").fetchone()[0]
                    conn.execute("PRAGMA trusted_schema = OFF")
                except sqlite3.Error as e:
                    raise EventLogError(f"cannot configure {p}: {e}") from None
                if str(mode).lower() != "wal" or sync != 2:
                    raise EventLogError(f"cannot enable WAL / synchronous=FULL on {p} (got {mode}, {sync})")
                drift = _check_schema(conn, create=True)
                rep = _verify_conn(conn, self._key, self._anchor_path, drift)
                if not rep.ok:
                    head = "; ".join(rep.problems[:5])
                    raise EventLogError(f"event log {p} does not verify (first bad seq {rep.first_bad_seq}): {head}")
                self._repair_anchor_tail()
            except BaseException:
                conn.close()
                raise
            self._conn = conn
            if self._key is None:
                log.warning("event log %s is UNKEYED: truncation and a rebuilt chain are undetectable (set SENTINEL_LOG_KEY)", p)
            self._since_cp, self._last_cp_time = self._events_since_checkpoint(), float(self._clock())
            self._append_raw("log_open", None, None, {"keyed": self._key is not None, "schema": SCHEMA_VERSION})
            recovered = []
            for u in self._unresolved():
                try:
                    self._append_raw("decision", u["session_id"], u["call_id"],
                                     {"decision": "deny", "reason": "restart", "actor": "system", "rule_id": None,
                                      "policy_digest": None})
                except DuplicateEvent:
                    continue
                recovered.append({"session_id": u["session_id"], "call_id": u["call_id"]})
            self._maybe_checkpoint()
            seq, h = self._head()
            return {"seq": seq, "head": h, "recovered": recovered}

    def close(self) -> None:
        with self._lock:
            if self._conn is None:
                self._closed = True
                return
            try:
                if not self._ro:
                    seq, _ = self._head()
                    last = self._conn.execute("SELECT kind FROM events WHERE seq = ?", (seq,)).fetchone()
                    if seq and not (last and last[0] == "checkpoint"):
                        self._checkpoint()
                    try:
                        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    except sqlite3.Error:
                        pass
            except (EventLogError, sqlite3.Error) as e:
                log.error("event log %s: final checkpoint failed: %s", self._path, e)
            finally:
                try:
                    self._conn.close()
                finally:
                    self._conn = None
                    self._closed = True

    def _require(self) -> sqlite3.Connection:
        if self._conn is None:
            raise EventLogError("event log is not open" if not self._closed else "event log is closed")
        return self._conn

    # ---- writing --------------------------------------------------------------
    def append(self, kind, *, session_id=None, call_id=None, payload=None) -> Event:
        if not isinstance(kind, str) or kind not in KINDS:
            raise ValueError(f"unknown event kind {str(kind)[:40]!r}")
        if kind in _RESERVED:
            raise ValueError(f"kind {kind!r} is written by the store itself")
        sid, cid = _check_id("session_id", session_id), _check_id("call_id", call_id)
        if kind in _NEEDS_CALL and (sid is None or cid is None):
            raise ValueError(f"{kind} requires session_id and call_id")
        body = sanitize_payload(payload, self._max_payload)
        if kind == "decision" and body.get("decision") not in ("approve", "deny"):
            raise ValueError("decision payload needs decision = approve|deny")
        with self._lock:
            conn = self._require()
            if self._ro:
                raise EventLogError("event log is read-only")
            ev = self._append_raw(kind, sid, cid, body)
            self._maybe_checkpoint()
            return ev

    def _head(self) -> tuple:
        row = self._require().execute("SELECT seq, hash FROM head WHERE id = 1").fetchone()
        if row is None:
            raise EventLogError("head record is missing")
        return row[0], row[1]

    def _append_raw(self, kind: str, sid, cid, body: dict) -> Event:
        conn = self._require()
        try:
            ts = float(self._clock())
        except Exception as e:
            raise EventLogError(f"clock failed: {type(e).__name__}") from None
        if not math.isfinite(ts):
            raise EventLogError("clock returned a non-finite time")
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as e:
            raise EventLogError(f"cannot write to the event log: {e}") from None
        try:
            row = conn.execute("SELECT seq, hash FROM head WHERE id = 1").fetchone()
            seq, prev = row[0] + 1, row[1]
            h = compute_hash(prev, seq, ts, sid, cid, kind, body)
            conn.execute("INSERT INTO events(seq, ts, session_id, call_id, kind, payload, prev_hash, hash) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (seq, ts, sid, cid, kind, canonical_json(body), prev, h))
            conn.execute("UPDATE head SET seq = ?, hash = ? WHERE id = 1", (seq, h))
            conn.execute("COMMIT")
        except BaseException as e:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            if isinstance(e, sqlite3.IntegrityError) and "events.call_id" in str(e):
                raise DuplicateEvent(f"{kind} already recorded for session {sid!r} call {cid!r}") from None
            if isinstance(e, sqlite3.Error):
                raise EventLogError(f"cannot write to the event log: {e}") from None
            raise
        if kind != "checkpoint":
            self._since_cp += 1
        return Event(seq, ts, sid, cid, kind, body, prev, h)

    def _maybe_checkpoint(self) -> None:
        if self._since_cp <= 0:
            return
        due = self._since_cp >= self._every
        if not due:
            try:
                due = float(self._clock()) - self._last_cp_time >= self._seconds
            except Exception:
                due = False
        if due:
            try:
                self._checkpoint()
            except EventLogError as e:                       # the triggering event IS durable; retry at the next append
                log.error("event log %s: automatic checkpoint failed: %s", self._path, e)

    def _checkpoint(self) -> Event:
        seq, h = self._head()
        mac = _mac(self._key, seq, h) if self._key is not None else None
        ev = self._append_raw("checkpoint", None, None, {"upto_seq": seq, "head_hash": h, "mac": mac})
        self._since_cp = 0
        try:
            self._last_cp_time = float(self._clock())
        except Exception:
            pass
        self._write_anchor(seq, h, mac)
        return ev

    def _write_anchor(self, seq: int, h: str, mac: "str | None") -> None:
        line = f"{seq} {h} {mac or '-'}\n".encode("ascii")
        try:
            existed = os.path.exists(self._anchor_path)
            fd = os.open(self._anchor_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            if not existed:
                dfd = os.open(os.path.dirname(os.path.abspath(self._anchor_path)) or ".", os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        except OSError as e:
            raise EventLogError(f"cannot write the anchor file {self._anchor_path}: {e}") from None

    def _repair_anchor_tail(self) -> None:
        """Drop a torn (unterminated) last anchor line left by a crash, so the next line starts clean."""
        try:
            with open(self._anchor_path, "rb+") as fh:
                data = fh.read(MAX_ANCHOR_BYTES + 1)
                if data and not data.endswith(b"\n") and len(data) <= MAX_ANCHOR_BYTES:
                    fh.truncate(data.rfind(b"\n") + 1)
                    fh.flush()
                    os.fsync(fh.fileno())
        except FileNotFoundError:
            pass
        except OSError as e:
            raise EventLogError(f"cannot repair the anchor file: {e}") from None

    def _events_since_checkpoint(self) -> int:
        conn = self._require()
        seq, _ = self._head()
        r = conn.execute("SELECT MAX(seq) FROM events WHERE kind = 'checkpoint'").fetchone()[0] or 0
        return max(0, seq - r)

    # ---- reading ---------------------------------------------------------------
    def _unresolved(self) -> list:
        rows = self._require().execute(
            "SELECT p.session_id, p.call_id, p.payload, p.ts FROM events p WHERE p.kind = 'call_proposed' AND NOT EXISTS "
            "(SELECT 1 FROM events d WHERE d.kind = 'decision' AND d.session_id = p.session_id AND d.call_id = p.call_id) "
            "ORDER BY p.seq").fetchall()
        out = []
        for sid, cid, ptext, ts in rows:
            pl = _loads_obj(ptext)
            out.append({"session_id": sid, "call_id": cid, "server": pl.get("server"), "tool": pl.get("tool"), "ts": ts})
        return out

    def unresolved_calls(self) -> list:
        with self._lock:
            try:
                return self._unresolved()
            except sqlite3.Error as e:
                raise EventLogError(f"cannot read the event log: {e}") from None

    def recent_resolved(self, n: int = 50) -> list:
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise ValueError("n must be a non-negative integer")
        n = min(n, 10000)
        with self._lock:
            try:
                rows = self._require().execute(
                    "SELECT d.session_id, d.call_id, d.payload, d.ts, (SELECT p.payload FROM events p WHERE "
                    "p.kind = 'call_proposed' AND p.session_id = d.session_id AND p.call_id = d.call_id) "
                    "FROM events d WHERE d.kind = 'decision' ORDER BY d.seq DESC LIMIT ?", (n,)).fetchall()
            except sqlite3.Error as e:
                raise EventLogError(f"cannot read the event log: {e}") from None
        out = []
        for sid, cid, dtext, ts, ptext in rows:
            d = _loads_obj(dtext)
            p = _loads_obj(ptext) if ptext is not None else {}
            out.append({"session_id": sid, "call_id": cid, "server": p.get("server"), "tool": p.get("tool"),
                        "decision": d.get("decision"), "reason": d.get("reason"), "rule_id": d.get("rule_id"), "ts": ts})
        return out

    def events(self, *, session_id=None, after_seq: int = 0, limit: "int | None" = None) -> Iterator[Event]:
        if session_id is not None and not isinstance(session_id, str):
            raise ValueError("session_id must be a string or None")
        if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
            raise ValueError("after_seq must be a non-negative integer")
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
            raise ValueError("limit must be a non-negative integer or None")
        return self._iter_events(session_id, after_seq, limit)

    def _iter_events(self, session_id, after_seq, limit) -> Iterator[Event]:
        left = limit
        cursor = after_seq
        while left is None or left > 0:
            size = 500 if left is None else min(500, left)
            with self._lock:
                conn = self._require()
                try:
                    if session_id is None:
                        rows = conn.execute("SELECT seq, ts, session_id, call_id, kind, payload, prev_hash, hash FROM events "
                                            "WHERE seq > ? ORDER BY seq LIMIT ?", (cursor, size)).fetchall()
                    else:
                        rows = conn.execute("SELECT seq, ts, session_id, call_id, kind, payload, prev_hash, hash FROM events "
                                            "WHERE session_id = ? AND seq > ? ORDER BY seq LIMIT ?",
                                            (session_id, cursor, size)).fetchall()
                except sqlite3.Error as e:
                    raise EventLogError(f"cannot read the event log: {e}") from None
            if not rows:
                return
            for r in rows:
                yield Event(r[0], r[1], r[2], r[3], r[4], _loads_obj(r[5]), r[6], r[7])
            cursor = rows[-1][0]
            if left is not None:
                left -= len(rows)

    def verify(self) -> VerifyReport:
        with self._lock:
            conn = self._require()
            try:
                drift = _check_schema(conn, create=False)
            except EventLogError as e:
                return VerifyReport(False, 0, None, [f"schema: {e}"], False, "n/a", self._key is not None, [])
            return _verify_conn(conn, self._key, self._anchor_path, drift)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
