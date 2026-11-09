# Plan: durable, tamper-evident event log (GitHub issue #4), first iteration

Goal: an append-only, hash-chained SQLite log of everything the approval hub does, written BEFORE the effect, so a restart loses nothing, every call has exactly
one terminal record, history survives reconnects, and tampering is detectable. Fail closed: if the log cannot be written, held calls are denied (`log_unavailable`).

## Decisions (defaults for the issue's open questions; change here before building if you disagree)
- Storage: **SQLite**, WAL mode, `synchronous=FULL`, one writer (a lock); behind a small `EventStore` class so Postgres can follow. OFF unless `SENTINEL_EVENT_LOG=/path/events.db` is set.
- Tamper evidence: SHA-256 hash chain + **HMAC checkpoints** (key `SENTINEL_LOG_KEY`, >=16 chars) + an **anchor file** (`<db>.anchor`, append-only lines `seq head_hash mac`, path
  overridable with `SENTINEL_LOG_ANCHOR`) written at every checkpoint. Honest threat model: detects edit / delete / reorder / insert / truncation by someone who can modify the DB file
  but does not hold the key. It does NOT protect against someone holding the key and the disk, nor against truncation of the tail after the last checkpoint (checkpoint every 100 events or
  60 s, and on clean close). Without a key the chain still detects edits, deletes, reorders and inserts, but a truncation (or a rebuilt chain) is undetectable; `verify` says so and `open` logs a WARNING.
- Restart behaviour for pending calls: the proxy denies its in-flight calls when the backend connection drops, so re-presenting them would be wrong. On start, every `call_proposed` without a
  `decision` gets a `decision` (deny, reason `restart`, actor `system`) so the audit invariant "every proposed call has exactly one decision" holds. The Inbox snapshot after a restart shows recent history from the log.
- Privacy: before storage, values under secret-looking keys (case-insensitive substring match on `password passwd secret token apikey api_key authorization cookie credential private_key access_key`) become
  `"[REDACTED]"` (recursively); strings are cut at 8,192 chars with a marker; a payload over 64 KB becomes `{"_truncated": true, "_orig_bytes": N, "_orig_sha256": "..."}`. The hash chain covers the STORED (redacted) form.
- No deletion (append-only). Retention is by rotation: `eventlog_cli rotate` archives the whole log and starts a new one (see docs/eventlog.md).

## Schema
`events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session_id TEXT, call_id TEXT, kind TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)`.
`hash = sha256(prev_hash + "\n" + canonical_json({"seq", "ts", "session_id", "call_id", "kind", "payload"}))`, canonical JSON = sorted keys, separators `(",",":")`, ensure_ascii. Genesis `prev_hash = "0"*64`.
Unique partial indexes give idempotency: one `call_proposed` and one `decision` per (session_id, call_id) => `DuplicateEvent`.
Kinds (closed set, anything else is a `ValueError`): `log_open`, `proxy_hello`, `proxy_close`, `call_proposed`, `decision`, `call_result`, `checkpoint`.
- `proxy_hello` payload: session_id, servers, auto_approve, monitor_mode, policy_digest|null, registry_digest|null, frozen_model_sha256|null.
- `call_proposed`: server, tool, args (redacted), auto, alerts [{severity, trigger, score, threshold, message}], policy {verdict, rule_id, digest}|null.
- `decision`: decision `approve|deny`, reason (`human|auto|policy|timeout|disconnected|cancelled|invalid|duplicate|restart|log_unavailable`), actor (`human|policy|auto|system`), rule_id, policy_digest.
- `call_result`: status `ok|error`, summary. `proxy_close`: reason. `checkpoint`: upto_seq, head_hash, mac|null.

## API (module `server/eventlog.py`; sync, thread-safe; callers use asyncio.to_thread)
```python
class EventLogError(Exception); class DuplicateEvent(EventLogError)
@dataclass(frozen=True) class Event: seq, ts, session_id, call_id, kind, payload, prev_hash, hash
class EventStore:
    def __init__(self, path, *, key: bytes | None = None, anchor_path=None, checkpoint_every=100, checkpoint_seconds=60,
                 max_payload_bytes=65536, clock=time.time)
    def open(self) -> dict                      # creates/opens, verifies the existing chain tail, appends log_open; returns {"seq", "head", "recovered": [call refs resolved as restart]}
    def append(self, kind, *, session_id=None, call_id=None, payload=None) -> Event   # durable on return; raises EventLogError / DuplicateEvent
    def unresolved_calls(self) -> list[dict]    # [{session_id, call_id, server, tool, ts}]
    def recent_resolved(self, n=50) -> list[dict]   # newest first: {session_id, call_id, server, tool, decision, reason, rule_id, ts}
    def events(self, *, session_id=None, after_seq=0, limit=None) -> Iterator[Event]
    def verify(self) -> VerifyReport            # dataclass: ok, n_events, first_bad_seq|None, problems[str], checkpoints_ok, anchor ("ok"|"missing"|"mismatch"|"n/a"), keyed(bool)
    def close(self)                             # final checkpoint
def load_key(env) -> bytes | None               # SENTINEL_LOG_KEY
```
`open()` itself performs the restart recovery (appends `decision` deny/`restart`/actor `system` for each unresolved call) and refuses to open (EventLogError) if the existing chain does not verify.

## Hub integration (server/inbox_hub.py, after EL1)
Env: `SENTINEL_EVENT_LOG` (path), `SENTINEL_LOG_KEY`, `SENTINEL_LOG_ANCHOR`. If set but unusable (cannot open / chain broken): the hub REFUSES every proxy session (`hello_reject` reason `log_unavailable`) and logs ERROR once; never silently run unlogged.
Write-ahead rules (each append runs in a thread; failure => fail closed):
- `proxy_hello` appended before `hello_ack` (failure => reject `log_unavailable`); `proxy_close` best effort.
- `call_proposed` appended after monitor+policy evaluation and BEFORE any `inbox_pending` broadcast or auto/policy reply (failure => `proxy_decision` deny / reason `log_unavailable`, nothing broadcast).
- `decision` appended BEFORE `proxy_decision` is sent and before `inbox_resolved` is broadcast (an approve whose record cannot be written is replaced by deny/`log_unavailable`). Cancels are decisions too (reason `cancelled`, actor `system`).
- `call_result` best effort. Duplicate => already resolved: ignore.
- `inbox_snapshot` gains `recent` (list from `recent_resolved(50)`) shown by the UI as history.
- `/health` detail view: `event_log: {path, events, keyed}`; public view `{events, keyed, ok}`.
Protocol additions: `proxy_decision.reason` may be `log_unavailable`; `inbox_snapshot.recent` (optional list). Proxy: accept `log_unavailable` in its closed set ("Denied by SENTINEL: log_unavailable").

## CLI (server/eventlog_cli.py; `cd server && python -m eventlog_cli ...`)
- `verify <db> [--key-env SENTINEL_LOG_KEY] [--anchor PATH]`: exit 0 ok, 1 tamper/problems (prints the first bad seq and every problem), 2 unreadable.
- `show <db> --session S [--call C]`: a readable timeline (proposed -> alerts -> decision -> result).
- `export <db> --jsonl [--session S]`: one JSON object per event on stdout.
- `policy-test <db> <policy.json> [--registry reg.json] [--session S]`: evaluate the LOGGED proposals with `server/policy.py` and print the same table as `policy_cli test` plus, for logged sessions, how the human actually decided vs what the policy would have done (agreement / would-auto-allow-a-denied-call).

## Tickets
| Id | Area | Files |
|---|---|---|
| EL1 | store library | `server/eventlog.py`, `tests/server/test_eventlog*.py` |
| EL2 | CLI | `server/eventlog_cli.py`, `tests/server/test_eventlog_cli.py` |
| EL3 | hub integration | `server/inbox_hub.py`, `server/main.py`, `server/health_view.py`, tests |
| EL4 | proxy reason + UI history | `sentinel_proxy/`, `frontend/src/**` |
| EL5 | e2e (kill -9, restart, tamper), gate stage, mutants, docs/eventlog.md, DECISIONS D19, issue #4 comment | tests/e2e, scripts, docs |

Non-goals now: Postgres, pruning, signed external transparency log, encryption at rest, multi-writer. (Built since: `eventlog_cli replay`, `rotate`, `verify --previous`.)
