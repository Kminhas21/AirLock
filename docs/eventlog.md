# Durable, tamper-evident event log (opt-in)

An append-only, hash-chained SQLite log of everything the approval hub does. Every record is written **before** its effect, so a restart loses nothing, every proposed call
has exactly one decision, and edits to the file are detectable. If the log cannot be written, held calls are denied (`log_unavailable`); a hub whose log is unusable refuses every proxy session.

## Turn it on
```
SENTINEL_EVENT_LOG=/var/lib/sentinel/events.db      # required to enable it
SENTINEL_LOG_KEY=<at least 16 characters>             # HMAC key for checkpoints (strongly recommended)
SENTINEL_LOG_ANCHOR=/var/lib/sentinel/events.anchor   # optional; default <db>.anchor
SENTINEL_LOG_RESULTS=1                                # optional: also store tool-output summaries (scrubbed); default stores status + length only
```
The database file is created with mode 0600. Without `SENTINEL_EVENT_LOG` nothing is logged and nothing changes.

## What is recorded (kinds)
`log_open`, `proxy_hello` (servers, monitor mode, policy / registry digests, frozen-model hash), `call_proposed` (server, tool, redacted args, alerts, policy verdict and rule),
`decision` (approve/deny, reason, actor `human|policy|auto|system`, rule id), `call_result` (status, length), `proxy_close`, `checkpoint`.
Restart: on startup every `call_proposed` without a `decision` gets one (deny, reason `restart`, actor `system`): the proxy already denied those calls when the connection dropped.
The Inbox shows recent history from the log after a restart ("history" badge).

## Privacy
Values under secret-looking keys (`password`, `secret`, `token`, `apikey`, `authorization`, `cookie`, `credential`, `private_key`, `access_key`) are stored as `[REDACTED]`; long strings are cut;
a payload over 64 KB becomes a stub with its size and sha256. Free text that may echo a secret (alert messages, tool output) is scrubbed of that call's secret argument values before it is stored,
and tool output is not stored at all unless `SENTINEL_LOG_RESULTS=1`. Redaction is by key NAME and known VALUE: a secret in a differently-named field or in free text that does not match is stored. Review before logging sensitive systems.

## Tools (`cd server && python -m eventlog_cli ...`)
- `verify <db> [--key-env SENTINEL_LOG_KEY] [--anchor PATH]`: exit 0 ok, 1 tampering or problems (prints the first bad seq and every problem), 2 unreadable.
- `show <db> --session S [--call C]`: readable timeline. `export <db> --jsonl [--session S]`: one JSON object per event.
- `policy-test <db> <policy.json> [--registry reg.json]`: evaluate the LOGGED proposals with a policy and compare with what the human actually decided (including "the policy would have auto-allowed a call the human denied").

## What tamper evidence does and does not give you
Detects edit, delete, reorder and insert (chain), forged checkpoints (HMAC, needs the key), and truncation back past an anchored checkpoint (anchor file). It does **not** protect against: someone holding the key and
the disk; truncation of the tail after the last checkpoint (checkpoints every 100 events / 60 s and at clean shutdown); and, WITHOUT a key, a chain and anchor rebuilt together. Without a key `verify` says so.
A keyed log requires a MAC on every checkpoint, so a key cannot be added to an existing unkeyed log; `open()` refuses a log that does not verify, including a missing anchor.
Limits of v1: append-only (no pruning or rotation yet), SQLite only, replays logged proposals through policies but not through the monitors, single host. See DECISIONS D19.
