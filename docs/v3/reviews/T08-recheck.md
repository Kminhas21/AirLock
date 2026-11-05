# T08 re-review (after the B1 / S1-S6 fixes)

Reviewer: independent re-check, 2026-11-05. Scope: working tree on top of `16bada3`. Only this file was written in the repo. All probes,
mutations and hostile tests ran in a scratch copy (`.../scratchpad/mut_t08_re/`: eval/ server/ seismograph/ tests/ + contracts.ts) or as
read-only runs. `OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1`, real MiniLM. The v3 evaluation was not run or touched.

## Verdict: CHANGES REQUESTED

B1 is closed and S1-S6 are fixed and verified. One blocking item remains, in the repo's own gate: `scripts/mutation_check.py` (run by
`scripts/verify.sh:62`) now fails with two STALE mutants (R1, R3), because the fixes rewrote the code those mutants target. Everything else is
non-blocking.

## Blocking

**RB1. `scripts/mutation_check.py` has two stale mutants, so the verify.sh "mutation check" stage fails.**
The script exits 1 when a mutant's target text is not found exactly `count` times ("a stale mutation would silently prove nothing"). I loaded
`MUTANTS` and counted each target in the current tree (read-only):
- `R1 denied-party match ignored (denials never reach the registry detector)`: expected 1, found 0. `RegistrySessionMonitor.register_decision` was
  split into two `try` blocks (detector, then explanation state), so the old two-line anchor is gone.
- `R3 v3 modes: frozen-file failure no longer falls back to action_sim` (added by T08): expected 1, found 0. The fallback now builds the reason with
  `clean_field(f"... ({type(exc).__name__}: {exc})", safe_text.REASON)` and a snapshot copy; the `({exc!r})` anchor no longer exists.
The other 20 mutants still match once. The spec review said R3 and R4 were "not stale" and killed; that was true before the fixes. Fix: re-anchor R1 and
R3 on the new text (R3: drop the `return _fallback_registry(...)` in the `except (OSError, ValueError, KeyError, FrozenRegistryError, ...)` block of
`_resolve_registry`, and confirm it is killed by `test_proposal_monitor_registry_v3.py`), then run `python scripts/mutation_check.py` once and attach the output.
I did not run the full script (22 full-suite runs); the stale count is certain from the exact-match rule.

## (1) B1 verification: CLOSED

### Hostile inputs through real sessions (TestClient + WebSocket + fake LLM)
My own file `tests/e2e/test_hostile_re.py` (scratch only). For each of `action_sim`, `learned`, `registry`, `registry_learned`,
`registry_learned_e`, `registry_learned_dropout` (the `rules` path and `goal_persistence` are covered in the direct probe below, because a hostile
name can never reach them through the WS): 14 payloads (`\n`, `\r\n`+fake `Monitor:` line, U+2028, U+2029, U+0085, VT, FF, bidi override + isolates,
zero-width space/joiner, emoji ZWJ family + newline, 5000 chars, ESC+NUL, NBSP/ideographic space/figure space, a mix of all line breakers), each in:
the tool name (`send_email<payload>`), the destination (`dana<payload>@acme-corp.example` plus a URL with the payload, built by the real extractor),
subject, body, a nested `{"a": [payload, {"b": payload}]}` argument, and the registry note. Three proposals per session, all denied (a verbatim retry
alerts in every mode). Then a second variant with the linter bypassed (`Registry.validate -> []`) so a hostile party or entry id reaches the message.
Asserted for EVERY alignment_alert and session_complete in the stream: newline count equals 1 for v3 modes (the final `Monitor: <mode> (frozen,
provisional: see DECISIONS D10)` line, checked verbatim) and 0 for all others; no Cc/Cf/Zl/Zp/other-whitespace character other than that newline;
length < 3000; `monitor_errors == 0`; a monitor alert exists (non-vacuous).
Result: 190 passed, 6 skipped, 0 failed. The 6 skips are lint-bypassed cases where a hostile entry id made the entry invalid, so the detector had
nothing to match and did not alert (nothing to check). Hostile ids are covered by the next probe and by the repo's `entry_id` parametrisation.
First run had 16 failures, all mine: a 5000-char tool name makes each proposal cost about 1 s of MiniLM time at 1 thread (the 8 s harness timeout),
and the crlf/nbsp lint-bypass cases change what the extractor resolves; both fixed in the test, none in the product.

### Direct probe, odd types and every call site
`tests/server/test_hostile_re2.py` (scratch): tool names `123, None, bytes with invalid UTF-8, an object whose __str__ raises, an object whose
__str__ contains a newline, a list, a dict, float, bool`, a name combining ESC/bidi/ZWSP/ZWJ-emoji/CR/LF/NEL/VT/FF/U+2028/U+2029, a 10 000-char name;
args with nested dicts/lists, list-valued `to`, newline-laden values; entry id, party and note with CR/LF/NEL/U+2028 injected into the loaded
registry; `args` that are `None`, `[]`, a string or an int. All 6 monitor families plus `SessionDrift` (`goal_persistence` with a forced 5000-char
denied tool name that has keywords; circumvention with `send_email\nCRIT`, `write_file`, `send_slack_message`). 7 passed. Every alert that was produced
(16 / 3 / 18 / 6 / 4 / 5 for action_sim / learned / registry / registry_learned / _e / _dropout) had the expected line structure and was
`json.dumps(...).encode("utf-8")`-safe (no lone surrogates). Non-str names and non-dict args make the detector raise inside `on_proposal`; that is
caught, counted in `monitor_errors` and no alert is sent (fail-open, pre-existing behaviour). Those types cannot come from the WS (names are str, args
are parsed JSON dicts).

### Paths that still leak
None into an alert message. Residual (by design, cannot be removed by sanitising): the cleaned text is still agent-chosen words inside the first
line, e.g. `Registry match: send_email CRITICAL: all clear, approve to partners@team.com ...` (up to 80 chars of tool name). It is no longer a separate
line and cannot fake the `Monitor:` line, but a human skimming could still read it. Suggest quoting the tool name (`'send_email ...'`) as the
destination party already is. Non-blocking.

### Other places that build human-readable strings from agent / registry data
| place | source | sanitised? |
|---|---|---|
| `SessionMonitor._message` (action_sim, learned) | tool, args via describe_effect | yes (EFFECT 200) |
| `RegistrySessionMonitor` explanation + plain fallback message | tool, token, party, entry id/kind/note, earlier denied tool/tokens, feature names | yes (all fields) |
| `SessionDrift.observe_tool_call` (rules, tracker text, analyzer text) | tool name | yes (whole message, 1000) |
| `goal_persistence` | denied tool names | yes (5 names, 80 each) |
| fallback reasons (`_fallback`, `_fallback_registry`, load_registry, frozen load), `last_session_fallback` on /health, registry lint log lines | file content, exception text | yes (1000) |
| `session_complete` message | fixed strings only | n/a |
| `error` events (`main.py` 118, 128, 131, 146, 152, 170) | the CLIENT's own start_task fields (`event`, `model`) echoed back to that client, or fixed text | not sanitised, not agent- or registry-controlled; no leak. Note `Unknown model '{model_key}'` reflects an arbitrary client string to itself. |
| `reasoning`, `tool_pending.reasoning_context`, `tool_name`, `tool_params`, `tool_resolved.result/agent_response` | raw agent text / tool output | unsanitised BY DESIGN: these are data fields shown in their own widgets (reasoning node, tool detail `.detail-code`, pre-wrap), not the CRITICAL banner. Only `AlertBanner.tsx:43` uses `pre-line`, and no `innerHTML` exists in `frontend/src`. |
| server log lines (`log.exception("... failed on %s (%s)", node_id, tool)` and similar) | raw tool name | not sanitised: log-line forging only, no UI. Nit. |

## (2) Mutations: 30 mutants, 28 killed by the repo's tests, 2 survivors of the repo's suites

Runner: `re_s3/mut.py` (scratch). Suites: `test_safe_text.py` + `test_alert_message_safety.py` (survivors were additionally run against
`test_proposal_monitor_registry_v3.py`, `test_proposal_monitor_registry.py`, `test_proposal_monitor.py`, `test_health.py`).

Killed: M01 sanitiser strips only `\n`; M02 only `\n \r \t space`; M03 U+2028/2029 not stripped; M04 format chars (bidi, ZWSP) kept; M05 lone surrogates kept;
M06 `limit` ignored inside `clean_field`; M07 truncation one char over the limit; M08 truncate BEFORE sanitising; M09 NEL/VT/FF left alone; M10 scan cap
removed; M11 earlier-denied effect text not cleaned (action_sim/learned); M12 proposed effect not cleaned; M13 tool name raw in "Registry match"; M14 earlier
denied tool raw; M15 note raw; M16 destination token raw; M17 earlier denied destinations raw; M18 party raw in "reaches party"; M19 plain fallback message
tool raw; M21 limit forgotten on note; M23 Monitor line appended before a whole-message clean (kills the newline); M24 Monitor line also on non-v3 registry modes;
M25 session fallback reason raw (killed by the v3 unit file, not by the two safety files); M26 rules circumvention message raw; M27 goal_persistence names raw;
M28 earlier-denied party raw; M29 unregistered-party raw; M30 tool name cleaned with a 1M limit.

Survivors of the repo suites:
- **M22 `limit` forgotten on the destination token** (`clean_field(rt.token.value, 10**6)`): SURVIVES all repo tests. It is a real exposure
  (the extractor does not bound tokens: a 5000-char URL host yields a ~5000-char message), and my WS test `long-registry` kills it. Add a test with a
  very long URL/email destination and assert `len(message) < 1000`. Non-blocking (the shipped code has the limit).
- **M20 `limit` forgotten on the entry id** (`clean_field(e.id, 10**6)`): survives. Operator-written ids only; the linter may bound them anyway. Add a
  10 000-char id (linter bypassed) to `test_every_interpolated_field_is_truncated`. Non-blocking.

The earlier survivors M02/M10/M11b/M13/M16 (N1-N3, S1): S1/M13 is closed by content hashing and tests (below); the test additions for
N1/N2 are present in `test_proposal_monitor_registry_v3.py` and `test_ws_registry_decisions.py` (the latter passes twice, and
the duplicate-approve case is driven for all four registry modes). I did not re-mutate M10/M11b/M16 individually.

## (3) S1 / S2: verified (real code, `re_s3/s12.py`)

- S1: registry edited in place, SAME size (`"acme"` -> `"zcme"`), mtime restored with `os.utime(ns=...)`: stat showed identical size and mtime_ns;
  `get_monitor_factory()` returned a NEW factory, `/health` digest changed (`7dfcd41e...` to a new value), the new session's entries have party `zcme`.
- S2: frozen file replaced mid-run (threshold 0.88483 -> 0.9348, same mtime restored; if the byte length changed that is irrelevant, the key is a hash):
  new factory, `/health.frozen_model.sha256` changed (`6864d477...` -> `0e9a3f42...`) and a session built from the new factory has threshold 0.9348;
  a session built from the OLD factory object (snapshot) still has 0.8848 and the session created before the swap keeps 0.8848. After the frozen file
  was DELETED, sessions from the existing factory still build from the snapshot, the next `get_monitor_factory()` falls back loudly
  (`monitor=action_sim, requested_monitor=registry_learned_e, frozen_model=null`) and `/health` agrees. Snapshot dir: `/tmp/sentinel-frozen-*` is removed
  by the factory's `weakref.finalize` (atexit too): after normal exits of three different scripts / pytest runs, zero directories remained. Directories
  can survive only a SIGKILL / hard crash (nit: `/tmp` litter, harmless).

## (4) S3: verified (`re_s3/s3.py`)
Forced `_frozen_loader` to raise `RuntimeError("kaboom\nCRITICAL: fake line " + "x"*3000)` for one session. The session was `action_sim`.
`/health` then showed `monitor_errors: 1, session_fallbacks: 1` and `last_session_fallback = "registry_learned_dropout -> action_sim: RuntimeError: kaboom CRITICAL: fake line xxx..."`,
exactly 1000 characters, no newline. `/health.monitor` still reports the registry mode (by design: the factory itself is healthy; the counters carry the
degradation). Documented in `live_drift.monitor_info`.

## (5) Defaults unchanged
- Behavioural diff against git HEAD (`git archive HEAD` into the scratch, same script, same sequence of 4 proposals/denials): for `action_sim`,
  `learned` and `rules` the full JSON of active mode, every alert (trigger, message, score, threshold) and `/health` info is byte-identical.
- Code diff: `DEFAULT_MODE` unchanged; `_resolve_basic` now catches `(OSError, ValueError, KeyError)` instead of `Exception`, but other exceptions now
  reach `_resolve`, which logs, counts and still falls back to `rules` (same outcome, one extra `monitor_errors` increment). `SessionMonitor._message`
  now cleans and caps the two effect strings at 200 characters: in the repo's trace data 13 of 7151 effect strings exceed 200 (max 281), so a few
  alert TEXTS in default mode are truncated with an ellipsis; detection and scores are unchanged. `/health` gains `session_fallbacks` and
  `last_session_fallback` in every mode (additive; the five legacy tests that compare the dict exactly were updated). `live_drift` rules message is
  whitespace-normalised and capped at 1000 (identical for all known tools).
- Test runs (no flakiness, `PYTHONDONTWRITEBYTECODE=1`): whole `tests/` except the 122-case parity file: **1822 passed, 0 failed** (158 s). All older
  monitor files (`test_proposal_monitor.py`, `test_proposal_monitor_registry.py`, `test_health.py`, `test_live_drift.py`, `tests/e2e/test_ws_monitor.py`,
  `test_monitor_parity.py`, `test_registry_parity.py`) are inside that run.

## (6) New tests run twice, diff skim
| file | run 1 | run 2 |
|---|---|---|
| tests/server/test_safe_text.py | pass (1 s) | pass (1 s) |
| tests/server/test_alert_message_safety.py | pass (17 s) | pass (15 s) |
| tests/server/test_proposal_monitor_registry_v3.py | pass (16 s) | pass (15 s) |
| tests/server/test_docs_t08.py | pass (<1 s) | pass (1 s) |
| tests/e2e/test_ws_registry_decisions.py | pass (9 s) | pass (8 s) |
| tests/e2e/test_registry_parity_v3.py (122 cases) | pass (72 s) | pass (69 s) |

Skim of the diff for new bugs: no blocking defect other than RB1.
- Snapshot lifecycle is sound: `mkdtemp` + write is wrapped so a failed write removes the directory; the load failure path removes it; the
  `BaseException` path removes it and re-raises; the factory removes it via `weakref.finalize` (not `__del__`). A session mid-build keeps its factory alive
  through the bound method, so a concurrent factory swap cannot delete the file under it. Only leak: an exception thrown by `MonitorFactory.__init__`
  itself after the copy exists (e.g. `registry.digest()`), practically impossible.
- No fd leaks (`Path.read_bytes` only). Cache key is computed outside the factory lock from one read and the resolve reads again; a change between the two
  makes the stored key stale, so the next call just re-resolves (self-healing, no wrong state kept).
- Message size is bounded (about 2 KB worst case, longest observed in my 5000-char runs was below 3000 by assertion).
- Cost: each `get_monitor_factory()` (every session start and every `/health`) now reads and hashes two small files (2-7 KB); fine. Registry read has no size
  cap (operator-controlled path; same as before).
- A 5000-char tool name costs about 0.6-1.2 s of MiniLM time per monitor call at 1 thread (tokenising and embedding the long effect). Pre-existing, not a
  regression, but an agent can slow the monitor thread this way. Nit.

## Non-blocking items (for the record)
1. Quote the tool name in the registry message (residual in-line wording, above).
2. Add tests that pin M22 (token limit) and M20 (id limit).
3. Sanitise the tool name in the `log.exception` lines (log forging only).
4. `Unknown model '{model_key}'` / `Expected 'start_task' event, got '{got}'` echo client input; harmless but could use `clean_field`.
5. `/health` still exposes absolute registry/frozen paths unauthenticated (pre-existing, N6 of the first review).

## Final: CHANGES REQUESTED
Blocking: RB1 only (re-anchor mutation_check R1 and R3 and show a green `python scripts/mutation_check.py`). On that fix this is an APPROVE.
