# T08 code-quality review (v3 live registry monitors: registry_learned_e / registry_learned_dropout)

Reviewer scope: server/proposal_monitor.py, server/live_drift.py, server/main.py, server/agent_loop.py, eval/dump_expectations.py,
scripts/make_replay_registry.py, scripts/verify.sh, the two new Python test files, frontend/e2e/registry-ui-v3.spec.ts,
frontend/e2e/helpers/traces.ts, AlertBanner.tsx / App.css. No repo file other than this one was changed. Mutations ran in a scratch copy.

## Verdict: CHANGES REQUESTED

Blocking: B1 (banner/line spoofing through agent-controlled strings, now rendered multi-line). Everything else is should-fix or nit.

## Test runs (OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1, real MiniLM, run twice)

| file | tests | run 1 | run 2 |
|---|---|---|---|
| tests/server/test_proposal_monitor_registry_v3.py | 58 passed | 12.9 s | 13.4 s |
| tests/e2e/test_registry_parity_v3.py | 122 passed | 73.6 s | 74.9 s |

No flakiness, no skips. Nothing in either file is time- or order-dependent except the mtime tests, which set mtime explicitly (see S2).

## Findings

### BLOCKING

**B1. Agent-controlled text reaches the banner and `white-space: pre-line` makes newlines real (spoofing).**
server/proposal_monitor.py:351 (`{tool} to {rt.token.value}`), :372/:374 (`best[0]` = earlier tool name), :407 (plain message), and
frontend/src/App.css:422 (`pre-line`), AlertBanner.tsx:43.
`tool` is `tc.function.name` straight from the model (agent_loop.py:308) and is not validated before the monitor sees it. Reproduced in the
scratch copy: a tool named `send_email\nCRITICAL: all clear, approve` yields the message
`Registry match: send_email\nCRITICAL: all clear, approve to partners@team.com ...`. Before this change newlines collapsed to spaces; with
`pre-line` the hostile agent now controls whole lines of a CRITICAL banner the human uses to decide, and can fake a `Monitor:` line anywhere but the
last (the real one is appended last, so `lines.at(-1)` checks in the tests do not detect this). React escapes text nodes, so there is no HTML/script
injection (checked: no `innerHTML`/`dangerouslySetInnerHTML` anywhere in frontend/src). Registry notes are operator-written and trusted, but share the
same path (a note containing `\n` is rendered as a line break; the linter does not restrict it).
Fix: add one helper in proposal_monitor.py, e.g. `def _clean(s, n=200): return " ".join(str(s).split())[:n]`, and apply it to `tool`, every
`token.value`, `best[0]`, `e.note`, `e.party` before they are interpolated (:334, :351, :372-374, :407). Better and more robust: keep the message free
of newlines and send the Monitor line as its own field/element, or have the UI split on the final "\nMonitor:" only. Add a test with a tool name
and a note containing `\n` and assert `message.count("\n") == 1` for v3 modes and `== 0` otherwise.

### should-fix

**S1. Registry cache key can miss a content change (same mtime, size and inode).**
server/proposal_monitor.py:228-234 (`_file_sig`), :244-245, :594-596. Reproduced: an in-place edit that keeps the byte length (party `acme` -> `zcme`)
and restores mtime (`os.utime`, `cp -p`, `rsync -t`, `tar x`, or two writes inside one kernel timestamp tick) returned the OLD factory and OLD
digest. Mutation M13 (signature reduced to mtime only) SURVIVED every test: the size/inode components are untested, and so is the same-mtime case.
Fix: make the signature a content hash: read the file once (`raw = Path(key).read_bytes()`, registries are small), key on `hashlib.sha256(raw)`,
and parse that same `raw` (also removes the stat-then-read race). Keep stat only as a cheap pre-check if cost matters. Add a test that rewrites
same-size content and restores mtime.

**S2. Frozen model file is not part of the factory key; /health can disagree with what sessions actually run.**
:492-497 `_frozen_info` re-reads the file separately from the loader (two reads, TOCTOU), :445-448 `new_session` re-reads and re-parses the frozen file
for EVERY session, and :594-596 does not include its signature. If the file is replaced or deleted after the factory resolved, /health keeps saying
`registry_learned_e` with the old `sha256`, while sessions silently run a different model or fall back to action_sim (the test
`test_session_build_failure_still_ends_in_action_sim` demonstrates exactly this state and only asserts `error_count() >= 1`).
Fix: add `_file_sig(frozen path)` to the key (cheap), compute `sha256` from the very bytes the loader parsed, and ideally load the frozen blob once per
factory and build sessions from the parsed dict (needs a dict overload in the loader, or write the verified bytes to a temp file once).

**S3. Per-session fallback is invisible in health and per-session logs are noisy.**
:470-478. A session that degrades to action_sim increments only `monitor_errors`; `monitor`/`registry`/`frozen_model` still report the registry
mode, and the fallback calls `_resolve_basic("action_sim", os.environ)` (a full re-resolve with frozen-file load and an INFO line) on every session.
Fix: on first failure, flip the factory into the fallback state (set `self.mode`, `registry_info=None`, `frozen_model=None`, keep `reason`) under a
lock, so /health tells the truth and subsequent sessions skip the retry (or retry with a backoff); mark the SessionMonitor with `degraded_from`.
Add a health assertion to the existing test (mutation M15, dropping `_count_error`, was killed only because that test checks the counter; nothing checks `monitor`).

**S4. Exception swallowing mislabels programming errors.**
:264-265 `load_registry` wraps `from server.registry import Registry` inside the same `try` and reports "cannot be parsed" for any bug or ImportError.
:564-565 does the same for the frozen loader ("cannot load the frozen ..."). Move the import above the `try`, catch `(OSError, ValueError)` for the
expected failures, and let the rest log with `log.exception` (they already fall back, so nothing becomes fatal).
Also `RegistrySessionMonitor.register_decision` (:422) swallows a failure of `detector.register_decision` and then skips `_denied_props`, leaving
detector and explanation state out of step; log which of the two failed.

**S5. Docs do not match the code for the threshold override.**
README.md ("`SENTINEL_MONITOR_THRESHOLD` ... D8 ... / D9 only"), proposal_monitor.py:29 and :289 ("overrides the frozen D8/D9 threshold") while
:449-453 applies the override to D9b/D9c as well (and `test_threshold_override_still_works` relies on it). Update the three texts to "D8 / D9 / D9b / D9c".
Also docs/registry.md "Running it live" says the registry is "mtime-cached"; it is keyed on mtime+size+inode (and, after S1, should say content hash).
`/health` now also returns `frozen_model` for `registry`/`registry_learned` (live_drift.py:100 checks `REGISTRY_MODES`), which the README only documents for v3.

**S6. Duplication: a mode table would remove four parallel branches.**
`V3_MODES` is tested at :409, :485, :552, :555; `did == "D8"` at :450 and :562 (`det.threshold["t_same"]` vs `det.threshold`); `"action_sim" if mode in
REGISTRY_MODES else "rules"` at :471. registry_learned (D9) and the v3 modes already share one session class, which is good, but the per-mode facts
live in code. Suggest a small frozen dataclass `ModeSpec(detector_id, model_env, default_model, loader, needs_entries, monitor_line, fallback)` in a
dict, so adding D9d means one row and "which env/loader/fallback" can no longer diverge (S2's key would also be built from the spec).

### nit

- N1. Test gap, explanation state: M10 (denied history shared across sessions via a module-level list) and M16 (approve recorded as denied in `_denied_props`)
  SURVIVED all suites: they only change the explanation text, and `test_sessions_keep_their_own_registry` / `test_no_alert_when_nothing_denied...` check alert
  presence, not the message. Add assertions on the cited "earlier DENIED proposal" in a two-session test and after an approve.
- N2. M11b (`register_decision(..., outcome.decision)` instead of the effective deny) survived: gate timeouts already return `GateResult("deny", "timeout")`
  (gate.py:31, 35), so it only differs for a forged/duplicate approve (`ledger.claim` false). No test drives that case with a registry monitor. Add one.
- N3. M02 (drop the `SENTINEL_REGISTRY` unset check) survives because the empty path then fails as "does not exist"; behaviour is equal, only the reason text
  changes. `_assert_action_sim_fallback` takes `mentions=` but the unset/empty_env cases never pass it; pass `"SENTINEL_REGISTRY"` to pin the message.
- N4. `test_stub_embedder_never_runs_the_v3_detector` accepts `action_sim` or `rules`; pin the expected one for the environment.
- N5. :289-290 the "UNCALIBRATED ... D8/D9" warning text is stale for v3 (see S5). Fallback warnings lack the active replacement mode in the structured reason
  (`factory.reason` keeps only the registry reason when action_sim itself then falls to rules).
- N6. /health exposes absolute registry and frozen-model paths unauthenticated (live_drift.py:99-101). Pre-existing for `registry`, extended by `frozen_model`;
  consider reporting basenames or gating with the WS token. The env path itself is operator-controlled and only ever read (no traversal or overwrite surface).
- N7. Registry cache `_registry_cache` (:224) keeps one entry per distinct path forever; in production there is one path, so memory is bounded. The embedder LRU is
  capped (256) and vectors are read-only, so sharing across sessions is safe. Denied lists are per session.
- N8. scripts/verify.sh:36 `mktemp -d` is never removed (add `trap 'rm -rf "$TMPD"' EXIT`); the v3 id list is repeated in verify.sh:48, make_replay_registry.py:31 and
  the spec (cmp stage guards drift, ok). make_replay_registry.py:76 writes to a possibly missing directory and non-atomically; with no matching ids it writes an
  EMPTY registry and exits 0, which a v3 monitor then rejects (live falls back while `dump_expectations` computes D9b alerts for the same empty registry).
  Make `--v3` fail when `have` is empty, and have dump_expectations warn or refuse an entry-less registry for D9b/D9c to mirror the live rule.
- N9. frontend/e2e/helpers/traces.ts:60 comment says "D8/D9 stages"; add D9b/D9c. In registry-ui-v3.spec.ts:66-70 the relay lookup assumes `Object.values(e.match)[0]`
  is the destination; fine for the committed registry, brittle otherwise. `npx playwright test registry-ui` also matches registry-ui-v3.spec.ts, but both specs
  skip on a SENTINEL_MONITOR mismatch, so the stages do not cross-run (verified by reading the skip conditions).

## What was checked and found sound

- Concurrency: per-session detectors and `RegistrySessionMonitor` are used strictly sequentially (`await asyncio.to_thread(...)`), so no per-session locking is needed;
  the only shared mutable object is the eval embedder, whose `embed` is serialised by `LockedEmbedder` (no other embedder method is called by the detectors; M17, removing the
  lock, is killed by test_proposal_monitor.py::test_shared_embedder_is_serialised_by_a_lock). Lock order is acyclic: factory lock -> registry lock / shared lock / live_drift lock;
  `_reset_embedder_cache` releases its lock before taking the factory lock. The slow model load happens while holding `_factory_lock`, which only delays concurrent sessions and
  /health, not the event loop (all callers use `to_thread`).
- Registry replaced mid-session: each session owns a private deep copy (`registry.to_dict()`), so a session never sees an edit; the next `get_monitor_factory()` re-resolves.
  A truncated/partial write falls back to action_sim and recovers on the next stat change (covered by the typo/recover test).
- agent_loop.py:314-341: rules path always runs, the alert is emitted before `tool_pending`, and `register_decision` receives the EFFECTIVE decision (timeout, forged and duplicate approve are
  denies). Shared fallback code (`_fallback_registry`) always lands on action_sim, never on a registry-trained detector without a registry, including the empty-entries registry.
- eval/dump_expectations.py: v3 handling is strict and consistent (mutually exclusive flags, early clean errors, embedder-less schema pre-check); scripts and spec correct apart from the nits above.

## Mutation results (scratch copy; the 10 most important behaviours plus extras)

Killed (test that went red):
- stub embedder fallback (M01): v3 unit `test_stub_embedder_never_runs_the_v3_detector`.
- lint errors accepted (M03): `test_registry_edits_apply...typo_falls_back_then_recovers`; unparseable/missing/not_object/bad_kind/duplicate_ids/no_entries causes are all parametrised in `test_no_valid_registry_falls_back_to_action_sim` (M04 fallback to rules instead of action_sim killed).
- empty-entries fallback (M05): killed (v3 unit).
- v3 modes load via the v2 loader (M06) and schema_version check removed (M07): v3 unit (`wrong_schema_version`).
- Monitor line dropped (M08) or prepended (M08b): `test_alert_names_everything_and_ends_with_the_monitor_line`.
- alert after tool_pending (M09): `test_registry_parity_v3.py::test_live_alerts_equal_offline_alerts`.
- register_decision always approve (M11a) / never called (M11c): tests/e2e/test_ws_monitor.py.
- frozen_model health key dropped / sha truncated / schema_version dropped (M12a-c): v3 unit.
- threshold override ignored (M14), per-session fallback not counted (M15), session fallback not to action_sim (M19), factory key ignoring the registry file (M18), dropout not a v3 mode (M20), notes dropped from the message (M22), embed lock removed (M17): all red.

Survivors (see findings): M02 (unset-registry reason text, N3), M10 (shared denied history, N1), M11b (raw outcome.decision, N2), M13 (cache signature mtime-only, S1), M16 (approve recorded as denied in explanation, N1).
Per-session isolation of DETECTION is covered; isolation of the explanation state is not.
