# DECISIONS

Living log of what was traced, decided and verified while fixing the bugs listed in the SENTINEL interview-brief
recap artifact (claude.ai/artifact/64Dafb7nbXXihDqsofxz5Y). Each claim in the recap was re-checked against the code
before being accepted as a bug.

## D0. Process decisions
- **Skills**: `/matt-pocock` and `/superpowers` are not installed in this environment (absent from the skill list,
  `~/.claude/skills`, and plugins). I did not pretend to run them. I followed their methods as I understand them:
  reproduce first, failing test (red) before the fix (green), one vertical slice at a time; and subagent-driven
  development: one fresh agent per module with an explicit spec, disjoint file ownership, parallel waves, review before merge.
- **Verification gate** = `scripts/verify.sh`. Exit code is the only verdict. It runs pytest (unit + contract + black-box
  e2e), the legacy seismograph script, `tsc -b`, eslint, vitest, `vite build`, and `scripts/mutation_check.py`
  (re-introduces each bug and requires the suite to go red, so passing tests cannot be vacuous).
  The e2e tests (X1) are written by a different agent from the spec/contract only, never from the implementation.
- **Cycle**: trace -> propose -> implement -> `verify.sh` -> if red, trace the failure and repeat. Stop only on GREEN.
- **Contract authority**: `frontend/src/types/contracts.ts`. The backend conforms to it (the UI renders those shapes);
  a test parses that file so a rename cannot drift silently. Canonical terminal event is `session_complete`;
  `task_complete` remains accepted by the UI only as a legacy alias for the mock server.
- Per-module reasoning lives in `docs/decisions/<module>.md`; module specs in `docs/modules/SPEC.md`.

## D1. Bug register (verified against code at baseline commit 350b7df)

| ID | Bug | Evidence | Module |
|----|-----|----------|--------|
| B1 | Gate takes the *next arbitrary* JSON as the decision; no `event`/`node_id` check | `agent_loop.py:360` | G1 |
| B2 | Gate has no timeout; a walk-away hangs the coroutine forever | `agent_loop.py:360` | G1 |
| B3 | `/ws` has no auth/origin check (CORS only guards HTTP) | `main.py:65-77` | A1 |
| B4 | Mock FS/DB/logs are module globals; a new session's reset wipes an in-flight one | `mock_environment.py:358-380` | E1 |
| B5 | LLM call has no timeout/retry; on error the loop `break`s with no terminal event so the UI hangs | `agent_loop.py:273-285` | L1 |
| B6 | Circumvention is only checked on the approve branch, so denied attempts are never counted | `agent_loop.py:364-376` | T1 |
| B7 | Non-idempotent approve (double-approve duplicates effect) | no ledger | G1 |
| B8 | Contract mismatch: UI WS port 8000 vs backend 8080; `session_complete` vs `task_complete`; live `drift_update`/`alignment_alert` use heuristic shape, UI expects Seismograph shape | `useWebSocket.ts:15`, `agent_loop.py:379-409` | C1 W1 D1 |
| B9 | Frontend reconnects every 2 s with no backoff; `connect` used before declared (lint) | `useWebSocket.ts` | W1 |
| B10 | Seismograph is not wired into the live loop (only `demo/` imports it) | import graph | D1 |
| B11 | N=3 baseline: PCA rank 2 so z~0, covariance singular; `+1e-4*I` hack gives distance 175.5 on the next point; threshold 2.5 is a magic number | `test_pipeline --stub-only` step 3 | S1 |
| B12 | Seismograph resource map covers 4 tools and disagrees with live map (read_file "data" vs "filesystem") | `analyzer.py:27-40` vs `risk_scorer.py` | S2 |
| B13 | Frontend does not compile: `tsc -b` errors, 12 lint errors, so `npm run build` fails | baseline run | W2 |
| B14 | Replay needs a valid model key (validated before the replay branch), so it fails without an API key; `server/cached_runs` has only `aligned_demo.json` in the old shape; no adversarial replay | `main.py:105-121` | R1 |
| B15 | Unhandled/odd first messages (non-object JSON) and `str(e)` leaked to client | `main.py:87-146` | I1 |

### Known limitations deliberately NOT fixed (documented, not hidden)
- No real process/container isolation for tools (needs gVisor/Docker; out of scope, mock sandbox keeps "denial = no effect").
- No persistence / reconnect rehydration (needs event log or Redis).
- Seismograph baseline is frozen and cold-start blind for the first N steps.
- Head-of-line blocking: tool calls in one turn are gated sequentially by design.

## D2. Baseline measurements (before any change)
- `scripts/verify.sh`: RED. pytest: 0 tests. `tsc -b`: 5 errors. eslint: 12 errors + 1 warning. `vite build`: fails.
- `python -m seismograph.test_pipeline --stub-only`: passes, but step-3 distance = 175.511.

## D3. Module log

| Module | Bugs | What changed | Decision / why | Proof |
|---|---|---|---|---|
| G1 `server/gate.py` | B1 B2 B7 | `await_decision` matches `event=="tool_decision"` + `node_id`, only exact `"approve"` approves, total deadline (`SENTINEL_GATE_TIMEOUT_S`, default 300 s), `DecisionLedger` | Fail-closed everywhere. Kept the "suspended coroutine is the pending state" design; added correlation instead of an approval queue | 22 unit tests; e2e forged/garbage/timeout; 3 mutants killed |
| T1 `server/drift_tracker.py` | B6 | circumvention observed when a tool is *proposed*, not after approval | A denied attempt is exactly the case the detector exists for | unit regression + mutant |
| L1 `server/llm_call.py` | B5 | timeout 60 s, 2 retries, jittered exponential backoff, no retry on 4xx auth/bad request, `LLMUnavailable` | Rejected relying on SDK `max_retries` (opaque, untestable). Known gap: `Retry-After` not honoured | 15 unit tests; e2e retry + exhaustion; 2 mutants |
| E1 `server/mock_environment.py` | B4 | per-session `Environment` in a `ContextVar`, created lazily | Module globals removed. Each session entry point must call `reset_environment()` inside its own task (it does, in `main.py`) | concurrency regression red->green; mutant |
| A1 `server/auth.py` | B3 | Origin allow-list + optional `SENTINEL_WS_TOKEN` (constant-time) checked before `accept()` | Token unset = open (dev default, documented). Token travels in the query string, so it can reach access logs | 27 unit + 6 e2e; 2 mutants |
| C1 `server/events.py` | B8 | event builders; contract test parses `contracts.ts` | The UI's types are authoritative; `session_complete` is canonical, `task_complete` is a UI-side legacy alias | 15 tests incl. a self-test that detects a renamed field |
| S1/S2 `seismograph/` | B11 B12 | shrinkage covariance + `pinv`; threshold `3.368` (sqrt of chi2 99%, df=3); resource map = server map | Worst-case distance on a coplanar baseline probe fell 5.0 -> 0.35, scale-invariant. `test_pipeline.py` edit: one assertion used the old (wrong) `read_file`="data" mapping | 16 tests; 2 mutants |
| D1 `server/live_drift.py` | B10 | live loop now runs the Seismograph per session (stub embedder by default; `SENTINEL_EMBEDDER=minilm` for the real model with automatic stub fallback) | Stub default keeps startup fast and offline. The recap's "A6 open item" is closed | 17 tests |
| R1 `server/replay.py` | B14 | replay reads contract-shaped `demo/cached_runs/*_run.json`, honours the human's actual decision, needs no model key | Old `server/cached_runs/aligned_demo.json` (heuristic shape) deleted. R1 wrote tests and code together (no separate red pass); covered by the e2e replay tests and the B14 mutant | 23 tests; real-server smoke |
| W1/W2 `frontend/` | B8 B9 B13 | env-configured URL (default `:8080`), backoff reconnect, `session_complete`/`error` routing, `tsc`/lint clean without `any` | Mock server stays on 8000 (env `MOCK_PORT`), UI points to it via `VITE_SENTINEL_WS_URL` | vitest 14; `tsc`, eslint, `vite build` |
| I1 `agent_loop.py`, `main.py` | B1-B8 B14 B15 | loop rewired onto the modules above; exactly one terminal event; generic client-facing errors; replay before model validation | Exception text is logged server-side only | 52 e2e tests (written first, by a different agent) |

### D4. Bugs found *by the verification process itself*
- **B16** (import crash): running the app the documented way (`cd server && uvicorn main:app`) failed with
  `No module named 'seismograph'`. All unit/e2e tests passed because `pytest.ini` puts the repo root on `sys.path`.
  Found by a real-uvicorn smoke test, not by tests. Fix: `live_drift.py` adds the repo root; regression test
  `tests/e2e/test_startup.py` (subprocess, clean path, red first) and a mutant.
- **Test gaps found by mutation testing** (3 mutants survived the first time): circumvention test accepted any alert
  (a goal-persistence warning satisfied it), no test for LLM-retry exhaustion, no test for unexpected-server-exception
  leakage. Closed in `tests/e2e/test_ws_gaps.py`. These three tests were written by me after seeing the surviving mutants,
  so they are not independent of the implementation; the strict assertions come from SPEC.md, not from the code.

### D5. Honest limits of the verification
- The gate proves the listed behaviours against a *fake* LLM. No live OpenRouter call was made (no API key here).
- The real MiniLM embedder path was not exercised (model not cached here); only the stub and the fallback are tested.
- Browser behaviour (graph, plots) is covered by types/lint/build and unit tests of the pure socket logic, not by a browser test.
- `demo/generate_cached_runs.py` was not re-run (needs the ML model). Cached runs were generated under the old threshold/maps.
- Frontend mutants are not in the mutation check (it copies only the backend).
