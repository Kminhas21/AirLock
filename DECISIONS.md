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
(appended as modules land; see below)
