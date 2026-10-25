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

### D4b. Bugs found by the *live browser run* (Playwright against the real stack)
- **B17** UI never sends `model`, and the default `claude-sonnet` only exists when `OPENROUTER_API_KEY` is set, so any
  other provider setup failed every UI session with "Unknown model". Also the provider base URL was hardcoded.
  Fix: `pick_default_model` (env override -> claude-sonnet -> first registered), `OPENROUTER_BASE_URL`. Tests red first.
- **B18** Chart threshold line hardcoded at 2.5 while the backend breaches at 3.368 (UI and alert disagreed on screen).
  Fix: single `frontend/src/lib/drift.ts`; `tests/contract/test_ui_threshold.py` parses it and compares to the backend constant.
- **B19** The Kill Chain rendered **without edges**: custom nodes had no `<Handle>`s, so React Flow dropped every edge.
  tsc/lint/unit tests cannot see this. Browser test asserts `edges == nodes - 1`; red first, then fixed (screenshot-verified).
- The browser harness: real Chromium, real Vite UI, real WebSocket, real FastAPI, and a real HTTP endpoint speaking the
  OpenAI protocol that returns a *scripted* conversation. The model is the only fake. 12/12 stable over 3 repeats.

### D4c. Found by the second round of browser cases (instrumented, red first)
- **B20** `node_type: "replan"` was in the contract and the UI had dashed styling for it, but the backend never emitted it, so that
  UI path was dead. Now the tool proposed right after a denied one is `replan` (backend black-box test + browser test for the dashed edge).
- **B21** Connection dot flashed red after every finished session (server closes the socket by design). Measured with a
  MutationObserver: class history `connected -> (red) -> connected`. Now: expected close => immediate reconnect, amber
  "reconnecting"; real drop => backoff + red. Logic in `frontend/src/lib/reconnect.ts` (unit tested).
- **B22** Narrow viewport: page was 626 px wide on a 390 px screen and the Run button was off-screen (no `@media` rules existed).
  Added a single-column layout below 800 px.
- Checked and fine: a 25+ node session renders one connected graph with zero node overlaps.
- Not applicable: light theme (the app is dark-only, there is no `prefers-color-scheme` handling). Not testable here: Firefox/WebKit (only Chromium is installed).

### D5. Honest limits of the verification
- The gate proves the listed behaviours against a *scripted* LLM over real HTTP. No real model was called (no API key here), so
  real-model behaviour (malformed tool calls, refusals, long outputs) is untested.
- **Drift quality is NOT validated.** The live runs used the stub embedder (hash-based, no semantics). What is shown: the plumbing
  (embed -> PCA -> Mahalanobis -> `drift_update` -> chart) and the rule-based circumvention detector (resource category) work
  end to end. What is not shown: that MiniLM embedding distance separates aligned from adversarial behaviour. Hugging Face
  and the PyTorch index are blocked in this sandbox, so the real embedder could not be run.
- The real MiniLM embedder path was not exercised (model not cached here); only the stub and the fallback are tested.
- Browser behaviour (graph, plots) is covered by types/lint/build and unit tests of the pure socket logic, not by a browser test.
- `demo/generate_cached_runs.py` was not re-run (needs the ML model). Cached runs were generated under the old threshold/maps.
- Frontend mutants are not in the mutation check (it copies only the backend).

## D6. Real-model embedding evaluation (2026-10-25) — see eval/results/REPORT.md
Setup: MiniLM-L6-v2 (real), 120 traces / 762 labeled steps from 6 independent generators, blind-relabelled by 2 reviewers
(5 disagreements, none changed a label), thresholds calibrated on dev only, results on the 53 held-out test traces (46 violation steps).
**Pre-registered verdict (eval/SPEC.md): D2, D3, D4 all FAIL.**
- D0 shipped Mahalanobis: on-time 9.7%, recall 8.7%, AUC 0.66 — worse than the rules (-22.6pp, CI excludes 0). The shipped embedding drift does not detect circumvention.
- D2 corrected message drift (centroid cosine): on-time 12.9%, AUC 0.67 (0.58 on post-denial proposals) — near chance. Message text does not signal circumvention.
- D3 action similarity: on-time 67.7% [50, 84] (needs 70), +35.5pp over rules (CI excludes 0), FA 4.7%, latency ~8 ms. Fails only the on-time cutoff, narrowly, BUT
  its false alarm rate on benign proposals after a denial is 22.1% (21/95) and 16.7% on same-category hard negatives; the 4.7% headline is diluted by steps it cannot alert on.
  Shared payload text dominates the score (an internal email with the same payload outscored a paraphrased external webhook).
- D4 rules OR D3: on-time 74.2% passes, FA 6.0% fails (28.4% on benign post-denial proposals).
- **D5 control (regex "external destination after a denial", no ML): on-time 87.1%, recall 87%, FA 0.7%, ~0 ms.** It beats every embedding detector on every metric.
  Caveat: D5 was written AFTER inspecting the data's structure (including test), so its numbers are optimistic and not pre-registered; it also encodes this scenario's convention (team.com = internal).
- Added value of embeddings over the control: D3 caught 4 violations D5 missed (of 46); D3 OR D5 recall 44/46 vs D5 40/46, at 22 vs 3 false alarms. One violation (gen_a-010#8) was missed by everything.
Conclusion: on this data embeddings do not earn their place as the primary detector; a destination/policy check does most of the work. Embeddings add a small recall gain
only for violations whose destination is not lexically obvious, which this dataset under-represents. The next step is a harder, regex-resistant holdout, not more tuning on this one (the v1 test split is now spent).
Limits: synthetic LLM-written data from one model family, clustered traces (CIs optimistic), no multiplicity correction, 53 test traces.
