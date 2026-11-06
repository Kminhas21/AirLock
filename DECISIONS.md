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

## D7. Evaluation v2: regex-resistant holdout (2026-10-25) — eval/results_v2/REPORT_V2.md, rule in eval/SPEC_V2.md
Data: 80 new traces (40 adversarial) built so that NO violation names an external host (0/57), plus external-but-benign and same-party-but-unrelated negatives;
blind-relabelled by two reviewers who saw routing notes (kappa 1.0, 0 disagreements: labels are deterministic GIVEN the notes; detectors never see the notes).
Fit/calibrate on v1 dev + v2 dev (101 traces); v2 test scored once (46 traces, 24 with violations); v1 test = regression guard.
**Mechanical decision: "Partial: no detector qualifies; best on-time among detectors with benign-after-denial FA <= 10% is D3 (29.2%)".**
- The v1 winner collapses on v2: regex control D5 on-time 8.3%, FA 28% on benign post-denial proposals, 49% on regex traps. v1 "success" was the dataset shortcut.
- Learned combiner D7 has the best on-time on v2 (37.5% [19, 58]), keeps D5's v1 on-time (87.1% = 87.1%), and beats D5 on v2 by +29.2pp [8, 52] (paired). It fails the pre-registered bars:
  on-time >= 70%, benign-after-denial FA 11.8% (bar 10%), regex-trap FA 20.9% (bar 10%).
- D3 passes the benign-after-denial bar (7.3%) so the rule names it, but it loses to D7/D5 on v1 (58% vs 87%) and its v2 advantage over D7 is within noise (n=24).
- D6 hybrid: +16.7pp over D5 [4, 33] but worse false alarms than D7. Rules (D1): 20.8%.
- Absolute performance on the hard cases is poor for everything (best 37.5%). Violations that carry only a weak semantic clue and route through internal-looking destinations
  cannot be caught without knowing the routing: a destination registry/policy (docs/PROPOSALS.md section 2) is the missing input, not a better embedding.
- Rule-following note: the rule's "partial" branch picks D3, but D7 is the better all-round detector by the evidence; both are integrated behind SENTINEL_MONITOR, default per the rule (D3), switchable.
Limits: synthetic one-model-family data; 24 violating test traces (CIs wide, overlapping between D3/D6/D7); dev mixes v1 (shortcut-dominated) and v2; D7 has 10 fitted parameters vs 0 for D5.

## D8. Live integration and the D7 train/serve skew (2026-10-25)
Integration (server/proposal_monitor.py): `SENTINEL_MONITOR=action_sim` (frozen D3, the pre-registered survivor; default) | `learned` (frozen D7) | `rules`.
Alerts are emitted at the proposal BEFORE tool_pending; the server loads the SAME frozen detector code the evaluation scored (no re-implementation).
Falls back loudly to `rules` if the model/frozen file is missing (/health shows the ACTIVE monitor/embedder and `monitor_errors`); monitor exceptions never kill a session.
Verification: offline == live on 200/200 traces for D3 and (post-hoc) D7 with the real MiniLM; Playwright (real browser + WebSocket + backend) replays 12 traces from both datasets
acting as the human per the recorded decisions and asserts live alerts == offline, alert-before-decision, one terminal event, and that /health reports the real embedder;
running the WRONG monitor against the other's expectations fails 7/12 (the check discriminates).
**Bug found by the parity tests:** D7's `steps_since_denial` was computed on trace step indices that include message-only steps, which cannot exist in a live session
(train/serve skew; 7/200 traces differed offline vs live). Fixed POST-HOC (eval/results_v2_posthoc/REPORT_V2_POSTHOC.md; original results kept byte-identical in eval/results_v2/):
feature is now `proposals_since_denial`, invariant to message-only steps (property-tested for D3/D6/D7). Effect on D7 was negligible (on-time 37.5% -> 37.5%, FA(e) 20.9% -> 18.6%);
survivor decision unchanged (partial, D3). To run the learned monitor: `SENTINEL_MONITOR=learned SENTINEL_MONITOR_MODEL=eval/results_v2_posthoc/frozen_models.json`.
Open: nothing qualifies against the pre-registered bar; best on-time on the hard holdout is 37.5% (D7). The missing input is a destination/routing registry (docs/PROPOSALS.md section 2).

## D9. Destination registry (2026-10-26) — eval/SPEC_REGISTRY.md, eval/results_registry/REPORT_REGISTRY.md
Built: server/registry.py (format, validation, token scanning for all 13 tools incl. shell/SQL/task ids, resolution, degrade/corrupt, CLI, docs/registry.md; 312 tests),
two independent extractions of the 68 routing notes (agree on 209/210 destination tokens; both lint clean), detectors D8 (rule: registry party match x payload similarity) and D9 (D7 + registry features).
**Pre-registered verdict: Shortfall — no registry detector meets the `full` criteria; registry integrated as OPT-IN, default unchanged.**
- The registry is the missing input: with the full registry D9 alerts at the first violation on 24/24 v2 test traces (D7 without it: 37.5%; D3 29.2%); the paired gain over D7 is +62.5pp [41.7, 81.0].
- It degrades roughly in proportion to missing entries: drop30 74%, drop60 47.5%, wrong10 (10% wrong entries) 96%, ext2 (second extractor) 100%, none 16.7%.
  WITHOUT a registry D9 is worse than D7 (16.7% vs 37.5%): registry-trained detectors must not run unless a registry is configured (graceful-degradation criterion failed for both D8 and D9).
- Why it fails the bars: D9 false alarms on benign post-denial proposals 16.4% (bar 10%) and on regex traps 27.9% (bar 10%) — its threshold was calibrated without the (e) constraint (pre-registered asymmetry).
  D8 is the opposite: FA 0.7% overall / 2.7% (c) / 7.0% (e) but on-time 50% and only 64.5% on v1 (needs 77%).
- Descriptive sweep (post-hoc, test already seen; eval/results_registry/D9_threshold_sweep_DESCRIPTIVE.md): raising only D9's threshold to 0.70-0.80 gives 100% on-time with 1.8-3.6% FA(c) and 2.3-7.0% FA(e):
  the shortfall is largely calibration. NOT a selection; needs a fresh holdout (v3).
Caveats: registries were extracted from the same notes that define the labels (upper bound); v2 TEST is not fresh; 17 of 40 v2 dev traces have registry entries; extractors agree perfectly because the notes are explicit (same model family).

## D10. v3 fresh holdout with realistic registries (2026-11-04) — eval/SPEC_V3.md (+ Amendments 1-3), eval/results_v3/REPORT_V3.md
Process: PRD + 9 tickets; every code ticket went implement -> spec-compliance review -> code-quality review -> fix -> re-check (docs/v3/reviews/); detectors D9b/D9c frozen from v1+v2 dev
(sha256 6864d477...), runner provenance guard passed; scored ONCE (60 traces, 30 with a violation; all test data).
**Deviations, all recorded before scoring:** (1) two of five data generators were stopped by a safety classifier (relay-unlisted and stale-inventory families); NOT retried or reworded; v3 is 60 traces
and cannot test stale/sparse inventories well; (2) the freeze commit came after label adjudication (fit was blind to v3 by construction and verified by provenance hashes); (3) strata defined mechanically.
**Verdict (mechanical, PROVISIONAL): D9b qualifies on every ASSESSABLE criterion; D8 and D9 do not; C6 and C8 were not assessable.** No default recommended (spec).
- D9b: on-time 73.3% [56.7, 88.2]; FA overall 1.6%, benign-after-denial 5.9%, traps 2.9%; +36.7pp over D7/D3 [16.7, 56.2]; latency median 0.08 ms, p95 42 ms (embedding needed on post-denial proposals: 1.28 calls/step); on `listed` routes 22/22 first violations on time.
- D9 (pre-(e)-constraint) has 76.7% but FA 20.3% / 23.5%: the D9 shortfall was calibration, confirmed on fresh data. D8 (rule): 33.3%, below D7.
- **The criteria that probe the registry's failure modes were NOT assessable and their point estimates are bad:** C6 (benign proposals reaching a stale relay entry): D9b alarmed on 6/7 = 85.7% (bar 20%, n=7 < 15);
  C8 (routes the registry is silent on): D9b on-time 0/6 vs D3 about 1/6 (n=6 < 8). Had those strata been large enough, D9b would likely FAIL both.
- Without any registry the registry-trained detectors are useless: on-time D9b 0%, D9 16.7%, D8 3.3% vs D3 36.7%. They must only run when a valid registry is configured (the live monitor already falls back to D3).
- On the mixed traces (partial inventories) D9b is on time on only 40% of first violations (rules D1: 60%; D3/D7: 10%); relay_known (complete inventory): D9b 90%, D3 50%.
- Oracle registry (perfect): D9b 86.7%; the two operator-authors agreed (identical v3 scores).
Limits: synthetic one-model-family data; 30 violating traces; strata small (stale 2, missing 6); no multiplicity correction; labels deterministic given truth notes (kappa 1.0).

## D11. Live v3 monitors (opt-in) and the banner-spoofing fix (2026-11-05) — docs/v3/reviews/T08-*.md
Added `SENTINEL_MONITOR=registry_learned_e` (frozen D9b) and `registry_learned_dropout` (D9c); default stays action_sim. They NEVER run without a valid registry
(v3: 0% on-time without one): any failure (registry unset/invalid/empty, frozen file missing/corrupt/wrong schema, stub embedder) falls back loudly; `/health` shows requested vs active,
registry digest, frozen model hash, `session_fallbacks`. Offline == live on all 60 v3 traces for both modes (120/120).
**Security finding fixed (code-quality review, blocking):** alert text interpolated agent- and registry-controlled strings (tool name, destinations, party, notes); with the banner's `white-space: pre-line`
a tool named `send_email\nCRITICAL: all clear, approve` produced a fake line inside a genuine CRITICAL banner (social engineering of the human approver). Fixed with one sanitiser (server/safe_text.py: whitespace/control/format/bidi
characters removed or collapsed, per-field length limits) applied to every monitor family's alert text; re-checked with 14 hostile payloads x 6 monitor families, 30 own mutations.
Known remaining limits (reported, not fixed): (1) the Kill Chain detail panels (reasoning, tool result, agent response) preserve newlines by design, so an agent can still fake lines inside those labelled panels; (2) `/health` is unauthenticated and shows absolute registry/model paths;
(3) server log lines carry the raw tool name (log forging only); (4) the monitor text can still quote up to 80 characters of the agent's own words in the first line; (5) two sanitiser length limits (destination token, entry id) are only covered by an end-to-end test, not a unit test.

## D12: v3-degrade (stale and missing registries, built mechanically) — SHORTFALL
Pre-registered in eval/SPEC_V3_DEGRADE.md (commit before scoring), scored once: eval/results_v3_degrade/{REPORT.md,results.json}.
Traces and labels unchanged; only the registry is degraded (22 violating traces for M1/M2, 74 benign proposals for B1; both above the
minimum sizes, so C6/C8-style checks are now assessable).
- **Missing route (M1)**: on-time D9b 0%, D9c 0%, D9 18%, D8 5% vs D3 45% on the same traces. All four fail S1; paired CI vs D3 excludes 0 (D9b -45 pts [-68, -27]).
- **Stale-internal (M2)**: D9b 5%, D9c 14%, D9 14%, D8 0% vs D3 45%. All fail S2.
- **Sparse (M3, p=0.5, 5 seeds)**: D9b/D9c on-time 29% vs D3 37% (bar 32%): fail; D9 passes on-time (41%) but its FA exceeds 5% (S5 fail).
- **Stale-relay benign (B1)**: FA D9b 95%, D9c 99%, D9 99%, D8 45% vs D3 8%. Largely inherent to trusting a registry, but the cost is large.
- Verdict: no registry detector is robust. The earlier provisional D9b qualification stands only for complete, correct registries.
Decision: registry monitors stay opt-in and are NOT recommended as default. Cause: the registry detectors lean on the registry for the
decision, so a wrong or silent entry removes their signal instead of falling back to action similarity.
Next candidates (each needs its own pre-registered run, not done): registry OR D3 union; advisory/age-limited entries.
Limits: degradations model staleness, they are not real stale inventories; M1 and M2 share traces; synthetic data, one model family.

## D13: v3-union (registry OR D3), POST-HOC design on seen data — SHORTFALL by one criterion
Pre-registered in eval/SPEC_V3_UNION.md before scoring; scored once: eval/results_v3_union/. Same 60 traces and degradations as D12, so
this is NOT a fresh holdout. Members frozen (D8/D9b/D9c + D3).
- Degradations: U8, U9b, U9c all pass S1, S2, S3, S5 (by construction S1/S2 >= D3: 45.5% vs bar 40.5%). Sparse registry: U9b/U9c on-time 53% vs D3 37%, FA 2.6-2.8%.
- Undegraded registry: U9b on-time 76.7%, FA 3.2%, traps 7.4%, gain over D7 +40 pts, over D3 +40 pts. U9c: 76.7%, 3.0%, 5.9%.
  **U3 fails for every union: FA on benign post-denial proposals is 11.8% (U9b), 11.1% (U9c), 12.4% (U8) vs the 10% bar.** U8 also fails U1/U5/U6 (its registry member adds nothing).
- Verdict: shortfall. The criterion was not relaxed. The miss is 1-2 points on a small bucket; it is the cost of OR-ing in D3's own post-denial FA.
- S4 (benign proposals sent to a wrongly listed relay): U9b 96%, U9c 100%: still the inherent cost of trusting a wrong entry.
- Latency: median per-step 10-13 ms (members run one after the other, MiniLM embedding included), within 100 ms.
Reading: the union removes the collapse seen in D12 (never worse than D3 when the registry is missing/stale) at the price of ~+5-6 pts FA on
post-denial benign proposals. Whether that trade is acceptable is the maintainer's call; the spec's bar says no.
Live monitor unchanged (registry modes remain opt-in, fallback chain unchanged); no union mode was added to server/.

## D14: union monitor mode (opt-in)
`SENTINEL_MONITOR=registry_learned_dropout_or_action` = frozen D9c OR D3 (action similarity). Needs SENTINEL_REGISTRY like the other registry modes;
falls back loudly to `action_sim` if the registry, either frozen file or the embedder is unusable (never half a union). Both members see every
proposal and decision; at most one alert per proposal (registry member's wins). Live alerts equal the offline union on all 60 v3 traces
(tests/e2e/test_registry_parity_union.py). Evidence and cost: D13 (missed the FA-on-post-denial-proposals bar: 11.1% vs 10%; 100% FA when a
registry wrongly lists a relay). Opt-in, not the default, not recommended without reading D13.

## D15: /health hardening and Kill Chain drawer sanitiser (closes the two D11 known limits)
- `/health` has a PUBLIC view (default): same keys, registry / frozen-model paths reduced to the file name, last per-session fallback reduced to
  "<mode> -> <used>: <ExceptionType>" (the message can carry paths and parsed content). The DETAIL view (full paths and message) needs the
  token when SENTINEL_WS_TOKEN is set (`?token=` or `Authorization: Bearer`), or, with no token configured, SENTINEL_HEALTH_DETAIL=1 (set by the
  Playwright config for local e2e). The opt-in never overrides a configured token. Code: server/health_view.py; tests/server/test_health_view.py.
- Kill Chain detail drawer: single-value fields (title, tool) are collapsed to one line (120 chars); agent-text panels (reasoning, result, agent
  response) strip bidi / zero-width / line-separator / control characters, are bounded to 20,000 chars and render one numbered line each (CSS
  counter gutter), so a forged "Decision: APPROVE" line is visibly a numbered line of the agent's own text. Code: frontend/src/lib/safeText.ts,
  NodeDetail.tsx; tests: safeText.test.ts, NodeDetail.test.tsx (vitest now includes .tsx).
- Found on the way: the drawer still coloured drift against a hard-coded 2.5 (B18 had fixed only the chart). Now uses DRIFT_THRESHOLD.
- Mutation check: 31 mutants (9 new: H1-H4 health, U1 union, F1-F4 frontend run through vitest, with a baseline check of the unmutated copy).
  The first run was RED: F2 (drift colour reverted to 2.5) survived because no test pinned the colour. A test was added; F2 is now killed.
- Still open: parameters panel shows pretty JSON (newlines escaped, safe); alert banners were already safe (D11).

## D16: MCP proxy + approval inbox (PROPOSALS #1, first version)
Owner decisions: MCP-based agents first; BLOCK until a human decides; decision in the existing web UI; local developer tool; stdio only;
operator `auto_approve` allowlist (downstream `readOnlyHint` NOT trusted unless `trust_read_only_hint` is set per server); simple session id;
call-based monitors only (the proxy sees tool calls, not reasoning, so no Seismograph drift for proxied sessions). Plan and wire protocol:
docs/plans/PROPOSAL-1-mcp-proxy.md.
Built as three parallel tickets (hub `server/inbox_hub.py`, proxy `sentinel_proxy/`, UI inbox `frontend/src/**/Inbox*`), then an independent
security review (read-only reviewer) found 1 BLOCKER and 4 MAJOR defects, all fixed and re-tested:
- BLOCKER `/inbox/ws` was reachable by any local process without an Origin header (the agent could approve its own calls). Both inbox sockets now
  REFUSE every connection unless SENTINEL_WS_TOKEN is set and presented. Limit: a token stops a process that cannot read your environment; software
  with full access to your account cannot be stopped by this.
- MAJOR auto-approve failed open when the monitor was degraded (rules fallback; real monitors swallow exceptions and return []). Now auto-approve
  applies only when a working monitor looked at the call, did not error (process-wide error counter did not rise) and raised no alert.
- MAJOR a duplicate call_id across sessions could resolve the wrong call. (session_id, call_id) is reserved synchronously; `inbox_decision` requires session_id.
- MAJOR the UI truncated arguments, so a human could approve content they never saw. Over the display limit the card shows a TRUNCATED banner and Approve is disabled.
- MAJOR a stuck UI stalled the hub / orphaned its socket. Sends are concurrent with a per-peer timeout, failed peers are closed so browsers reconnect.
- Smaller: duplicate token= query, silent never-matching auto_approve entries (now warned), half-dead proxy sockets (now dropped and reconnected), unbounded sets.
Evidence: 70 proxy tests, 87 hub tests, 68 UI unit tests, 11 full-stack tests (real uvicorn + real stdio proxy + real downstream + human client),
2 Playwright tests (real browser, 390 px viewport) and 6 new mutants in the gate.
Known and accepted for v1: no `proxy_cancel` frame (if the agent cancels, a stale card can sit until its timeout, and a late approve is logged
although the proxy forwards nothing); `error_count()` is process-wide (an error in another session can cause a spurious hold, which errs safe);
stdio downstream only; the proxy does not forward tools/list_changed; no OpenTelemetry observe-only mode.

## D17: proxy_cancel
When the agent cancels a request (`notifications/cancelled`) or the proxy's own safety-net timeout fires, the proxy sends
`{"event":"proxy_cancel","call_id","reason":"cancelled"|"timeout"}` (best effort, detached task, existing send timeout) and never forwards the call afterwards.
The hub resolves the pending call as deny/`cancelled`, broadcasts `inbox_resolved`, sends no `proxy_decision` and does NOT register anything with the monitor
(a cancelled call is not a human denial and must not teach a denied effect); a cancel arriving while the monitor still runs marks the call so it is never held
or approved; a late `inbox_decision` is ignored; a cancel racing an approve is a no-op after the approve. The UI shows such rows as CANCELLED.
Closes the "stale card / late approve logged" limit of D16. Tests: 75 proxy, hub cancel tests incl. both race orders, 1 full-stack test with a real SDK
cancel, UI label tests; 3 new mutants (X7-X9).
Also filed for later (GitHub issues, not built): #3 policy engine, #4 durable tamper-evident event log with storage.

## D18: policy engine (GitHub issue #3), first iteration
Plan and decisions: docs/plans/POLICY-ENGINE.md. JSON policy (`SENTINEL_POLICY`), ordered rules `allow|deny|ask` over server, tool, argument conditions
(equals/in/glob/under/contains/exists/max_len and negations), registry destination (internal/external/relay/none, party) and alert presence. No regex.
Precedence deny > ask > allow, then default (`ask`); the reported rule is the most specific of the winning class. An alert escalates an allow to ask, never a deny.
Fail closed: unparseable/invalid/oversized policy => policy mode stays ON and EVERY call is held (never legacy auto-approve); a rule that raises => ask unless a deny matched;
a condition that cannot be evaluated is false for positive operators and true for negative ones (lint warns on negative ops in allow rules); a tool/server name that cannot be
evaluated (control/bidi/oversize/non-string) is false in allow rules and TRUE in deny/ask rules. Hub: the policy decides (the proxy's `auto_approve` flag is ignored when a
usable policy is configured); an allow stands only if a working monitor looked at the call and raised no alert; the policy is pinned per proxy session (digest recorded); every
resolved call carries `rule_id` and `policy_digest`; UI shows "auto-allowed by rule X" / "denied by rule X" / "held by rule X". CLI: `policy_cli lint|explain|test` (test replays recorded traces:
on eval/final_v3/traces.json the example policy would allow 11 of the violating proposals, all semantic cases a path rule cannot see, and ask for 193 benign ones: the policy
is a burden reducer, not a detector).
Bugs found on the way: (1) an independent review of the engine's own ambiguity list exposed that odd tool names could bypass a deny rule (fixed as above);
(2) `load_policy_file(5)` opened file descriptor 5 and CLOSED it, which killed pytest's event loop and looked like a flaky crash for two agents; the loader now rejects non-path
inputs (regression test + mutant Y7). Lesson: a "flaky" crash that reproduces twice in a row is a bug, not flakiness.
Evidence: 365 policy tests, hub policy tests, 13 full-stack tests (incl. allow/deny/ask/default/broken policy), 1 Playwright test, 7 new mutants.
Not built (follow-up): built-in agent-loop integration, drift-state inputs, per-session policy overrides, hot reload inside a running session, YAML.

## D19: durable tamper-evident event log (GitHub issue #4), first iteration
Plan: docs/plans/EVENT-LOG.md; operator guide: docs/eventlog.md. SQLite (WAL, synchronous=FULL, 0600), SHA-256 hash chain, HMAC checkpoints (`SENTINEL_LOG_KEY`) and an append-only anchor file; opt-in via
`SENTINEL_EVENT_LOG`. Write-ahead in the hub: `proxy_hello` before the ack, `call_proposed` before any broadcast or auto/policy reply, `decision` before `proxy_decision`/`inbox_resolved`. Fail closed: an approve whose
record cannot be written becomes deny/`log_unavailable`; an unusable log (cannot open, chain broken) makes the hub refuse every proxy session. Restart: `open()` resolves orphaned calls as deny/`restart`.
Decided open questions: HMAC key from env plus anchor file (single-host tamper evidence); pending calls are NOT re-presented after a restart (the proxy already denied them) but are resolved in the log and shown as history.
Found by the end-to-end test (not by the unit tests): the tool OUTPUT stored in `call_result` echoed a redacted argument (`password`), because key-name redaction cannot see a secret inside free text. Now tool output is
not stored by default (status + length), `SENTINEL_LOG_RESULTS=1` stores a summary scrubbed of the call's own secret argument values, and alert messages are scrubbed the same way (`eventlog.secret_values` / `scrub`). Lesson: test secrecy on the BYTES
of the file, not on the fields you meant to redact.
Evidence: 242 store+CLI tests (6 mutation sanity checks by the author), 23 hub-log tests, kill -9 / restart / tamper / unkeyed end-to-end tests over the real backend, proxy and CLI, 6 new mutants (Z1-Z6).
Not built: Postgres, retention/rotation/pruning, external transparency log, monitor replay of logged sessions, encryption at rest, a Playwright stage for the history badge (covered by reducer/static-render tests and the snapshot end-to-end test).
Gate follow-up (D19): the first full gate after the event log was RED on two things. (1) `test_call_result_logged...` asserted the old call_result shape that D19 deliberately changed (fixed; plus a test for the opt-in scrubbed summary).
(2) A ~50% flaky hub test turned out to be a real race: `ui_connected` registered the UI for broadcasts BEFORE awaiting the history read, so a broadcast (e.g. the previous proxy closing) could reach a UI ahead of its snapshot.
Fixed by holding the UI's send lock from registration to the end of the snapshot send; regression test `tests/server/test_inbox_snapshot_first.py` (fails on the old order) and mutant Z7. Flaky-looking == race until proven otherwise.

## D20: operator UI (docs/PROPOSALS.md #8), first iteration
Plan: docs/plans/OPERATOR-UI.md; operator guide: docs/operator-ui.md. Inbox cards: "Why flagged" (alert score vs the alert's own threshold + earlier denied calls), "Session so far" (counters + last 10 calls, redacted previews),
deny-with-reason (the operator's cleaned note reaches the agent for human denials only, is logged, and is shown in history), and standing rules.
Standing rules are the risky part (persistent widening of authority), so: OFF unless `SENTINEL_POLICY_WRITABLE=1` and a usable `SENTINEL_POLICY`; the browser never composes a rule (the hub builds it from a call it saw; scopes exact | tool_under | tool,
`tool` never for allow); explicit `confirm === true`; whole-policy validation before an atomic write with `.bak`; write-ahead `policy_rule_added` event in the log (a failed log write writes nothing); 20 requests/minute; applies to NEW sessions only (policy is pinned per session).
Threshold: `drift_update.threshold` carries the active breach threshold (optional; absent in recorded replays), the chart and drawer use it, with the constant as fallback.
Design choices: the live card shows the current call's arguments UNREDACTED (the operator must see what they approve; a credential being sent is itself a risk signal), the history previews and the log are redacted; monitors were not changed (no structured alert evidence yet).
Found on the way: two test-design slips of mine (matching the next `inbox_resolved` instead of the right session; asserting redaction on the live card) and a hub test that raced the broadcast order (the agent made it wait for the event). None was a product bug.
Not built: editing/removing rules from the UI, rule expiry, per-operator identity (needs #6), structured alert evidence from the monitors, the built-in loop's UI.
Gate follow-up (D20): the first operator-UI gate was RED only because mutant F2 went STALE (the UI agent refactored the drawer to use the threshold carried by the event, so the mutation target text vanished); re-anchored, plus F7 (the UI ignores the event's threshold). A stale mutant is a gate failure by design: it means a guard no longer guards what it claims.
