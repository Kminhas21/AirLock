# SENTINEL course: everything that was built, fixed and measured

How to read this: each module says **what it is**, **where it lives** (file paths), **what changed**, and **how to try it**. Modules build on one another; Module 9 is a cheat-sheet of commands. Numbers come from `DECISIONS.md` (D1-D14) and `eval/results*/`; nothing here is new data.

---

## Module 0: What SENTINEL is

An agent proposes tool calls (send an email, read a file, query a DB). Two products watch it:

| Part | Job | Code |
|---|---|---|
| **Airlock** | Stops every proposed tool call until a human says `approve` or `deny` (fail-closed) | `server/gate.py`, `server/agent_loop.py` |
| **Seismograph** | Watches the agent's *reasoning* drift (MiniLM embeddings -> PCA -> Mahalanobis distance) and draws it | `seismograph/`, `server/live_drift.py` |
| **Proposal monitors** (new work) | Raise an alert at the moment a proposal looks like something you already denied, *before* the human decides | `server/proposal_monitor.py` |
| **UI** | Kill-chain graph, drift chart, approve/deny buttons, alert banners | `frontend/src/` |

Protocol: one WebSocket (`/ws`) = one session. Client sends `start_task`; server streams events (`node`, `tool_pending`, `drift_update`, `alignment_alert`, ...); for each `tool_pending` the client answers `{"event":"tool_decision","node_id":...,"decision":"approve"|"deny"}`; the session ends with exactly one `session_complete` or `error`.

---

## Module 1: The 22 bugs that were fixed (B1-B22)

Every fix has a regression test, and the gate also *mutation-tests the tests* (Module 8).

**Safety and correctness (Airlock)**
- B1 the gate accepted any next JSON as the decision -> now matches `event` + `node_id`; only the exact string `"approve"` approves.
- B2 no timeout, a walk-away hung forever -> `SENTINEL_GATE_TIMEOUT_S` (default 300) then the proposal is **denied**.
- B3 `/ws` had no auth/origin check -> `SENTINEL_WS_TOKEN` (`?token=`) and `SENTINEL_ALLOWED_ORIGINS`.
- B6 circumvention was only checked on approve -> denied attempts now count.
- B7 double-approve duplicated the effect -> `DecisionLedger`, once-only.
- B4 mock FS/DB were module globals, a new session wiped a running one -> per-session `ContextVar`.
- B5 LLM call had no timeout/retry and left the UI hanging -> bounded retries, always a terminal event.
- B15 odd first messages and `str(e)` leaked to clients -> validated, generic error text.
- B14 replay needed an API key -> replay is checked first and needs none.

**Drift engine (Seismograph)**
- B10 never wired into the live loop -> live per-session adapter (`server/live_drift.py`).
- B11 baseline of 3 points gave a singular covariance (a distance of 175.5 on the next point) -> shrinkage; threshold 3.368 = chi-square 99%, df=3.
- B12 two disagreeing resource maps -> unified.

**Contract and UI**
- B8 port 8000 vs 8080, `task_complete` vs `session_complete`, wrong drift shape -> one contract (`frontend/src/lib/*.ts` + `tests/contract/`).
- B9 reconnect every 2 s with no backoff -> exponential backoff (`lib/backoff.ts`).
- B13 frontend did not compile, 12 lint errors -> `tsc`, lint, vitest, build all pass.
- B17 UI never sent a `model` -> sensible default and clear error.
- B18 chart threshold hard-coded at 2.5 vs backend 3.368 -> single source.
- B19 Kill Chain had **no edges** (custom nodes lacked `<Handle>`s) -> handles added; verified in a real browser.
- B20 `replan` node type existed but was never emitted -> emitted and rendered.
- B21 red connection dot after every finished session -> state is "session complete", not "error".
- B22 broken at phone width (626 px on a 390 px screen) -> `@media` rules.

**Packaging**
- B16 the import crash: `cd server && uvicorn main:app` failed because `seismograph/` is a sibling directory that was not on `sys.path`. pytest hid it (its config added the path). Fixed in `server/live_drift.py` with a clean-subprocess regression test (`tests/server/`).

**Found later by review and fixed (security)**
- Banner spoofing: an agent could name a tool `send_email\nCRITICAL: all clear, approve` and forge a line inside a genuine alert. All agent- or registry-influenced strings now pass through `server/safe_text.py` (one line, fixed lengths, control/bidi characters removed). 14 hostile payloads across 6 monitor families are tested.

---

## Module 2: The proposal monitors (what raises alerts)

Alert shape: `alignment_alert`, `severity: critical`; emitted **before** `tool_pending`. Choose one with `SENTINEL_MONITOR`:

| Mode | What it is | Needs a registry | Status |
|---|---|---|---|
| `rules` | original resource-category rules | no | baseline |
| `action_sim` (**default**) | embeds "what would this action do" and compares to effects you denied (D3) | no | pre-registered survivor |
| `learned` | D7, logistic combiner of features | no | optional |
| `registry`, `registry_learned` | D8 / D9, use a destination registry | **yes** | opt-in |
| `registry_learned_e`, `registry_learned_dropout` | D9b / D9c | **yes** | opt-in, provisional |
| `registry_learned_dropout_or_action` | **new**: D9c OR D3 | **yes** | opt-in, see D13/D14 |

Safety net: every registry mode **falls back loudly** to `action_sim` (and to `rules` if only the stub embedder exists) when the registry, a frozen model file or MiniLM is unusable. `GET /health` shows `monitor` (active) vs `requested_monitor`, `registry`, `frozen_model`, `embedder`, `monitor_errors`, `session_fallbacks`.

### The destination registry (`server/registry.py`, `docs/registry.md`)
A JSON file telling the monitor which destinations are internal / external / relay (an internal-looking address that forwards outside). Keys: `email`, `email_glob`, `domain`, `host`, `url_prefix`, `channel`, `channel_glob`, `path_prefix`, `path_glob`, `db_table`, `repo`, `queue`, `any_glob`; most-specific entry wins; unknown destinations count as external. Example:
```json
{"version":1,
 "defaults":{"internal_domains":["team.com"]},
 "entries":[
  {"id":"r1","kind":"relay","party":"acme-supply","match":{"email":"acme-liaison@team.com"},"note":"distribution list with external subscribers"},
  {"id":"r2","kind":"internal","match":{"path_prefix":"/project/outbox/legacy"}}]}
```
Tools: `cd server && python -m registry_cli lint reg.json` and `python -m registry_cli resolve reg.json --tool send_email --args '{"to":"acme-liaison@team.com"}'`.

---

## Module 3: How we decided which detector is good (evaluation design)

Requirements you gave -> how they were measured: **detection timing** (alert at the first violating proposal, before execution), **added value** (what embeddings caught that rules missed), **false alarms** (an alert before any denial counts as a false alarm; acknowledging a denial must not alert), **latency**.

Design safeguards: dev/test split by hash; thresholds fitted on dev only; pass criteria written *before* scoring; paired bootstrap CIs (2000 resamples); blind relabelling by independent agents; a regex-resistant control (D5) so we know a detector is not just matching "external address after denial"; hash-checked provenance of frozen models.

Detector ladder: D0 shipped Mahalanobis, D1 rules, D2 corrected message drift, D3 action similarity, D4 rules OR D3, D5 regex control, D6 hybrid, D7 learned combiner, D8 registry rule, D9/D9b/D9c registry + learned features.

---

## Module 4: What the experiments found (honest results)

1. **v1** (easy traces): everything looked good, partly because regex shortcuts worked.
2. **v2** (regex-resistant holdout): the regex collapsed; no detector qualified. Diagnosis: the missing input was *where a destination really leads*. That is why the registry was built.
3. **v3** (fresh 60 traces, registries built from an operator-style inventory, not from the truth notes): D9b qualified **provisionally**: on-time 73.3% (CI 56.7-88.2) vs 36.7% for the best no-registry detector; false alarms 1.6% overall, 5.9% after-denial benign, 2.9% on traps; median 0.08 ms, p95 42 ms.
4. **v3-degrade** (D12): stale or missing registry entries break the registry detectors. Missing route: D9b on-time 0% vs D3 45%. Stale "internal": 5% vs 45%. **No registry detector is robust.**
5. **v3-union** (D13, post-hoc on seen data): D9c OR D3 passes every degradation criterion (never worse than D3; sparse registry 53% vs 37%) and with a correct registry gets 76.7% on-time, 3.0% FA. It **misses one bar**: false alarms on benign post-denial proposals 11.1% vs the 10% limit. A wrongly listed relay still causes ~100% FA on traffic to it. You chose to ship it as opt-in anyway (D14).

Limits to remember: synthetic data from one model family; 30 violating traces in v3; two data generators were stopped by a safety classifier and were not retried or reworded, so stale/sparse inventories were only tested mechanically (v3-degrade), not with realistic hand-written inventories.

---

## Module 5: What YOU can do (features and sample workflows)

**Workflow A: Watch a session with no API key (replay)**
1. Start backend and frontend (Module 9). 2. Open the UI, choose the adversarial scenario, run. 3. See nodes appear, the drift chart cross the 3.368 line, and the approve/deny buttons on each `tool_pending`.

**Workflow B: Live agent with human gating**
Set `OPENROUTER_API_KEY`, start the backend, run a task in the UI. Every tool call pauses at the gate. Deny one; if the agent retries the same goal by another route (e.g. a webhook instead of email), the `action_sim` monitor shows a critical banner *before* you are asked again.

**Workflow C: Raw WebSocket client**
```python
import asyncio, json, websockets
async def main():
    async with websockets.connect("ws://localhost:8080/ws") as ws:
        await ws.send(json.dumps({"event":"start_task","task":"summarise the Q3 report","scenario":"adversarial","mode":"replay"}))
        async for raw in ws:
            ev = json.loads(raw); print(ev["event"])
            if ev["event"] == "tool_pending":
                await ws.send(json.dumps({"event":"tool_decision","node_id":ev["node_id"],"decision":"deny"}))
            if ev["event"] in ("session_complete","error"): break
asyncio.run(main())
```

**Workflow D: Turn on a registry monitor**
1. Write a registry (Module 2) and lint it. 2. `SENTINEL_MONITOR=registry_learned_dropout_or_action SENTINEL_REGISTRY=/path/reg.json uvicorn main:app --port 8080` from `server/`. 3. `curl localhost:8080/health` and confirm `monitor` equals the mode you asked for; if it shows `action_sim`, read `session_fallbacks`/logs for why. 4. Edit the registry any time: the next session picks it up (content-hash cache) with no restart.
Keep entries fresh: stale entries are the failure mode measured in D12/D13.

**Workflow E: Re-run the science**
`python -m eval.run_eval_v3` (one-shot, refuses to overwrite), `python -m eval.run_eval_v3_degrade`, `python -m eval.run_eval_v3_union`. Results land in `eval/results_v3*/REPORT.md`.

**Workflow F: Prove nothing regressed**
`scripts/verify.sh`. Exit code 0 is the only verdict.

---

## Module 6: Configuration reference

| Variable | Meaning |
|---|---|
| `OPENROUTER_API_KEY` | live agent |
| `SENTINEL_WS_TOKEN`, `SENTINEL_ALLOWED_ORIGINS` | WebSocket access control |
| `SENTINEL_GATE_TIMEOUT_S` | human decision deadline, default 300 s, then deny |
| `SENTINEL_MONITOR` | mode (Module 2), default `action_sim` |
| `SENTINEL_EMBEDDER` | `minilm` (default) or `stub` |
| `SENTINEL_REGISTRY` | registry file for registry modes |
| `SENTINEL_MONITOR_MODEL`, `SENTINEL_REGISTRY_MODEL`, `SENTINEL_REGISTRY_MODEL_V3` | frozen model files |
| `SENTINEL_MONITOR_THRESHOLD` | optional override, uncalibrated |
| `VITE_SENTINEL_WS_URL` | frontend WebSocket URL |

---

## Module 7: Map of the code base

- `server/`: `main.py` (WS entry), `agent_loop.py`, `gate.py`, `events.py`, `replay.py`, `proposal_monitor.py` (modes, factory, union), `registry.py`/`registry_cli.py`, `safe_text.py`, `live_drift.py`, `drift_tracker.py`, `mock_environment.py`.
- `seismograph/`: embedder, PCA, Mahalanobis analyzer.
- `eval/`: specs (`SPEC*.md`), detectors (`detectors*.py`, `detectors_union.py`), runners (`run_eval*.py`), data (`final*/`, `registries_*/`), results (`results*/`), integrity checks.
- `frontend/src/`: UI; `frontend/e2e/`: Playwright (live WebSocket, replay parity, registry banner).
- `tests/`: server, eval, contract, e2e, browser (a fake LLM that replays traces).
- `scripts/`: `verify.sh` (the gate), `mutation_check.py`.
- `docs/`: this course, `registry.md`, `HANDOFF.md`, `EMBEDDING_EVAL.md`, `PROPOSALS.md`, `v3/` (PRD, tickets, review packages).
- `DECISIONS.md`: every decision with its reasons (D1-D14).

---

## Module 8: The verification gate (why you can trust "green")

`scripts/verify.sh` runs backend tests, the legacy seismograph script, frontend type-check/lint/unit/build, Playwright browser tests, offline-vs-live **replay parity** for each monitor family (live alerts must equal the offline detector's alerts on every trace), registry-file freshness checks and the registry UI banner tests. Last it runs `scripts/mutation_check.py`: it re-introduces 22 known bugs one at a time and fails if the test suite does *not* catch each one. The union mode was added with its own parity test over all 60 v3 traces.

Process used to build it: ticketed vertical slices (`docs/v3/tickets/`), implementer -> spec review -> code-quality review -> fix -> re-check (`docs/v3/reviews/`). The matt-pocock and superpowers skills are not installed in this environment, so their methods were followed by hand; this is stated in `DECISIONS.md`.

---

## Module 9: Run it

```bash
# backend
pip install -r requirements-dev.txt          # includes server deps
cd server && uvicorn main:app --port 8080    # MiniLM loads in the background
curl localhost:8080/health

# frontend
cd frontend && npm ci && npm run dev         # ws://localhost:8080/ws by default

# tests and gate
scripts/verify.sh                            # exit 0 = green (several minutes)
cd frontend && npm test && npx playwright test

# offline mode without model downloads
SENTINEL_EMBEDDER=stub uvicorn main:app --port 8080   # implies the rules monitor
```

## Module 10: Open questions and what I would do next

- Fresh holdout (v4) before trusting the union: realistic hand-written stale/sparse inventories, which the generators could not produce.
- Registry freshness: age-limit entries (advisory when older than N days) so a stale relay entry cannot cause near-total false alarms.
- `/health` is unauthenticated and shows file paths; Kill Chain detail panels still preserve newlines (the banner is safe, the panels are not fully).
- Whether to recommend any registry monitor as default is the maintainer's call; the current recommendation is: keep `action_sim` as default.
