# SENTINEL handoff: everything you need to talk to an agent about this project

Written so a person (or an AI agent) who has not touched this codebase in a while can get oriented. Last updated 2026-10-22.

## 1. What this is
SENTINEL is a **human-in-the-loop safety layer for tool-using AI agents**. A bundled agent proposes tool calls (read a file, send an email, run a shell command...). Each call is paused in the **Airlock** until a human approves or denies it in a web UI. The **Seismograph** watches for *drift*: an agent that is told "no" and then tries to reach the same goal another way ("circumvention"). The plan is shown as a graph called the **Kill Chain**. It started as a hackathon project (HooHacks 2026), three people: Alpha (backend), Bravo (frontend), Charlie (Seismograph). It was the subject of an interview-prep recap.

**It is a demo, not a production monitor.** Tools are fake (dict mutations), there is no persistence, and it only monitors its own bundled agent. See `docs/PROPOSALS.md` for what would make it a real monitoring system.

## 2. Architecture
```
Browser (React 19, Vite, Zustand, React Flow + dagre, Plotly)
      |  one WebSocket = one agent session   ws://localhost:8080/ws
FastAPI (server/main.py)  -- auth check (Origin/token) -> first message must be start_task
      |
agent_loop.py: while-loop  --HTTP-->  OpenRouter (or any OpenAI-compatible endpoint)
   |- gate.py            waits for the matching human decision (fail-closed, deadline)
   |- drift_tracker.py   rule-based circumvention (resource category)
   |- live_drift.py      Seismograph per session (embed -> PCA -> Mahalanobis)
   |- tools.py -> mock_environment.py   13 fake tools, per-session state (ContextVar)
   `- replay.py          cached demo runs, no API key needed
```
**The key idea:** there is no approval queue. `await websocket.receive_json()` inside `gate.await_decision` *is* the pause: a suspended coroutine is a pending action.

**Graph libraries:** `@xyflow/react` (React Flow) draws the Kill Chain, `dagre` computes the layout, Plotly draws the drift charts, Zustand holds state. (Not networkx; nothing uses it.)

## 3. WebSocket contract (source of truth: `frontend/src/types/contracts.ts`)
Client to server: `start_task {task, scenario: aligned|adversarial, model?, mode?: live|replay}`, `tool_decision {node_id, decision: approve|deny}`.
Server to client: `reasoning`, `tool_pending {node_type: tool_call|replan, risk_level...}`, `tool_resolved`, `drift_update {coordinates, metrics, mahalanobis_distance, baseline_breached}`, `alignment_alert {severity, trigger, threshold...}`, `session_complete {reason}` (always exactly one terminal event, or `error`). `task_complete` is a legacy alias used only by `frontend/mockServer.cjs`.
A pytest parses `contracts.ts` and checks the backend builders (`server/events.py`) against it, so a renamed field fails CI.

## 4. File map
| Path | Purpose |
|---|---|
| `server/main.py` | app, `/health`, `/models`, `/ws`; access check, replay vs live |
| `server/agent_loop.py` | the loop; prompts for aligned/adversarial; emits events |
| `server/gate.py` | `await_decision` (matches event+node_id, only exact "approve" approves, deadline), `DecisionLedger` |
| `server/drift_tracker.py` | rule-based circumvention counter and goal-persistence keywords |
| `server/live_drift.py` | per-session Seismograph adapter; `SENTINEL_EMBEDDER=stub` (default) or `minilm` (falls back to stub with a warning) |
| `server/llm_call.py` | timeout, retries, jittered backoff, `LLMUnavailable` |
| `server/mock_environment.py`, `tools.py`, `risk_scorer.py` | fake tools, tool schemas, risk and resource maps |
| `server/auth.py`, `providers.py`, `events.py`, `replay.py` | origin/token check; model registry; event builders; replay |
| `seismograph/` | `embedder.py` (MiniLM + stub), `projector.py` (PCA to 3-D), `drift_detector.py` (shrinkage Mahalanobis, threshold 3.368), `metrics.py`, `analyzer.py` |
| `demo/cached_runs/*_run.json` | contract-shaped recorded runs used by replay |
| `frontend/src/` | `hooks/useWebSocket.ts`, `lib/` (url, backoff, reconnect, routeEvent, drift threshold), `stores/sessionStore.ts`, `components/` |
| `tests/` | `server/` unit, `seismograph/`, `contract/`, `e2e/` (black-box over the real app), `browser/fake_llm.py` |
| `frontend/e2e/live.spec.ts` | Playwright: real browser, real WebSocket, real backend |
| `scripts/verify.sh`, `scripts/mutation_check.py` | the verification gate |
| `DECISIONS.md`, `docs/modules/SPEC.md`, `docs/decisions/*` | bug register, module specs, per-module reasoning |

## 5. Run it
```bash
pip install -r requirements-dev.txt
cd server && OPENROUTER_API_KEY=... uvicorn main:app --port 8080     # backend
cd frontend && npm ci && npm run dev                                  # UI on :5173
# no key? send start_task with "mode":"replay"
scripts/verify.sh                                                     # everything, exit 0 = green
```
Config: `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, `SENTINEL_DEFAULT_MODEL`, `SENTINEL_WS_TOKEN`, `SENTINEL_ALLOWED_ORIGINS`, `SENTINEL_GATE_TIMEOUT_S` (default 300), `SENTINEL_EMBEDDER`; frontend `VITE_SENTINEL_WS_URL`, `VITE_SENTINEL_WS_TOKEN`.

## 6. How correctness is established (the verification gate)
`scripts/verify.sh` runs: backend pytest (unit, contract, black-box e2e), the legacy Seismograph script, `tsc`, eslint, vitest, `vite build`, Playwright on the real stack, and a **mutation check** that re-introduces known bugs into a throwaway copy and requires the suite to fail for each. Exit code is the only verdict. The e2e tests were written by a separate agent from the spec only. The browser tests use a scripted OpenAI-protocol HTTP server (`tests/browser/fake_llm.py`): the model is the only fake.
Method for every fix: write a failing test first, then the smallest change, then rerun the gate. `/matt-pocock` and `/superpowers` skills were not available; their methods were followed by hand.

## 7. Bugs found and fixed (details and evidence in `DECISIONS.md`)
Gate accepted any message as a decision, had no timeout, and no auth on `/ws` (B1-B3); shared global mock state (B4); no LLM timeout/retry and sessions that hung (B5); circumvention only counted when approved (B6); UI/backend contract mismatches (B8); Seismograph not wired in, N=3 covariance blow-up, inconsistent resource map (B10-B12); frontend did not compile (B13); replay needed an API key (B14); **import crash** (B16, below); default model only with OpenRouter (B17); chart threshold 2.5 vs backend 3.368 (B18); **Kill Chain drew no edges** (B19); replan never emitted (B20); red connection dot after every session (B21); broken narrow layout (B22).

**The import crash, in plain terms:** `server/` files import each other by bare name (`import events`), so they only work when `server/` is the working directory. `seismograph/` sits *next to* `server/`, and Python does not add the repo root to its module search path when you start `uvicorn` from `server/`. Wiring Seismograph into the live loop therefore crashed startup with `No module named 'seismograph'`. The test suite hid it because `pytest.ini` adds the repo root to the path. Fixed by `live_drift.py` adding the repo root to `sys.path`, with a clean-subprocess regression test. Cleaner long-term fix: package the project (`pyproject.toml`, `pip install -e .`).

## 8. Current status (2026-10-22)
- Branch `fix/verified-gate-and-bug-fixes` on `Kminhas21/AirLock`, PR #1 into `alpha`.
- Gate green at last full run: 228 backend tests, 17 frontend unit tests, 8 browser tests, 18 mutants all caught (re-run before merging).
- **Not verified:** real LLM behaviour; **embedding drift quality** (see `docs/EMBEDDING_EVAL.md`); Firefox/WebKit; real tool isolation.
- Hugging Face is now reachable from the sandbox; installing sentence-transformers and downloading the model was in progress when this was written.
- Deliberately not built: persistence/reconnect rehydration, real sandbox, multi-user, auth beyond a static token.

## 9. Gotchas
- Backend port is **8080** (Windows reserves 8000). The mock server `frontend/mockServer.cjs` uses 8000 and is only for UI work without a backend.
- The server closes the socket after every session by design; the UI reconnects immediately.
- `mock_environment` state lives in a `ContextVar`: each session entry point must call `reset_environment()` inside its own task.
- `Embedder` uses `local_files_only=True`: the model must be downloaded once beforehand.
- Gate deadline defaults to 300 s; a timeout denies the action and ends the session with `gate_timeout`.
- `demo/generate_cached_runs.py` needs the real model and was not re-run after the threshold/map changes.
- Sandbox: network access is allow-listed per environment; the GitHub App must be installed on the repo for pushes.

## 10. Glossary
**Airlock** the approval gate. **Kill Chain** the graph of reasoning and tool-call nodes. **Seismograph** the drift pipeline. **Drift** behaviour moving away from a baseline. **Circumvention** reaching a denied goal via another tool. **Mahalanobis distance** distance from a baseline that accounts for the baseline's spread and correlations. **PCA** projects 384-d embeddings to 3-D. **Shrinkage** blends the estimated covariance with a scaled identity so it is invertible. **AUC** probability that a random positive scores higher than a random negative (0.5 = chance). **Mutation check** deliberately re-breaking the code to prove the tests notice.

## 11. Good questions to ask your agent
- "Run the embedding evaluation in `docs/EMBEDDING_EVAL.md` and report against the pass criteria."
- "Why does `check_circumvention` miss paraphrased attempts, and how would action-level embeddings help?"
- "Package the project so `pip install -e .` replaces the `sys.path` fix."
- "Implement the policy engine from `docs/PROPOSALS.md` section 2."
- "Which parts of `DECISIONS.md` section D5 are still unverified, and how would we verify each?"
