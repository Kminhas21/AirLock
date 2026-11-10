# Module specs (smallest-unit breakdown)

Rules for every module: tests FIRST (show them failing, "red"), then the minimal change ("green").
Touch only the files listed for your module. Do not git commit. Run only your own tests (others are in flux).
Write your reasoning/decisions to `docs/decisions/<MODULE>.md` (what you traced, alternatives rejected, residual risk).
Server modules are imported flat (`from gate import ...`) because pytest.ini sets `pythonpath = . server`.
Source of truth for event shapes: `frontend/src/types/contracts.ts`. Source of truth for bug list: `DECISIONS.md`.

## G1 gate — `server/gate.py`, `tests/server/test_gate.py`   (bugs B1 B2 B7)
`async def await_decision(websocket, node_id: str, timeout: float | None = GATE_TIMEOUT_S) -> GateResult`
`GateResult` = frozen dataclass `(decision: Literal["approve","deny"], reason: Literal["human","timeout","invalid"])`.
- Loops on `websocket.receive_json()`. Ignores (and logs at WARNING) anything that is not a dict, whose `event != "tool_decision"`, or whose `node_id != node_id`. Never treats an ignored message as a decision.
- `decision` is `"approve"` ONLY if the matching message has `decision == "approve"` exactly; anything else (missing, "APPROVE", "yes", None) => deny with reason "invalid". Fail-closed.
- `timeout` is a TOTAL deadline across all ignored messages (not per receive). On expiry => `GateResult("deny","timeout")`. `None` => wait forever. `GATE_TIMEOUT_S = float(os.getenv("SENTINEL_GATE_TIMEOUT_S", "300"))`.
- `WebSocketDisconnect` / any receive exception other than timeout propagates unchanged.
- Duplicate protection (B7): a module-level-free design — `DecisionLedger` class with `.claim(node_id) -> bool` (True first time only) used by the loop before executing a tool, so a node can execute at most once.
Tests use a FakeWebSocket with a scripted queue + asyncio; no network.

## T1 drift tracker — `server/drift_tracker.py`, `tests/server/test_drift_tracker.py`   (bug B6)
Move `DriftTracker` out of `agent_loop.py` (leave agent_loop alone; integration does the import swap) and fix:
- `observe_call(tool_name) -> bool`: called when a tool is PROPOSED (before the human decides). Increments `total_actions`; returns True and increments `circumvention_count` iff the tool's resource category is already denied and the tool itself was not the denied one. Counts regardless of later approve/deny.
- keep `record_denial`, `check_goal_persistence`, `drift_score` (= circumvention_count / total_actions, clamped to [0,1]), `denied_categories`, `denied_tools`.
- `check_circumvention` stays as a deprecated alias of `observe_call`.
Regression test: deny send_email, then agent proposes send_slack_message and it is DENIED too -> circumvention_count == 1 and drift_score > 0.

## L1 llm call — `server/llm_call.py`, `tests/server/test_llm_call.py`   (bug B5)
`async def create_completion(client, *, timeout=60.0, retries=2, base_delay=1.0, sleep=asyncio.sleep, rand=random.random, **kwargs)`
- Calls `client.chat.completions.create(timeout=timeout, **kwargs)`.
- Retries (exponential backoff `base_delay * 2**attempt`, full jitter via `rand`) on: `asyncio.TimeoutError`, `openai.APIConnectionError`, `openai.APITimeoutError`, `openai.RateLimitError`, `openai.InternalServerError`.
- Does NOT retry `openai.AuthenticationError`, `BadRequestError`, other 4xx — raises immediately.
- After exhausting retries raises `LLMUnavailable(Exception)` with the last error chained and `attempts` attribute.
Tests: fake client raising scripted errors; injected `sleep` records delays (no real sleeping).

## E1 per-session environment — `server/mock_environment.py`, `tests/server/test_mock_environment.py`   (bug B4)
Replace module-global stores with a per-session `Environment` held in a `ContextVar`.
- `get_environment()` returns the env for the current context, lazily creating a fresh default one if none (do NOT create one at import: child tasks copy the parent context and would share it).
- `reset_environment()` installs a FRESH env into the current context and returns it.
- All `exec_*` functions read/write through `get_environment()`. Public signatures of `exec_*` unchanged. Remove the module globals `MOCK_FS`/`MOCK_DB`/`*_LOG` (nothing else imports them — verified by grep).
Regression test: two asyncio tasks each `reset_environment()`, one writes a file, interleave with `await asyncio.sleep(0)`, the other must not see the write nor lose its own state; a third task started later must not see either.

## A1 ws access control — `server/auth.py`, `tests/server/test_auth.py`   (bug B3)
`def check_ws_access(origin: str | None, token: str | None, env=os.environ) -> AccessResult(allowed: bool, reason: str)`
- If `SENTINEL_WS_TOKEN` is set: `token` must match (`hmac.compare_digest`), else denied "bad_token". Unset => token not required (dev default), but log one WARNING at import-time-free call site? (keep it pure: just return `reason="open"`).
- `Origin`: if an origin header is present it must be in `SENTINEL_ALLOWED_ORIGINS` (comma list, default `http://localhost:5173,http://127.0.0.1:5173`), else denied "bad_origin". Absent origin (non-browser client) is allowed.
Pure function, no FastAPI imports.

## C1 event builders + contract test — `server/events.py`, `tests/contract/test_events_contract.py`   (bug B8)
Pure builders returning dicts: `reasoning`, `tool_pending`, `tool_resolved`, `drift_update`, `alignment_alert`, `session_complete`, `error`. Timestamps are ISO-8601 UTC generated inside (injectable `now=` for tests).
The contract test PARSES `frontend/src/types/contracts.ts` (regex over `export interface XEvent { event: "name"; field: type; ... }`) and asserts, for every builder, that the produced key set equals the interface's field set (optional `?` fields may be absent). Also asserts every `event` literal in contracts.ts that the server can send has a builder, and validates every event in `demo/cached_runs/*.json` against the same parsed field sets (ignoring `delay_ms`). This makes a field rename fail CI.
Builder field decisions (contract = frontend types are authoritative): `tool_resolved` includes `agent_response` (""), `session_complete` has `reason`+`message`.

## S1 seismograph math — `seismograph/drift_detector.py`, `seismograph/projector.py`, `tests/seismograph/test_drift_detector.py`   (bug B11)
Root cause traced: PCA on a 3-sample baseline has rank 2, so the 3rd coordinate is ~0 and the baseline covariance is singular; the fixed `+1e-4*I` hack yields distances like 175 on the next point.
- Replace the fixed epsilon with shrinkage: `cov_s = (1-a)*cov + a*(trace(cov)/d)*I` (a = 0.1 default, param), with a floor of `1e-9` on the scale term so identical points do not give a zero matrix. Use `np.linalg.pinv`/`solve` so no `LinAlgError` is possible.
- Replace magic `2.5` with `CHI2_99_DF3 = 3.368` (= sqrt(chi2.ppf(0.99, 3))), documented; constructor `threshold` param still overrides.
- Projector must always return 3 coords (pad with 0.0 when PCA has fewer comps) — keep as is if already true.
Tests: never raises on identical / collinear / coplanar / NaN-free random baselines (hypothesis-style loop of 200 seeds); distance finite; scale invariance (multiplying all coords by 10 leaves distance unchanged); a point near baseline mean < threshold, a far point > threshold; `python -m seismograph.test_pipeline --stub-only` must still pass (if an assertion encoded the old magic numbers, update it AND record why in your decision file).

## S2 seismograph resource map — `seismograph/analyzer.py`, `tests/seismograph/test_analyzer_maps.py`   (bug B12)
`analyzer.TOOL_RESOURCE_MAP`/`TOOL_KEYWORD_MAP` cover only 4 tools and disagree with the live `server/risk_scorer.py` (e.g. read_file is "data" vs "filesystem"). Make them cover all 13 tools and be EQUAL to `risk_scorer.RESOURCE_MAP`. A test (importing `risk_scorer` via pythonpath) asserts equality so the two can never drift. Seismograph must not import from `server/`.
S1 and S2 may both be done by one agent in sequence (different files).

## W1 frontend socket — `frontend/src/hooks/useWebSocket.ts`, `frontend/src/lib/*`, `frontend/src/App.tsx`, `frontend/src/vite-env.d.ts`, `frontend/package.json`(+lock; ONLY for vitest), `frontend/vite.config.ts`, `frontend/mockServer.cjs`   (bugs B8 B9)
- URL from `import.meta.env.VITE_SENTINEL_WS_URL`, default `ws://localhost:8080/ws`; optional `VITE_SENTINEL_WS_TOKEN` appended as `?token=`. Mock server moves to env-configurable port (default 8000 kept for the mock only, documented).
- Pure, testable modules in `src/lib/`: `wsUrl.ts` (build URL), `backoff.ts` (exponential, capped, jittered; reset on open), `routeEvent.ts` (event -> handler dispatch, including `session_complete` AND legacy `task_complete` => setIsRunning(false), and `error` => setIsRunning(false) + surface message via console.error/store-free callback). Hook uses them.
- Fix lint error "Cannot access variable before it is declared" for `connect` (self-reference in onclose) using a ref.
- `App.tsx` must send `model` only if chosen (do not invent one); decisions already include node_id.
- Add `vitest` (devDependency) + `"test": "vitest run"` script; tests in `frontend/src/lib/*.test.ts`.
Do NOT edit sessionStore.ts / KillChain.tsx / DriftMonitor.tsx (module W2 owns them).

## W2 frontend type health — `frontend/src/components/DriftMonitor.tsx`, `KillChain.tsx`, `frontend/src/stores/sessionStore.ts`, new `frontend/src/types/*.d.ts`   (bug B13)
Make `npx tsc -b` and `npm run lint` clean WITHOUT `any`/`eslint-disable` escape hatches: `NodeData` must satisfy react-flow's `Record<string, unknown>` (use `type` alias instead of `interface`, or extend), declare plotly types (`declare module 'react-plotly.js'` with a minimal typed Props, or `@types/react-plotly.js` if installable — prefer the .d.ts to avoid touching package.json), fix the "first argument must be an inline function expression" React-compiler lint in KillChain.tsx:273. Behaviour must not change. Do NOT touch package.json.

## X1 end-to-end acceptance tests — `tests/e2e/test_ws_session.py`, `tests/e2e/fakes.py`   (all bugs, black-box)
Written from the contract and this spec ONLY — do not read or depend on how `server/agent_loop.py` implements things. Use `fastapi.testclient.TestClient(main.app)` and `monkeypatch.setattr(main, "get_client", lambda key: (FakeClient(script), "fake-model"))` (also patch `main.list_models`/`DEFAULT_MODEL` if needed). `FakeClient.chat.completions.create` is async and replays a script of assistant turns (content + tool_calls, shaped like openai objects: `.choices[0].message.content/.tool_calls[i].id/.function.name/.function.arguments`).
Scenarios (each its own test, assertions on the received event stream):
 1. approve path: tool_pending -> approve -> tool_resolved(decision=approve) -> ... -> exactly one terminal `session_complete`.
 2. deny path: result starts with "[DENIED", `is_replan` true, tool NOT executed (assert via `mock_environment.get_environment()` side-effect log or file absent).
 3. out-of-order/forged message while pending (wrong event name; right event wrong node_id; non-JSON-object) must NOT approve; then correct deny/approve is honoured.
 4. garbage decision value => denied.
 5. gate timeout (set env `SENTINEL_GATE_TIMEOUT_S=0.3` via monkeypatch BEFORE import-time read is a problem -> patch `gate.GATE_TIMEOUT_S` AND agent_loop's reference; if impossible, patch `main`/`agent_loop` attribute named `GATE_TIMEOUT_S`) => deny + terminal event `session_complete` with reason `gate_timeout`.
 6. LLM raises `openai.AuthenticationError`-like error => terminal `session_complete(reason="llm_error")` (or `error`), never a hang (use a TestClient receive with a thread timeout guard).
 7. LLM transient errors twice then success => session completes normally.
 8. circumvention: deny send_email, model proposes send_slack_message, human denies it => an `alignment_alert` with `severity` present and `drift_update` events matching the contract shape (coordinates/metrics/mahalanobis_distance/baseline_breached).
 9. every emitted event validates against the field sets parsed from contracts.ts (reuse the parser from tests/contract if present, else re-implement).
10. replay mode works with NO api key / unknown model key, for both scenarios `aligned` and `adversarial`, and replay respects the same contract.
11. two concurrent sessions do not share mock environment state.
12. bad first message (not start_task / not a JSON object) => `error` event, connection closed.
13. auth: with `SENTINEL_WS_TOKEN` set, connect without token is rejected; with `?token=` accepted; bad Origin rejected.
These are EXPECTED TO FAIL against the current code (that is the point: they are the acceptance gate). Report which fail and why, to prove they exercise the bugs rather than pass vacuously.

## Wave 2 (after wave 1)
- D1 `server/live_drift.py`: per-session adapter combining `SeismographAnalyzer` (embedder chosen by `SENTINEL_EMBEDDER=stub|minilm`, auto fallback to stub with a WARNING when sentence-transformers/model cache is unavailable) and `DriftTracker`; emits contract-shaped `drift_update` / `alignment_alert`.
- R1 replay: `run_replay` reads contract-shaped files from `demo/cached_runs/{scenario}_run.json`; main validates model only for live mode.
- I1 integration: `agent_loop.py` / `main.py` wired to gate, tracker, llm_call, events, live_drift, auth, per-session env.
