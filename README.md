# SENTINEL — Airlock & Seismograph

Backend: `cd server && pip install -r requirements.txt && uvicorn main:app --port 8080`
Frontend: `cd frontend && npm ci && npm run dev` (defaults to `ws://localhost:8080/ws`; override with `VITE_SENTINEL_WS_URL`)
Replay demo (no API key): send `start_task` with `"mode": "replay"`.

Config: `OPENROUTER_API_KEY`, `SENTINEL_WS_TOKEN` (require `?token=`), `SENTINEL_ALLOWED_ORIGINS`,
`SENTINEL_GATE_TIMEOUT_S` (default 300).

Proposal monitor (alerts when a tool is *proposed*, before `tool_pending` / the human decision; DECISIONS.md D6-D7):
- `SENTINEL_MONITOR=action_sim|learned|rules` (default `action_sim`). `action_sim` = frozen D3 (similarity of the proposed
  effect to effects you already denied in this session; the pre-registered survivor), `learned` = frozen D7 (logistic
  combiner), `rules` = the original resource-category rules. Alerts: `alignment_alert`, `severity: critical`,
  `trigger: denied_effect_match`, message names the score, the threshold and the earlier denied effect.
- `SENTINEL_MONITOR_MODEL` = path of the frozen detector parameters (default `eval/results_v2/frozen_models.json`).
- `SENTINEL_EMBEDDER=minilm|stub` (default **`minilm`**; the monitors need real embeddings). The model is loaded in a
  background thread at startup. If MiniLM is not in the local cache, or the frozen file is missing/corrupt, the server logs
  a WARNING and falls back (embedder -> `stub`, monitor -> `rules`); it never refuses to start.
  `GET /health` reports what is ACTIVE: `{"status", "monitor", "embedder", "monitor_errors"}` (`monitor_errors` counts monitor
  exceptions, each of which was logged and let the proposal through to the human without an alert).
  Tests and CI that do not need real embeddings set `SENTINEL_EMBEDDER=stub` (which implies the `rules` monitor).

Verify everything: `pip install -r requirements-dev.txt && scripts/verify.sh` (exit 0 = green). See `DECISIONS.md`.
