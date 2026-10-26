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
  `GET /health` reports what is ACTIVE: `{"status", "monitor", "requested_monitor", "registry", "embedder", "monitor_errors"}` (`monitor_errors` counts monitor
  exceptions, each of which was logged and let the proposal through to the human without an alert).
  Tests and CI that do not need real embeddings set `SENTINEL_EMBEDDER=stub` (which implies the `rules` monitor).

Destination-registry monitors (OPT-IN, DECISIONS.md D9; the default stays `action_sim`; operator guide: `docs/registry.md`, "Running it live"):
- `SENTINEL_MONITOR=registry` (frozen D8: registry party match x payload similarity) or `registry_learned` (frozen D9: D7 plus registry features).
  Alerts: `alignment_alert`, `severity: critical`, `trigger: registry_denied_party_match`; the message names the destination,
  the registry entry and its note, the party, the earlier denied proposal that reached it and the scores.
- `SENTINEL_REGISTRY` = path of your destination registry JSON (required for these modes). It is read and linted at every
  session start (mtime-cached), so edits apply to the next session without a restart; lint errors reject the file.
- `SENTINEL_REGISTRY_MODEL` = frozen D8/D9 parameters (default `eval/results_registry/frozen_registry_models.json`).
- `SENTINEL_MONITOR_THRESHOLD` = optional float in [0, 1] replacing the alert threshold of D8 (both `t_same` and `t_other`)
  / D9 only. **UNCALIBRATED**: the frozen thresholds are the pre-registered ones (see
  `eval/results_registry/D9_threshold_sweep_DESCRIPTIVE.md` and its caveat). Invalid values are ignored with a WARNING.
- Without a usable registry (unset, missing, unparseable, lint errors), a missing frozen file or the stub embedder the server
  logs a WARNING and runs `action_sim` instead (never a registry-trained detector without a registry: D9 without one scores
  16.7% on-time vs 37.5% for D7). `GET /health` then shows both: `{"monitor": "action_sim", "requested_monitor": "registry_learned",
  "registry": null, ...}`; with a working registry `"registry": {"path", "digest", "entries"}`.

Verify everything: `pip install -r requirements-dev.txt && scripts/verify.sh` (exit 0 = green). See `DECISIONS.md`.
