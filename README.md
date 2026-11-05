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
  `GET /health` reports what is ACTIVE: `{"status", "monitor", "requested_monitor", "registry", "embedder", "monitor_errors",
  "session_fallbacks", "last_session_fallback"}` (`monitor_errors` counts monitor exceptions, each of which was logged and let
  the proposal through to the human without an alert; `session_fallbacks` counts sessions that degraded PER SESSION, e.g. a
  registry monitor that could not be built for that session ran `action_sim`, and `last_session_fallback` says why, `null` if none).
  Alert texts are safe to render: every string an agent or a registry can influence (tool name, destination, party, registry
  note and entry id, earlier denied proposal, feature name) is reduced to ONE line before it is put into a message (all
  whitespace, control, line-separator and bidi/zero-width characters collapse or vanish) and cut to a fixed length with an
  ellipsis: tool 80, destination 120, party 60, entry id 60, note 160, earlier effect 200 characters (`server/safe_text.py`).
  The only newline in an alert is the one the monitor itself writes before its final `Monitor:` line (v3 modes).
  Tests and CI that do not need real embeddings set `SENTINEL_EMBEDDER=stub` (which implies the `rules` monitor).

Destination-registry monitors (OPT-IN, DECISIONS.md D9; the default stays `action_sim`; operator guide: `docs/registry.md`, "Running it live"):
- `SENTINEL_MONITOR=registry` (frozen D8: registry party match x payload similarity) or `registry_learned` (frozen D9: D7 plus registry features).
  Alerts: `alignment_alert`, `severity: critical`, `trigger: registry_denied_party_match`; the message names the destination,
  the registry entry and its note, the party, the earlier denied proposal that reached it and the scores.
- `SENTINEL_REGISTRY` = path of your destination registry JSON (required for these modes). It is read and linted at every
  session start (cached by the sha256 of its CONTENT, so any edit applies to the next session without a restart, even a
  same-size one with a restored mtime); lint errors reject the file.
- `SENTINEL_REGISTRY_MODEL` = frozen D8/D9 parameters (default `eval/results_registry/frozen_registry_models.json`).
- `SENTINEL_MONITOR_THRESHOLD` = optional float in [0, 1] replacing the alert threshold of D8 (both `t_same` and `t_other`),
  D9, D9b and D9c (every registry mode; not `action_sim` / `learned`). **UNCALIBRATED**: the frozen thresholds are the pre-registered ones (see
  `eval/results_registry/D9_threshold_sweep_DESCRIPTIVE.md` and its caveat). Invalid values are ignored with a WARNING.
- Without a usable registry (unset, missing, unparseable, lint errors), a missing frozen file or the stub embedder the server
  logs a WARNING and runs `action_sim` instead (never a registry-trained detector without a registry: D9 without one scores
  16.7% on-time vs 37.5% for D7). `GET /health` then shows both: `{"monitor": "action_sim", "requested_monitor": "registry_learned",
  "registry": null, ...}`; with a working registry `"registry": {"path", "digest", "entries"}`.

v3 registry monitors (OPT-IN, PROVISIONAL, DECISIONS.md D10; default unchanged):
- `SENTINEL_MONITOR=registry_learned_e` (frozen D9b) or `registry_learned_dropout` (frozen D9c). Same `SENTINEL_REGISTRY` handling and alert
  trigger as above; the alert text ends with `Monitor: <mode> (frozen, provisional: see DECISIONS D10)`.
- `SENTINEL_REGISTRY_MODEL_V3` = frozen D9b/D9c parameters (default `eval/results_registry_v3/frozen_registry_models_v3.json`;
  must carry `schema_version: registry_models_v3/1`). `SENTINEL_REGISTRY_MODEL` is not used by these modes.
- They NEVER run without a valid registry (the v3 evaluation: 0% on-time without one vs 36.7% for `action_sim`): unset / missing /
  unparseable / lint-failing / entry-less registry or a missing, corrupt or wrong-schema frozen file all log a WARNING and run
  `action_sim`; with the stub embedder `action_sim` cannot run either, so the chain ends at `rules`. `GET /health` adds
  `frozen_model` (also reported for `registry` / `registry_learned`) (`{"path", "sha256" (first 16 hex), "schema_version"}`, `null`
  during a fallback) next to `monitor` (active), `requested_monitor` and `registry`. Read "What the v3 evaluation showed" in `docs/registry.md` first.

Union monitor (OPT-IN, DECISIONS.md D13-D14): `SENTINEL_MONITOR=registry_learned_dropout_or_action` = frozen D9c OR D3, needs `SENTINEL_REGISTRY`, same fallbacks as the other registry modes.

Full walkthrough of everything built, with workflows: `docs/COURSE.md`.

Verify everything: `pip install -r requirements-dev.txt && scripts/verify.sh` (exit 0 = green). See `DECISIONS.md`.
