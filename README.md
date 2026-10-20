# SENTINEL — Airlock & Seismograph

Backend: `cd server && pip install -r requirements.txt && uvicorn main:app --port 8080`
Frontend: `cd frontend && npm ci && npm run dev` (defaults to `ws://localhost:8080/ws`; override with `VITE_SENTINEL_WS_URL`)
Replay demo (no API key): send `start_task` with `"mode": "replay"`.

Config: `OPENROUTER_API_KEY`, `SENTINEL_WS_TOKEN` (require `?token=`), `SENTINEL_ALLOWED_ORIGINS`,
`SENTINEL_GATE_TIMEOUT_S` (default 300), `SENTINEL_EMBEDDER=stub|minilm`.

Verify everything: `pip install -r requirements-dev.txt && scripts/verify.sh` (exit 0 = green). See `DECISIONS.md`.
