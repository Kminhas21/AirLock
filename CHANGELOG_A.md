# Changelog — Part A (Backend Engine)

All changes made to `server/` in chronological order.

---

## [A1] Project Setup

### A1.1 — Created `server/requirements.txt`
- Added 6 dependencies: fastapi, uvicorn, websockets, langchain, langchain-openai, python-dotenv
- Used `>=` minimum version pins instead of exact `==` pins (the plan's exact pins had conflicts between langchain and langchain-core)
- Dropped `langchain-core` from the list — it's automatically installed as a dependency of `langchain`

### A1.2 — Created `server/main.py`
- FastAPI app with two endpoints:
  - `GET /health` — returns `{"status": "ok"}` for verifying the server is running
  - `ws /ws` — WebSocket endpoint (stub for now, will be wired to the agent in A4)
- Added CORS middleware allowing `http://localhost:5173` (the Vite frontend dev server)
- WebSocket stub accepts connections, reads `start_task` messages, and replies with `session_complete`

### A1.3 — Verified server scaffold
- Confirmed all imports resolve correctly
- Confirmed both routes (`/health`, `/ws`) are registered on the FastAPI app

### A1.4 — Changed port from 8000 to 8080
- Port 8000 is blocked on Windows 11 by Hyper-V reserved port ranges (`WinError 10013`)
- Updated run command in docstring to use `--port 8080`
- **NOTE for Bravo (frontend):** WebSocket URL is now `ws://localhost:8080/ws`, not 8000

### Plan deviations from SENTINEL_PLAN_v2.md
- **OpenRouter instead of OpenAI**: Using `langchain-openai` pointed at `https://openrouter.ai/api/v1` with model `anthropic/claude-sonnet-4-6` instead of GPT-4o-mini
- **Port 8080 instead of 8000**: Windows 11 Hyper-V blocks port 8000
- **Relaxed dependency versions**: `>=` instead of `==` to avoid pip resolution conflicts
