# PLANS.md — SENTINEL Project Direction

This file tracks the current architectural direction and any deviations from the original SENTINEL_PLAN_v2.md.

---

## Major Architectural Change: LangChain Removed

**Decision date:** 2026-03-21
**Reason:** LangChain adds unnecessary complexity. The agentic loop is ~60 lines of Python. LangChain's agent executors, callback handlers, and tool decorators obscure what's actually simple logic. The asyncio.Event gate pattern required by LangChain's architecture is fragile and hard to debug.

### What Changed

| Before (Original Plan) | After (Current Direction) |
|------------------------|--------------------------|
| LangChain + `langchain-openai` + `langchain-core` | OpenAI Python SDK (`openai`) only |
| `create_openai_tools_agent` + `AgentExecutor` | Hand-written `while True` loop in `agent_loop.py` |
| `@tool` decorators on mock functions | OpenAI JSON function-calling schemas in `tools.py` |
| `asyncio.Event()` gate with pending dicts + background tasks | `await websocket.receive_json()` — the WebSocket receive IS the gate |
| GPT-4o-mini via OpenAI API | Any model via OpenRouter (Claude Sonnet, GPT-4o, DeepSeek, etc.) |
| Single hardcoded model | Model dropdown — frontend selects model via `GET /models` |
| 4 tools (read_file, write_file, send_email, query_database) | 6 tools (+ run_shell_command, create_github_issue) |
| 5 hardcoded files in MOCK_FS | 15+ realistic project files |

### New File Structure (server/)

```
server/
├── main.py              # FastAPI app, /health, /models, /ws endpoint
├── agent_loop.py        # Core agentic while-loop with airlock gate built in
├── providers.py         # Model registry (OpenRouter + optional Ollama)
├── tools.py             # 6 tool schemas (OpenAI JSON format) + execute_tool()
├── mock_environment.py  # Rich in-memory mock data (replaces mock_tools.py)
├── risk_scorer.py       # tool_name → risk_level lookup
├── requirements.txt     # fastapi, uvicorn, websockets, openai, python-dotenv
└── .env                 # OPENROUTER_API_KEY
```

### Default Model

`anthropic/claude-sonnet-4-6` via OpenRouter. Can be swapped to `deepseek/deepseek-chat` or any other OpenRouter model by changing one string.

---

## Other Deviations from Original Plan

### Port 8080 (not 8000)
Windows 11 Hyper-V reserves port 8000. All references to the backend use port 8080.
**Impact on Bravo (frontend):** WebSocket URL is `ws://localhost:8080/ws`

### Relaxed Dependency Versions
Using `>=` instead of `==` pins. The original plan's exact pins had pip resolution conflicts.

---

## What Has NOT Changed

- **WebSocket message contracts** — all event types (reasoning, tool_pending, tool_decision, tool_resolved, drift_update, alignment_alert) use the exact same JSON schemas
- **Frontend architecture** — React + @xyflow/react + Plotly + Zustand, unchanged
- **Seismograph pipeline** — Charlie's module is unchanged, Alpha imports it at integration time
- **Dual scenarios** — aligned vs adversarial system prompts, same concept
- **Replay mode** — cached JSON runs for demo safety net
- **Overall data flow** — start_task → reasoning → tool_pending → decision → tool_resolved → drift_update → session_complete

---

## Data Flow (Updated)

```
Frontend sends: start_task {task, scenario, model, mode}
    ↓
Server gets model client from providers.py
    ↓
agent_loop.py runs the while-loop:
    ↓
Call LLM (via OpenRouter) with messages + tool schemas
    ↓
If text content → emit "reasoning" event → frontend shows blue node
    ↓
If tool_calls → for each tool:
    emit "tool_pending" → frontend shows colored node with Approve/Deny buttons
    await websocket.receive_json() ← BLOCKS here until human decides
    if approved: execute tool via tools.py → mock_environment.py
    if denied: return denial string to LLM
    emit "tool_resolved"
    ↓
LLM sees tool results → decides next action → loop continues
    ↓
When LLM stops calling tools → emit "session_complete"
```

---

## Task Progress — Part A (Backend)

- [x] A1: Project setup (FastAPI scaffold, /health, /ws stub, CORS, port 8080)
- [x] A2: Foundation (requirements, providers, mock_environment, tools, risk_scorer)
- [x] A3: Basic agent loop (terminal test via OpenRouter with Claude Sonnet 4)
- [x] A4: Airlock gate (WebSocket integration, main.py rewrite, /models endpoint, test client)
- [x] A5: Dual scenarios (aligned + adversarial prompts — built into A3/A4)
- [ ] A6: Seismograph stub + replay mode
