"""
SENTINEL Backend — FastAPI server with WebSocket endpoint.

This is the entry point. Run with:
    uvicorn main:app --reload --port 8080

Endpoints:
    GET  /health  — Returns {"status": "ok", "monitor": <ACTIVE monitor>, "embedder": "minilm"|"stub"|"none",
                             "monitor_errors": <count>}
    GET  /models  — Returns list of available models for the frontend dropdown
    WS   /ws      — WebSocket endpoint for the full agent session
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import events
from auth import check_ws_access
from providers import get_client, list_models, DEFAULT_MODEL
from agent_loop import run_agent_loop
from live_drift import monitor_info
import proposal_monitor
from replay import run_replay
from mock_environment import reset_environment

logger = logging.getLogger(__name__)

SCENARIOS = ("aligned", "adversarial")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Load MiniLM (Seismograph + proposal monitor) in the background so the first session does not pay for it.
    proposal_monitor.warm_up_in_background()
    yield


app = FastAPI(title="SENTINEL Backend", lifespan=lifespan)

# Allow the Vite dev server (frontend) to connect.
# Without this, the browser blocks WebSocket connections from localhost:5173
# to localhost:8080 because they're different origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health check; also says which proposal monitor and embedder are ACTIVE (a stub fallback is visible here)."""
    # monitor_info() may load the embedding model on first use, so keep it off the event loop
    return {"status": "ok", **await asyncio.to_thread(monitor_info)}


@app.get("/models")
async def models():
    """
    Returns the list of available models for the frontend dropdown.

    The frontend calls this on page load to populate the model selector.
    Each model has a 'key' (sent back in start_task) and a 'display_name'
    (shown to the user).

    Response format:
    {
        "models": [
            {"key": "claude-sonnet", "display_name": "Claude Sonnet 4"},
            {"key": "deepseek", "display_name": "DeepSeek V3"},
            ...
        ],
        "default": "claude-sonnet"
    }
    """
    return {
        "models": list_models(),
        "default": DEFAULT_MODEL,
    }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket endpoint. Handles a full agent session:

    0. Origin / token are checked BEFORE the handshake is accepted
    1. Client connects
    2. Client sends a single start_task message with:
       - task: the user's instruction (e.g. "Summarize the project files")
       - scenario: "aligned" or "adversarial" (which system prompt to use)
       - model: model key from /models endpoint (live mode only)
       - mode: "live" (real agent) or "replay" (cached demo run, needs no API key)
    3. The agent loop (or replay) takes over the WebSocket and ends with exactly
       one terminal event (session_complete) or an error event
    4. The connection is closed afterwards
    """
    access = check_ws_access(
        websocket.headers.get("origin"),
        websocket.query_params.get("token"),
    )
    if not access.allowed:
        logger.warning("rejected /ws connection: %s", access.reason)
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        data = await websocket.receive_json()

        if not isinstance(data, dict) or data.get("event") != "start_task":
            got = data.get("event") if isinstance(data, dict) else type(data).__name__
            await websocket.send_json(events.error(f"Expected 'start_task' event, got '{got}'"))
            await websocket.close(code=1008, reason="Expected start_task event")
            return

        task = data.get("task", "")
        scenario = data.get("scenario", "aligned")
        model_key = data.get("model", DEFAULT_MODEL)
        mode = data.get("mode", "live")

        if scenario not in SCENARIOS:
            await websocket.send_json(events.error(f"Unknown scenario. Available: {list(SCENARIOS)}"))
            return
        if mode not in ("live", "replay"):
            await websocket.send_json(events.error("Unknown mode. Available: ['live', 'replay']"))
            return

        # Fresh mock environment for THIS session (per-task ContextVar, so
        # concurrent sessions cannot clobber each other)
        reset_environment()

        if mode == "replay":
            # Replay never touches a model, so it must not require a valid key
            await run_replay(websocket, scenario=scenario)
            return

        try:
            client, model_id = get_client(model_key)
        except KeyError:
            await websocket.send_json(events.error(
                f"Unknown model '{model_key}'. Available: {[m['key'] for m in list_models()]}"
            ))
            return

        if not isinstance(task, str) or not task.strip():
            await websocket.send_json(events.error("start_task requires a non-empty 'task'"))
            return

        await run_agent_loop(
            websocket=websocket,
            client=client,
            model_id=model_id,
            task=task,
            scenario=scenario,
        )

    except WebSocketDisconnect:
        # Client went away mid-session; in-memory state is dropped (known limitation)
        logger.info("client disconnected mid-session")
    except Exception:
        # Details go to the server log only; never echo exception text to the client
        logger.exception("unexpected server error in /ws session")
        try:
            await websocket.send_json(events.error("Internal server error."))
        except Exception:
            pass  # Client already disconnected
    finally:
        try:
            await websocket.close()
        except Exception:
            pass  # Already closed
