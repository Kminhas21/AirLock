"""
SENTINEL Backend — FastAPI server with WebSocket endpoint.

This is the entry point. Run with:
    uvicorn main:app --reload --port 8080

Endpoints:
    GET  /health  — Returns {"status": "ok"}
    GET  /models  — Returns list of available models for the frontend dropdown
    WS   /ws      — WebSocket endpoint for the full agent session
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from providers import get_client, list_models, DEFAULT_MODEL
from agent_loop import run_agent_loop
from mock_environment import reset_environment

app = FastAPI(title="SENTINEL Backend")

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
    """Simple health check — hit this to verify the server is running."""
    return {"status": "ok"}


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

    1. Client connects
    2. Client sends a single start_task message with:
       - task: the user's instruction (e.g. "Summarize the project files")
       - scenario: "aligned" or "adversarial" (which system prompt to use)
       - model: model key from /models endpoint (e.g. "claude-sonnet")
       - mode: "live" (real agent) or "replay" (cached demo run)
    3. Server calls run_agent_loop() which takes over the WebSocket:
       - Sends reasoning events (agent thinking)
       - Sends tool_pending events (agent wants to use a tool)
       - Waits for tool_decision messages (human approve/deny)
       - Sends tool_resolved events (tool executed or denied)
       - Sends session_complete when done
    4. Connection closes after session_complete or on error
    """
    await websocket.accept()
    try:
        # Wait for the start_task message
        data = await websocket.receive_json()

        if data.get("event") != "start_task":
            await websocket.send_json({
                "event": "error",
                "message": f"Expected 'start_task' event, got '{data.get('event')}'",
            })
            await websocket.close(code=1008, reason="Expected start_task event")
            return

        # Extract session parameters from start_task
        task = data.get("task", "")
        scenario = data.get("scenario", "aligned")
        model_key = data.get("model", DEFAULT_MODEL)
        mode = data.get("mode", "live")

        # Validate the model key
        try:
            client, model_id = get_client(model_key)
        except KeyError:
            await websocket.send_json({
                "event": "error",
                "message": (
                    f"Unknown model '{model_key}'. "
                    f"Available: {[m['key'] for m in list_models()]}"
                ),
            })
            return

        # Reset mock environment for this session (fresh state)
        reset_environment()

        if mode == "replay":
            # TODO (A6): Stream events from cached_runs JSON files
            await websocket.send_json({
                "event": "error",
                "message": "Replay mode not implemented yet.",
            })
            return

        # Hand off to the agent loop — it owns the WebSocket from here.
        # run_agent_loop sends reasoning/tool_pending/tool_resolved events
        # and reads tool_decision messages directly from the WebSocket.
        await run_agent_loop(
            websocket=websocket,
            client=client,
            model_id=model_id,
            task=task,
            scenario=scenario,
        )

    except WebSocketDisconnect:
        # Client disconnected mid-session (closed browser tab, etc.)
        # This is normal — nothing to do.
        pass
    except Exception as e:
        # Unexpected error — try to notify the client before closing
        try:
            await websocket.send_json({
                "event": "error",
                "message": f"Server error: {str(e)}",
            })
        except Exception:
            pass  # Client already disconnected, can't send
