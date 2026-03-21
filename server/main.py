"""
SENTINEL Backend — FastAPI server with WebSocket endpoint.

This is the entry point. Run with:
    uvicorn main:app --reload --port 8080
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SENTINEL Backend")

# Allow the Vite dev server (frontend) to connect
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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket endpoint. Handles a full session:
    1. Client connects
    2. Client sends start_task
    3. Server streams reasoning/tool_pending/drift events
    4. Client sends tool_decision messages
    5. Server sends session_complete when done

    For now this is a stub — we'll wire up the agent in later tasks.
    """
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            event = data.get("event")

            if event == "start_task":
                # Stub: acknowledge the task for now
                await websocket.send_json({
                    "event": "session_complete",
                    "message": "Server received task (agent not wired yet)",
                })
            elif event == "tool_decision":
                # Will be handled by AirlockGate in task A4
                pass
    except WebSocketDisconnect:
        pass
