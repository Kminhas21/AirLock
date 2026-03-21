# SENTINEL Frontend — Changelog

All changes to the Bravo (frontend) workstream are documented here so the whole team can follow along.

---

## [Unreleased]

### B1: Project Scaffold (Completed)
- **Created** `frontend/` using Vite + React + TypeScript template
- **Installed dependencies:**
  - `@xyflow/react` — the graph library for the kill chain panel
  - `dagre` + `@types/dagre` — auto-layout algorithm so graph nodes don't overlap
  - `react-plotly.js` + `plotly.js` — 3D scatter plot for drift monitor
  - `zustand` — lightweight state management (simpler than Redux)
  - `ws` — WebSocket library for the mock server (dev dependency)
- **Created** `src/types/contracts.ts` — TypeScript interfaces for every WebSocket message type (reasoning, tool_pending, tool_decision, tool_resolved, drift_update, alignment_alert, start_task)
- **Created** directory structure: `src/components/`, `src/hooks/`, `src/stores/`, `src/types/`
- **Verified** project compiles with zero TypeScript errors

### B2: Mock WebSocket Server (Completed)
- **Created** `frontend/mockServer.cjs` — standalone Node.js WebSocket server for offline development
- **File is `.cjs`** (not `.js`) because Vite sets `"type": "module"` in package.json and the mock server uses CommonJS `require()`
- **Scenario replayed:** reasoning → read_file (low risk) → reasoning → write_file (high risk) → send_email (critical risk)
- **Interactive:** pauses on each tool_pending and waits for approve/deny decision from the UI
- **Denial branch:** if send_email is denied, replays a replan sequence with a write_file workaround, spiking drift scores, and fires an alignment_alert
- **Run with:** `node mockServer.cjs` (starts on ws://localhost:8000/ws)

### B3: WebSocket Hook + Zustand Store (Completed)
- **Created** `src/stores/sessionStore.ts` — central state store using Zustand
  - Holds: nodes, edges, pendingNodeId, driftPoints, alerts, selectedNodeId, isRunning
  - Has handler functions for each event type (reasoning, tool_pending, tool_resolved, drift_update, alignment_alert)
  - Handles graph edge styling: normal solid grey arrows vs dashed red denial fork arrows
  - Marks nodes with alert targets for pulsing red borders
- **Created** `src/hooks/useWebSocket.ts` — custom React hook for WebSocket connection
  - Connects on mount, auto-reconnects after 2s on disconnect
  - Parses incoming JSON and routes to the correct store handler via a switch on `event` field
  - Exposes `send()` function for sending tool_decision and start_task messages
  - Returns `{ connected, send }` for components to use
- **Verified** zero TypeScript errors
