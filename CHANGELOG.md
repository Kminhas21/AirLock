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

### B4: App Layout (Completed)
- **Replaced** Vite boilerplate App.tsx with SENTINEL layout: top bar → two-panel grid → alert banner
- **Created** `src/components/TaskInput.tsx` — top bar with task input, scenario dropdown (aligned/adversarial), Run button, connection indicator dot
- **Created** placeholder `KillChain.tsx` — renders nodes as a simple list with approve/deny buttons (will become react-flow graph in B5)
- **Created** placeholder `DriftMonitor.tsx` — renders drift data as text (will become Plotly charts in B6)
- **Created** placeholder `AlertBanner.tsx` — slide-up alert bar (will be polished in B7)
- **Replaced** `index.css` — dark theme global reset (#0f1117 background, full viewport)
- **Replaced** `App.css` — complete styling: dark panels, color-coded nodes, green/red action buttons, CSS grid layout (55%/45% split)
- **App is now fully functional** with the mock server — you can run scenarios and approve/deny tool calls
- **Verified** TypeScript compiles and production build succeeds

### B5: Kill Chain Graph (Completed)
- **Replaced** placeholder KillChain.tsx with full `@xyflow/react` implementation
- **3 custom node types:**
  - `ReasoningNode` — blue left border, shows truncated chain-of-thought text
  - `ToolNode` — amber (medium risk) or red (high/critical risk), shows tool name + params, Approve/Deny buttons when pending, decision badge after resolved
  - `ReplanNode` — wraps ToolNode with dashed orange border to indicate post-denial replan
- **dagre auto-layout** — automatically positions nodes top-to-bottom with proper spacing; recalculates every time a node is added
- **Edge styling:** solid grey for normal flow, dashed red animated for denial forks
- **Interactive features:**
  - Click any node to select it (blue highlight ring) — will connect to NodeDetail drawer in B7
  - Approve/Deny buttons only appear on the currently pending node
  - Pulsing red glow on nodes targeted by alignment alerts
  - Auto-fits viewport as nodes are added
- **CustomEvent pattern** — custom nodes use `window.dispatchEvent` to send approve/deny decisions back up to App.tsx, since react-flow custom nodes can't receive props directly
- **Updated** App.css with react-flow node styles (replaced old placeholder node styles)
- **Verified** TypeScript + production build pass
