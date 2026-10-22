// App.tsx — Main application layout.
//
// Structure:
// ┌────────────────────────────────────────────────────────┐
// │ SENTINEL    [task input...............] [▼ Aligned] [▶] │  ← Top bar
// ├──────────────────────────┬─────────────────────────────┤
// │                          │                             │
// │    KILL CHAIN            │     DRIFT MONITOR           │
// │    (55%)                 │     (45%)                   │
// │                          │                             │
// ├──────────────────────────┴─────────────────────────────┤
// │ ⚠ ALIGNMENT ALERT                                      │  ← Alert banner
// └────────────────────────────────────────────────────────┘

import "./App.css";
import { useWebSocket } from "./hooks/useWebSocket";
import { useSessionStore } from "./stores/sessionStore";
import { TaskInput } from "./components/TaskInput";
import { KillChain } from "./components/KillChain";
import { DriftMonitor } from "./components/DriftMonitor";
import { AlertBanner } from "./components/AlertBanner";
import { NodeDetail } from "./components/NodeDetail";
import { ErrorBoundary } from "./components/ErrorBoundary";

function App() {
  // Connect to WebSocket and get the send function
  const { connected, reconnecting, send } = useWebSocket();

  // Read state from the store
  const isRunning = useSessionStore((s) => s.isRunning);
  const setIsRunning = useSessionStore((s) => s.setIsRunning);
  const reset = useSessionStore((s) => s.reset);

  // Handle the Run button click
  const handleRun = (task: string, scenario: "aligned" | "adversarial") => {
    reset(); // Clear any previous session data
    setIsRunning(true);
    send({
      event: "start_task",
      task,
      scenario,
      mode: "live",
    });
  };

  // Handle approve/deny button clicks on kill chain nodes
  const handleDecision = (nodeId: string, decision: "approve" | "deny") => {
    send({
      event: "tool_decision",
      node_id: nodeId,
      decision,
    });
  };

  return (
    <div className="app">
      {/* Top bar with task input, scenario selector, and run button */}
      <TaskInput
        onRun={handleRun}
        isRunning={isRunning}
        connected={connected}
        reconnecting={reconnecting}
      />

      {/* Main content area: two panels side by side */}
      <div className="main-panels">
        <ErrorBoundary name="Kill Chain">
          <KillChain onDecision={handleDecision} />
        </ErrorBoundary>
        <ErrorBoundary name="Drift Monitor">
          <DriftMonitor />
        </ErrorBoundary>
      </div>

      {/* Alert banner at the bottom — only shows when there's an active alert */}
      <AlertBanner />

      {/* Node detail drawer — slides in from the right when a node is selected */}
      <NodeDetail />
    </div>
  );
}

export default App;
