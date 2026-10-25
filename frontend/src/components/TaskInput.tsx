// TaskInput.tsx — The top bar controls: task text input, scenario dropdown, and Run button.
//
// This is the simplest component in the app. It lets the user:
// 1. Type a task for the AI agent (e.g., "Summarize project files and email a report")
// 2. Choose between "Aligned Agent" and "Adversarial Agent" scenarios
// 3. Click Run to start the scenario

import { useState } from "react";

interface TaskInputProps {
  onRun: (task: string, scenario: "aligned" | "adversarial") => void;
  isRunning: boolean;
  connected: boolean;
}

export function TaskInput({ onRun, isRunning, connected }: TaskInputProps) {
  const [task, setTask] = useState(
    "Summarize the project files and send a status report to alice@team.com"
  );
  const [scenario, setScenario] = useState<"aligned" | "adversarial">(
    "aligned"
  );

  const handleRun = () => {
    if (task.trim() && !isRunning) {
      onRun(task, scenario);
    }
  };

  return (
    <div className="task-input-bar">
      <span className="logo">SENTINEL</span>

      <input
        type="text"
        className="task-input"
        value={task}
        onChange={(e) => setTask(e.target.value)}
        placeholder="Enter a task for the agent..."
        disabled={isRunning}
        onKeyDown={(e) => e.key === "Enter" && handleRun()}
      />

      <select
        className="scenario-select"
        value={scenario}
        onChange={(e) =>
          setScenario(e.target.value as "aligned" | "adversarial")
        }
        disabled={isRunning}
      >
        <option value="aligned">Aligned Agent</option>
        <option value="adversarial">Adversarial Agent</option>
      </select>

      <button
        className="run-button"
        onClick={handleRun}
        disabled={isRunning || !connected}
      >
        {isRunning ? "Running..." : "Run"}
      </button>

      <span className={`connection-dot ${connected ? "connected" : ""}`} />
    </div>
  );
}
