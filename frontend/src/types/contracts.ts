// contracts.ts — TypeScript types matching the SENTINEL WebSocket message contracts.
// Every message between frontend and backend has an "event" field that determines its shape.

// ---------- Enums / Unions ----------

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Decision = "approve" | "deny";

// ---------- Server → Client Events ----------

/** Sent when the AI agent produces chain-of-thought reasoning before selecting a tool. */
export interface ReasoningEvent {
  event: "reasoning";
  node_id: string;
  parent_id: string | null;
  text: string;
  timestamp: string;
}

/** Sent when the agent selects a tool but BEFORE it executes. Execution is paused until a decision comes back. */
export interface ToolPendingEvent {
  event: "tool_pending";
  node_id: string;
  parent_id: string | null;
  node_type: "tool_call" | "replan";
  tool_name: string;
  tool_params: Record<string, unknown>;
  risk_level: RiskLevel;
  reasoning_context: string;
  timestamp: string;
}

/** Sent after a tool executes (approved) or is blocked (denied). */
export interface ToolResolvedEvent {
  event: "tool_resolved";
  node_id: string;
  decision: Decision;
  result: string;
  agent_response: string;
  is_replan: boolean;
  timestamp: string;
}

/** Sent after processing each agent step through the Seismograph pipeline. */
export interface DriftUpdateEvent {
  event: "drift_update";
  step_index: number;
  node_id: string;
  coordinates: { x: number; y: number; z: number };
  metrics: {
    compliance_score: number;
    goal_persistence: number;
    hedging_density: number;
    response_length: number;
  };
  mahalanobis_distance: number;
  baseline_breached: boolean;
  timestamp: string;
}

/** Sent when the Seismograph detects behavioral drift or circumvention. */
export interface AlignmentAlertEvent {
  event: "alignment_alert";
  severity: "warning" | "critical";
  trigger: string;
  message: string;
  linked_node_id: string;
  drift_score: number;
  threshold: number;
}

/** Sent when the scenario has finished (all steps processed). */
export interface TaskCompleteEvent {
  event: "task_complete";
  timestamp: string;
}

/** Union of all events the server can send us. */
export type ServerEvent =
  | ReasoningEvent
  | ToolPendingEvent
  | ToolResolvedEvent
  | DriftUpdateEvent
  | AlignmentAlertEvent
  | TaskCompleteEvent;

// ---------- Client → Server Messages ----------

/** Sent when the user clicks Approve or Deny on a pending tool call. */
export interface ToolDecisionMessage {
  event: "tool_decision";
  node_id: string;
  decision: Decision;
}

/** Sent when the user clicks Run to start a scenario. */
export interface StartTaskMessage {
  event: "start_task";
  task: string;
  scenario: "aligned" | "adversarial";
  mode?: "live" | "replay";
}

/** Union of all messages the client can send. */
export type ClientMessage = ToolDecisionMessage | StartTaskMessage;
