// routeEvent.ts — pure dispatch from a parsed server message to handlers.

import type {
  AlignmentAlertEvent,
  DriftUpdateEvent,
  ReasoningEvent,
  ToolPendingEvent,
  ToolResolvedEvent,
} from "../types/contracts";

export interface EventHandlers {
  onReasoning: (e: ReasoningEvent) => void;
  onToolPending: (e: ToolPendingEvent) => void;
  onToolResolved: (e: ToolResolvedEvent) => void;
  onDriftUpdate: (e: DriftUpdateEvent) => void;
  onAlignmentAlert: (e: AlignmentAlertEvent) => void;
  setIsRunning: (running: boolean) => void;
  onError: (message: string) => void;
  onUnknown: (data: unknown) => void;
}

export function routeEvent(data: unknown, h: EventHandlers): void {
  if (typeof data !== "object" || data === null || !("event" in data)) {
    h.onUnknown(data);
    return;
  }
  const msg = data as { event: unknown; message?: unknown };
  switch (msg.event) {
    case "reasoning":
      h.onReasoning(data as ReasoningEvent);
      break;
    case "tool_pending":
      h.onToolPending(data as ToolPendingEvent);
      break;
    case "tool_resolved":
      h.onToolResolved(data as ToolResolvedEvent);
      break;
    case "drift_update":
      h.onDriftUpdate(data as DriftUpdateEvent);
      break;
    case "alignment_alert":
      h.onAlignmentAlert(data as AlignmentAlertEvent);
      break;
    case "session_complete":
    case "task_complete": // legacy alias (mockServer.cjs)
      h.setIsRunning(false);
      break;
    case "error":
      h.setIsRunning(false);
      h.onError(typeof msg.message === "string" ? msg.message : "Unknown server error");
      break;
    default:
      h.onUnknown(data);
  }
}
