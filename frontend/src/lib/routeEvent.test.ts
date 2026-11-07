import { describe, expect, it, vi } from "vitest";
import { routeEvent, type EventHandlers } from "./routeEvent";

function handlers(): EventHandlers {
  return {
    onReasoning: vi.fn(),
    onToolPending: vi.fn(),
    onToolResolved: vi.fn(),
    onDriftUpdate: vi.fn(),
    onAlignmentAlert: vi.fn(),
    setIsRunning: vi.fn(),
    onError: vi.fn(),
    onUnknown: vi.fn(),
  };
}

describe("routeEvent", () => {
  it("stops running on session_complete", () => {
    const h = handlers();
    routeEvent({ event: "session_complete", reason: "finished", message: "", timestamp: "t" }, h);
    expect(h.setIsRunning).toHaveBeenCalledWith(false);
  });
  it("treats legacy task_complete as session_complete", () => {
    const h = handlers();
    routeEvent({ event: "task_complete", timestamp: "t" }, h);
    expect(h.setIsRunning).toHaveBeenCalledWith(false);
  });
  it("on error: stops running and surfaces the message", () => {
    const h = handlers();
    routeEvent({ event: "error", message: "bad key" }, h);
    expect(h.setIsRunning).toHaveBeenCalledWith(false);
    expect(h.onError).toHaveBeenCalledWith("bad key");
  });
  it("dispatches data events to their handlers", () => {
    const h = handlers();
    const e = { event: "reasoning", node_id: "n", parent_id: null, text: "x", timestamp: "t" } as const;
    routeEvent(e, h);
    expect(h.onReasoning).toHaveBeenCalledWith(e);
    expect(h.setIsRunning).not.toHaveBeenCalled();
  });
  it("reports unknown events and non-objects without throwing", () => {
    const h = handlers();
    routeEvent({ event: "bogus" }, h);
    routeEvent(null, h);
    routeEvent("str", h);
    expect(h.onUnknown).toHaveBeenCalledTimes(3);
  });
});
