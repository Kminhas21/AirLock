import { beforeEach, describe, expect, it } from "vitest";
import { useInboxStore } from "./inboxStore";

const pending = { event: "inbox_pending", session_id: "s1", call_id: "c1", server: "fs", tool: "t", args: {}, auto: false, alerts: [], deadline_s: 30 };

describe("inboxStore", () => {
  beforeEach(() => useInboxStore.getState().reset());

  it("starts empty and disconnected", () => {
    const s = useInboxStore.getState();
    expect(s.pending).toEqual([]);
    expect(s.resolved).toEqual([]);
    expect(s.sessions).toEqual({});
    expect(s.connection).toBe("disconnected");
  });

  it("handleEvent applies reducer transitions", () => {
    const { handleEvent } = useInboxStore.getState();
    handleEvent(pending);
    expect(useInboxStore.getState().pending.map((p) => p.call_id)).toEqual(["c1"]);
    handleEvent({ event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "approve", reason: "human" });
    expect(useInboxStore.getState().pending).toEqual([]);
    expect(useInboxStore.getState().resolved[0]).toMatchObject({ call_id: "c1", decision: "approve" });
  });

  it("malformed events leave the state object untouched", () => {
    useInboxStore.getState().handleEvent(pending);
    const before = useInboxStore.getState();
    useInboxStore.getState().handleEvent({ event: "garbage" });
    useInboxStore.getState().handleEvent(null);
    expect(useInboxStore.getState()).toBe(before);
  });

  it("setConnection and reset", () => {
    useInboxStore.getState().setConnection("connected");
    expect(useInboxStore.getState().connection).toBe("connected");
    useInboxStore.getState().handleEvent(pending);
    useInboxStore.getState().reset();
    expect(useInboxStore.getState().pending).toEqual([]);
  });
});
