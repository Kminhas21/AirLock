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

  it("snapshotReceived: false until a snapshot, reset by every connection change", () => {
    const st = () => useInboxStore.getState();
    st().setConnection("connected");
    expect(st().snapshotReceived).toBe(false);
    st().handleEvent(pending);
    expect(st().snapshotReceived).toBe(false);
    st().handleEvent({ event: "inbox_snapshot", sessions: "bad" });
    expect(st().snapshotReceived).toBe(false);
    st().handleEvent({ event: "inbox_snapshot", sessions: [] });
    expect(st().snapshotReceived).toBe(true);
    st().setConnection("disconnected");
    expect(st().snapshotReceived).toBe(false);
  });

  it("notSent is set per call, and cleared by the next snapshot", () => {
    const st = () => useInboxStore.getState();
    st().markNotSent("s/c", true);
    expect(st().notSent).toEqual({ "s/c": true });
    st().markNotSent("s/c", false);
    expect(st().notSent).toEqual({});
    st().markNotSent("s/c", true);
    st().handleEvent({ event: "inbox_snapshot", sessions: [] });
    expect(st().notSent).toEqual({});
  });

  it("setConnection and reset", () => {
    useInboxStore.getState().setConnection("connected");
    expect(useInboxStore.getState().connection).toBe("connected");
    useInboxStore.getState().handleEvent(pending);
    useInboxStore.getState().reset();
    expect(useInboxStore.getState().pending).toEqual([]);
  });
});
