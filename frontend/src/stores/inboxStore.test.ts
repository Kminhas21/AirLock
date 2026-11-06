import { beforeEach, describe, expect, it, vi } from "vitest";
import { FORBIDDEN_TTL_MS, useInboxStore } from "./inboxStore";

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

  it("capabilities and the rule toast: stored from events, capabilities reset on any connection change, toast dismissable", () => {
    const st = () => useInboxStore.getState();
    st().handleEvent({ event: "inbox_snapshot", sessions: [], capabilities: { policy_writable: true } });
    expect(st().capabilities.policy_writable).toBe(true);
    st().handleEvent({ event: "inbox_rule_result", ok: true, rule_id: "r", reason: "ok" });
    expect(st().ruleResult).toMatchObject({ ok: true, rule_id: "r" });
    st().clearRuleResult();
    expect(st().ruleResult).toBeNull();
    st().setConnection("disconnected");
    expect(st().capabilities.policy_writable).toBe(false);
    expect(useInboxStore.getState().capabilities).toEqual({ policy_writable: false, can_decide: true });
  });

  it("inbox_forbidden shows a notice that auto-clears; a newer notice restarts the timer", () => {
    vi.useFakeTimers();
    try {
      const st = () => useInboxStore.getState();
      st().handleEvent({ event: "inbox_forbidden", action: "decide", reason: "role" });
      expect(st().forbidden).toEqual({ action: "decide", reason: "role" });
      vi.advanceTimersByTime(FORBIDDEN_TTL_MS - 100);
      st().handleEvent({ event: "inbox_forbidden", action: "rules", reason: "server" });
      vi.advanceTimersByTime(200);
      expect(st().forbidden).toEqual({ action: "rules", reason: "server" });
      vi.advanceTimersByTime(FORBIDDEN_TTL_MS);
      expect(st().forbidden).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("auth: setAuthRequired, auth_ok stores the principal, a connection change clears the principal but not the sign-in requirement", () => {
    const st = () => useInboxStore.getState();
    st().handleEvent({ event: "auth_ok", principal: { id: "alice", tenant: "acme", role: "admin" } });
    expect(st().principal?.id).toBe("alice");
    st().setConnection("disconnected");
    expect(st().principal).toBeNull();
    st().setAuthRequired("throttled");
    st().setConnection("disconnected");
    expect(st().auth).toEqual({ status: "required", reason: "throttled" });
    st().reset();
    expect(st().auth.status).toBe("none");
  });

  it("setConnection and reset", () => {
    useInboxStore.getState().setConnection("connected");
    expect(useInboxStore.getState().connection).toBe("connected");
    useInboxStore.getState().handleEvent(pending);
    useInboxStore.getState().reset();
    expect(useInboxStore.getState().pending).toEqual([]);
  });
});
