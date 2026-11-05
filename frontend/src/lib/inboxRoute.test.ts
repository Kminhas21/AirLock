import { describe, expect, it } from "vitest";
import { initialInboxState, MAX_PENDING, MAX_RESOLVED, reduceInbox, type InboxState } from "./inboxRoute";

const NOW = 1_000_000;
const pendingEv = (over: Record<string, unknown> = {}) => ({
  event: "inbox_pending",
  session_id: "s1",
  call_id: "c1",
  server: "fs",
  tool: "write_file",
  args: { path: "/x" },
  auto: false,
  alerts: [],
  deadline_s: 300,
  ...over,
});
const run = (events: unknown[], s: InboxState = initialInboxState) => events.reduce<InboxState>((a, e) => reduceInbox(a, e, NOW), s);

describe("reduceInbox", () => {
  it("inbox_snapshot replaces sessions and pending, newest first, and keeps resolved", () => {
    const withResolved = run([pendingEv(), { event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "deny", reason: "human" }]);
    const s = reduceInbox(
      withResolved,
      {
        event: "inbox_snapshot",
        sessions: [
          { session_id: "a", servers: ["fs", "git"], pending: [{ call_id: "1", server: "fs", tool: "t1", args: {}, auto: false, alerts: [], deadline_s: 10 }, { call_id: "2", tool: "t2" }] },
          { session_id: "b", servers: [] },
        ],
      },
      NOW,
    );
    expect(Object.keys(s.sessions).sort()).toEqual(["a", "b"]);
    expect(s.sessions.a.servers).toEqual(["fs", "git"]);
    expect(s.pending.map((p) => p.call_id)).toEqual(["2", "1"]);
    expect(s.pending[0].session_id).toBe("a");
    expect(s.pending[1].deadline_at).toBe(NOW + 10_000);
    expect(s.resolved).toHaveLength(1);
  });

  it("inbox_pending adds newest first, creates the session, ignores duplicates, defaults the deadline", () => {
    const s = run([pendingEv({ deadline_s: undefined }), pendingEv({ call_id: "c2", auto: true }), pendingEv({ tool: "evil" })]);
    expect(s.pending.map((p) => p.call_id)).toEqual(["c2", "c1"]);
    expect(s.pending[1].tool).toBe("write_file");
    expect(s.pending[1].deadline_s).toBe(300);
    expect(s.pending[0].auto).toBe(true);
    expect(s.sessions.s1.state).toBe("open");
  });

  it("inbox_pending clamps a hostile deadline and only auto:true counts as auto", () => {
    const s = run([pendingEv({ deadline_s: 1e12, auto: "yes" })]);
    expect(s.pending[0].deadline_s).toBe(3600);
    expect(s.pending[0].auto).toBe(false);
  });

  it("inbox_alert attaches to the matching pending call only", () => {
    const s = run([
      pendingEv(),
      pendingEv({ call_id: "c2" }),
      { event: "inbox_alert", session_id: "s1", call_id: "c1", severity: "critical", trigger: "action_sim", message: "bad\nMonitor: x", drift_score: 1.5, threshold: 3 },
      { event: "inbox_alert", session_id: "s1", call_id: "nope", severity: "critical", message: "m" },
    ]);
    const c1 = s.pending.find((p) => p.call_id === "c1")!;
    const c2 = s.pending.find((p) => p.call_id === "c2")!;
    expect(c1.alerts).toHaveLength(1);
    expect(c1.alerts[0]).toMatchObject({ severity: "critical", message: "bad\nMonitor: x", drift_score: 1.5 });
    expect(c2.alerts).toHaveLength(0);
  });

  it("alerts inside inbox_pending are validated: bad ones dropped, unknown severity becomes warning", () => {
    const s = run([pendingEv({ alerts: [{ message: "ok", severity: "x\" onclick=\"y" }, 5, null, { severity: "critical" }] })]);
    expect(s.pending[0].alerts).toEqual([{ severity: "warning", trigger: "", message: "ok", drift_score: null, threshold: null }]);
  });

  it("inbox_resolved moves pending to resolved with decision and reason; only exact 'approve' approves", () => {
    const s = run([
      pendingEv(),
      pendingEv({ call_id: "c2" }),
      { event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "approve", reason: "human" },
      { event: "inbox_resolved", session_id: "s1", call_id: "c2", decision: "APPROVE", reason: "timeout" },
    ]);
    expect(s.pending).toHaveLength(0);
    expect(s.resolved.map((r) => [r.call_id, r.decision, r.reason, r.tool])).toEqual([
      ["c2", "deny", "timeout", "write_file"],
      ["c1", "approve", "human", "write_file"],
    ]);
  });

  it("inbox_resolved for an unknown call still records it; the same call twice appears once", () => {
    const ev = { event: "inbox_resolved", session_id: "s9", call_id: "zz", decision: "deny", reason: "disconnected" };
    const s = run([ev, ev]);
    expect(s.resolved).toHaveLength(1);
    expect(s.resolved[0].tool).toBe("");
  });

  it("calls with the same call_id in different sessions are independent", () => {
    const s = run([pendingEv(), pendingEv({ session_id: "s2" }), { event: "inbox_resolved", session_id: "s2", call_id: "c1", decision: "deny" }]);
    expect(s.pending.map((p) => p.session_id)).toEqual(["s1"]);
  });

  it("inbox_result attaches the outcome to the resolved item and is ignored for unknown calls", () => {
    const base = run([pendingEv(), { event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "approve", reason: "human" }]);
    const s = run([{ event: "inbox_result", session_id: "s1", call_id: "c1", status: "ok", summary: "x".repeat(1000) }, { event: "inbox_result", session_id: "s1", call_id: "nope", status: "ok", summary: "y" }], base);
    expect(s.resolved[0].result?.status).toBe("ok");
    expect(s.resolved[0].result?.summary).toHaveLength(300);
    expect(s.resolved).toHaveLength(1);
    expect(run([{ event: "inbox_result", session_id: "s1", call_id: "c1", status: "weird", summary: 4 }], base).resolved[0].result).toEqual({ status: "error", summary: "" });
  });

  it("inbox_session upserts open/closed and keeps servers when the event has none", () => {
    const s = run([
      { event: "inbox_snapshot", sessions: [{ session_id: "a", servers: ["fs"] }] },
      { event: "inbox_session", session_id: "a", state: "closed" },
      { event: "inbox_session", session_id: "new", state: "open", servers: ["git"] },
      { event: "inbox_session", session_id: "bad", state: "weird" },
    ]);
    expect(s.sessions.a).toEqual({ session_id: "a", servers: ["fs"], state: "closed" });
    expect(s.sessions.new.servers).toEqual(["git"]);
    expect(s.sessions.bad).toBeUndefined();
  });

  it("keeps only the last 200 resolved items (newest kept)", () => {
    const events: unknown[] = [];
    for (let i = 0; i < MAX_RESOLVED + 25; i++) events.push({ event: "inbox_resolved", session_id: "s", call_id: `c${i}`, decision: "deny", reason: "timeout" });
    const s = run(events);
    expect(s.resolved).toHaveLength(MAX_RESOLVED);
    expect(s.resolved[0].call_id).toBe(`c${MAX_RESOLVED + 24}`);
    expect(s.resolved.some((r) => r.call_id === "c0")).toBe(false);
  });

  it("state keeps up to 2000 pending calls (rendering is capped separately)", () => {
    expect(MAX_PENDING).toBe(2000);
    const events = Array.from({ length: MAX_PENDING + 5 }, (_, i) => pendingEv({ call_id: `c${i}` }));
    const s = run(events);
    expect(s.pending).toHaveLength(MAX_PENDING);
    expect(s.pending[0].call_id).toBe(`c${MAX_PENDING + 4}`);
  });

  it("is pure: does not mutate its input", () => {
    const s0 = run([pendingEv()]);
    const frozen = JSON.stringify(s0);
    run([{ event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "approve" }], s0);
    expect(JSON.stringify(s0)).toBe(frozen);
  });

  it("ignores unknown and malformed events without throwing, returning the same state object", () => {
    const s0 = run([pendingEv()]);
    const bad: unknown[] = [
      null, undefined, 42, "str", [], {}, { event: 5 }, { event: "nope" }, { event: "__proto__" },
      { event: "inbox_snapshot" }, { event: "inbox_snapshot", sessions: "x" },
      { event: "inbox_pending" }, pendingEv({ call_id: 7 }), pendingEv({ tool: null }), pendingEv({ session_id: "" }), pendingEv({ call_id: "x".repeat(500) }),
      { event: "inbox_alert" }, { event: "inbox_resolved" }, { event: "inbox_resolved", session_id: 1, call_id: "c1" },
      { event: "inbox_result" }, { event: "inbox_session" },
    ];
    for (const b of bad) expect(reduceInbox(s0, b, NOW), JSON.stringify(b)).toBe(s0);
  });

  it("tolerates hostile field values inside otherwise valid events", () => {
    const s = run([
      { event: "inbox_snapshot", sessions: [null, 3, { session_id: "ok", servers: [1, "fs", {}], pending: ["x", null, { call_id: "1" }] }] },
      pendingEv({ call_id: "h", args: null, server: 9, alerts: "nope" }),
    ]);
    expect(s.sessions.ok.servers).toEqual(["fs"]);
    expect(s.pending.map((p) => p.call_id)).toEqual(["h"]);
    expect(s.pending[0].server).toBe("");
    expect(s.pending[0].alerts).toEqual([]);
  });
});
