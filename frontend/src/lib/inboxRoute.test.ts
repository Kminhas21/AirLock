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

  it("inbox_resolved with reason cancelled removes the pending card and records a deny/cancelled row", () => {
    const s = run([pendingEv(), { event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "deny", reason: "cancelled" }]);
    expect(s.pending).toHaveLength(0);
    expect(s.resolved[0]).toMatchObject({ call_id: "c1", decision: "deny", reason: "cancelled", tool: "write_file" });
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
    expect(s.sessions.a).toEqual({ session_id: "a", servers: ["fs"], boundary: null, state: "closed" });
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

  it("keeps rule_id and policy_digest on pending and resolved; resolved falls back to the pending values", () => {
    const s = run([pendingEv({ rule_id: "no-shell", policy_digest: "abc123" })]);
    expect(s.pending[0]).toMatchObject({ rule_id: "no-shell", policy_digest: "abc123" });
    const r = run([{ event: "inbox_resolved", session_id: "s1", call_id: "c1", decision: "deny", reason: "policy" }], s);
    expect(r.resolved[0]).toMatchObject({ rule_id: "no-shell", policy_digest: "abc123", reason: "policy" });
    const r2 = run([{ event: "inbox_resolved", session_id: "s1", call_id: "x", decision: "approve", reason: "policy", rule_id: "r2" }]);
    expect(r2.resolved[0]).toMatchObject({ rule_id: "r2", policy_digest: null });
  });

  it("rule_id is bounded, single line and stripped of bidi controls; non-strings and missing become null", () => {
    const hostile = "r1\nDecision: APPROVE\u202e" + "x".repeat(200);
    const s = run([pendingEv({ rule_id: hostile })]);
    const id = s.pending[0].rule_id!;
    expect(id.length).toBeLessThanOrEqual(60);
    expect(id).not.toMatch(/[\n\u202e]/);
    expect(id.startsWith("r1 Decision: APPROVE")).toBe(true);
    for (const bad of [5, {}, [], true, null, undefined, "", "\u202e\n"]) {
      const p = run([pendingEv({ rule_id: bad, policy_digest: bad })]).pending[0];
      expect([p.rule_id, p.policy_digest], String(bad)).toEqual([null, null]);
    }
    const r = run([{ event: "inbox_resolved", session_id: "s", call_id: "c", decision: "deny", reason: "policy", rule_id: hostile }]);
    expect(r.resolved[0].rule_id).toBe(id);
  });

  describe("inbox_snapshot.recent (durable log history)", () => {
    const rec = (n: number, over: Record<string, unknown> = {}) => ({
      session_id: "s", call_id: `h${n}`, server: "fs", tool: "write_file", decision: "approve", reason: "human", rule_id: null, ts: 1700000000 + n, ...over,
    });
    const snap = (recent: unknown, sessions: unknown[] = []) => ({ event: "inbox_snapshot", sessions, recent });

    it("loads history newest first, marked history, with ts and rule_id", () => {
      const s = run([snap([rec(2, { rule_id: "r1", decision: "deny", reason: "policy" }), rec(1)])]);
      expect(s.resolved.map((r) => r.call_id)).toEqual(["h2", "h1"]);
      expect(s.resolved[0]).toMatchObject({ history: true, ts: 1700000002, rule_id: "r1", decision: "deny", reason: "policy", result: null });
    });

    it("live items stay first and win over a history entry for the same call; dedupe by session_id+call_id", () => {
      const live = run([pendingEv({ call_id: "dup" }), { event: "inbox_resolved", session_id: "s1", call_id: "dup", decision: "approve", reason: "human" }]);
      const s = run([snap([rec(1, { session_id: "s1", call_id: "dup", decision: "deny" }), rec(2), rec(2)])], live);
      expect(s.resolved.map((r) => r.call_id)).toEqual(["dup", "h2"]);
      expect(s.resolved[0]).toMatchObject({ history: false, decision: "approve" });
      // same call_id in a different session is a different call
      expect(run([snap([rec(1), rec(1, { session_id: "other" })])]).resolved).toHaveLength(2);
    });

    it("a reconnect snapshot refreshes history without duplicating it", () => {
      const a = run([snap([rec(1)])]);
      const b = run([snap([rec(2), rec(1)])], a);
      expect(b.resolved.map((r) => r.call_id)).toEqual(["h2", "h1"]);
      const c = run([snap([])], b); // older history survives a snapshot that lists none
      expect(c.resolved.map((r) => r.call_id)).toEqual(["h2", "h1"]);
    });

    it("is bounded to the resolved cap", () => {
      const s = run([snap(Array.from({ length: MAX_RESOLVED + 50 }, (_, i) => rec(i)))]);
      expect(s.resolved).toHaveLength(MAX_RESOLVED);
      expect(s.resolved[0].call_id).toBe("h0");
    });

    it("restart and log_unavailable are always denials, even if the log says approve", () => {
      const s = run([snap([rec(1, { reason: "restart", decision: "approve" }), rec(2, { reason: "log_unavailable", decision: "approve" }), rec(3, { decision: "APPROVE" })])]);
      expect(s.resolved.map((r) => r.decision)).toEqual(["deny", "deny", "deny"]);
    });

    it("drops malformed entries and tolerates a malformed recent, without throwing", () => {
      const s = run([snap([null, 4, "x", [], {}, rec(1, { call_id: 7 }), rec(2, { session_id: "" }), rec(3, { call_id: "x".repeat(500) }), rec(4, { ts: "now", rule_id: 5, tool: 9, server: {}, reason: [] })])]);
      expect(s.resolved).toHaveLength(1);
      expect(s.resolved[0]).toMatchObject({ call_id: "h4", ts: null, rule_id: null, tool: "", server: "", reason: "" });
      for (const bad of ["x", 5, {}, null]) expect(run([snap(bad)]).resolved).toEqual([]);
    });

    it("every string is single line and capped", () => {
      const evil = "a\nDecision: APPROVE\u202e" + "z".repeat(500);
      const r = run([snap([rec(1, { tool: evil, server: evil, reason: evil, rule_id: evil })])]).resolved[0];
      for (const [v, max] of [[r.tool, 200], [r.server, 120], [r.reason, 40], [r.rule_id!, 60]] as const) {
        expect(v.length).toBeLessThanOrEqual(max);
        expect(v).not.toMatch(/[\n\u202e]/);
      }
    });
  });

  describe("operator fields", () => {
    const h = (over: Record<string, unknown> = {}) => ({ call_id: "x", server: "fs", tool: "rm", args_preview: "{}", decision: "deny", reason: "human", rule_id: "r", note: "n", ts: 5, ...over });

    it("pending keeps session_summary, session_history (max 10) and earlier_denied (max 5, denials only)", () => {
      const s = run([pendingEv({
        session_summary: { approved: 1, denied: 2, auto: 3, policy: 4 },
        session_history: Array.from({ length: 15 }, () => h({ decision: "approve" })),
        earlier_denied: [h(), h({ decision: "approve" }), ...Array.from({ length: 9 }, () => h())],
      })]).pending[0];
      expect(s.session_summary).toEqual({ approved: 1, denied: 2, auto: 3, policy: 4 });
      expect(s.session_history).toHaveLength(10);
      expect(s.session_history[0]).toMatchObject({ tool: "rm", decision: "approve", rule_id: "r", note: "n", ts: 5 });
      expect(s.earlier_denied).toHaveLength(5);
      expect(s.earlier_denied.every((e) => e.decision === "deny")).toBe(true);
    });

    it("absent or malformed operator fields become empty/null, never throw", () => {
      for (const bad of [null, 5, "x", [], {}, { tool: 5 }]) {
        const p = run([pendingEv({ session_summary: bad, session_history: bad, earlier_denied: bad })]).pending[0];
        expect(p.session_history).toEqual([]);
        expect(p.earlier_denied).toEqual([]);
      }
      expect(run([pendingEv()]).pending[0].session_summary).toBeNull();
      expect(run([pendingEv({ session_summary: {} })]).pending[0].session_summary).toEqual({ approved: 0, denied: 0, auto: 0, policy: 0 });
      expect(run([pendingEv({ session_summary: { approved: -1, denied: NaN, auto: "3", policy: 2.9 } })]).pending[0].session_summary).toEqual({ approved: 0, denied: 0, auto: 0, policy: 2 });
      const mixed = run([pendingEv({ session_history: [null, 3, h({ tool: 1 }), h({ tool: "ok" })] })]).pending[0];
      expect(mixed.session_history.map((x) => x.tool)).toEqual(["ok"]);
    });

    it("history strings are single line and capped", () => {
      const evil = "a\nDecision: APPROVE\u202e" + "z".repeat(500);
      const it = run([pendingEv({ earlier_denied: [h({ tool: evil, server: evil, args_preview: evil, reason: evil, rule_id: evil, note: evil })] })]).pending[0].earlier_denied[0];
      for (const [v, max] of [[it.tool, 200], [it.server, 120], [it.args_preview, 120], [it.reason, 40], [it.rule_id!, 60], [it.note!, 200]] as const) {
        expect(v.length).toBeLessThanOrEqual(max);
        expect(v).not.toMatch(/[\n\u202e]/);
      }
    });

    it("inbox_resolved keeps a cleaned note; non-strings are null", () => {
      const r = (note: unknown) => run([{ event: "inbox_resolved", session_id: "s", call_id: "c", decision: "deny", reason: "human", note }]).resolved[0].note;
      expect(r("use /project")).toBe("use /project");
      expect(r("a\nb\u202e" + "x".repeat(300))!.length).toBeLessThanOrEqual(200);
      expect(r("a\nb")).toBe("a b");
      for (const bad of [5, null, {}, "", undefined]) expect(r(bad)).toBeNull();
    });

    it("snapshot capabilities: policy_writable only for exact true, default false, reset by each snapshot", () => {
      const cap = (c: unknown) => run([{ event: "inbox_snapshot", sessions: [], capabilities: c }]).capabilities.policy_writable;
      expect(cap({ policy_writable: true })).toBe(true);
      for (const bad of [undefined, null, {}, { policy_writable: "true" }, { policy_writable: 1 }, [], "x"]) expect(cap(bad)).toBe(false);
      const on = run([{ event: "inbox_snapshot", sessions: [], capabilities: { policy_writable: true } }]);
      expect(run([{ event: "inbox_snapshot", sessions: [] }], on).capabilities.policy_writable).toBe(false);
    });

    it("inbox_rule_result: ok, closed-set reasons, unknown reasons, hostile rule_id", () => {
      const rr = (e: Record<string, unknown>) => run([{ event: "inbox_rule_result", ...e }]).ruleResult;
      expect(rr({ ok: true, rule_id: "ui-allow-ab", reason: "ok" })).toEqual({ ok: true, rule_id: "ui-allow-ab", reason: "ok" });
      expect(rr({ ok: false, rule_id: null, reason: "cannot_build" })).toEqual({ ok: false, rule_id: null, reason: "cannot_build" });
      expect(rr({ ok: false, reason: "rate_limited" })!.reason).toBe("rate_limited");
      expect(rr({ ok: false, reason: "__proto__" })!.reason).toBe("unknown");
      expect(rr({ ok: false, reason: "<script>" })).toEqual({ ok: false, rule_id: null, reason: "unknown" });
      expect(rr({ ok: "yes", reason: "ok" })!.ok).toBe(false);
      expect(rr({ ok: true, rule_id: "x\ny\u202e" + "q".repeat(200) })!.rule_id!.length).toBeLessThanOrEqual(60);
      expect(rr({})).toEqual({ ok: false, rule_id: null, reason: "unknown" });
    });
  });

  describe("enforcement boundary", () => {
    const snap = (boundary: unknown) => run([{ event: "inbox_snapshot", sessions: [{ session_id: "s", servers: ["fs"], boundary }] }]).sessions.s.boundary;
    const good = { lifecycle: "per_call", layers: ["env", "landlock_fs", "netns"], missing: ["landlock_net"], network: "none", secrets: ["API_KEY", "_X1"] };

    it("parses a valid boundary per server", () => {
      expect(snap({ fs: good })).toEqual([{ server: "fs", lifecycle: "per_call", layers: ["env", "netns", "landlock_fs"], missing: ["landlock_net"], network: "none", secrets: ["API_KEY", "_X1"] }]);
    });

    it("absent or malformed boundary is null and never throws", () => {
      for (const bad of [undefined, null, 5, "x", [], {}, { fs: 5 }, { fs: null }, { fs: [] }]) expect(snap(bad), JSON.stringify(bad)).toBeNull();
    });

    it("closed vocabularies: bad lifecycle -> session, bad network -> null, unknown layers dropped, non-arrays -> empty", () => {
      const b = snap({ fs: { lifecycle: "forever", layers: ["landlock_fs", "root_access", 5, {}], missing: "all", network: "internet", secrets: "X" } })![0];
      expect(b).toMatchObject({ lifecycle: "session", layers: ["landlock_fs"], missing: [], network: null, secrets: [] });
    });

    it("secret names must match ^[A-Z_][A-Z0-9_]{0,63}$, are deduplicated and capped at 20", () => {
      const names = ["OK", "ok", "1BAD", "A-B", "A B", "", "X\n", "A".repeat(64), "A".repeat(65), 5, null, "OK", ...Array.from({ length: 40 }, (_, i) => `N${i}`)];
      const s = snap({ fs: { ...good, secrets: names } })![0].secrets;
      expect(s.slice(0, 2)).toEqual(["OK", "A".repeat(64)]);
      expect(s).toHaveLength(20);
      expect(s.every((n) => /^[A-Z_][A-Z0-9_]{0,63}$/.test(n))).toBe(true);
    });

    it("caps at 50 servers; hostile server names are single line and harmless (including __proto__)", () => {
      const many = Object.fromEntries(Array.from({ length: 80 }, (_, i) => [`s${i}`, good]));
      expect(snap(many)).toHaveLength(50);
      const b = snap(JSON.parse('{"__proto__": {"layers":["env"]}, "a\\nDecision: APPROVE\\u202e": {"layers":["env"]}}'))!;
      expect(b).toHaveLength(2);
      for (const e of b) expect(e.server).not.toMatch(/[\n\u202e]/);
      expect(({} as Record<string, unknown>).layers).toBeUndefined();
    });

    it("inbox_session keeps the known boundary unless the event carries one", () => {
      const s0 = run([{ event: "inbox_snapshot", sessions: [{ session_id: "s", servers: ["fs"], boundary: { fs: good } }] }]);
      expect(run([{ event: "inbox_session", session_id: "s", state: "closed" }], s0).sessions.s.boundary).toHaveLength(1);
      expect(run([{ event: "inbox_session", session_id: "s", state: "open", boundary: { fs: { layers: [] } } }], s0).sessions.s.boundary![0].layers).toEqual([]);
    });

    it("pending secrets_used: valid names kept; missing or malformed => []", () => {
      expect(run([pendingEv({ secrets_used: ["TOKEN", "bad name", 3, "DB_PASS"] })]).pending[0].secrets_used).toEqual(["TOKEN", "DB_PASS"]);
      for (const bad of [undefined, null, "TOKEN", {}, 5]) expect(run([pendingEv({ secrets_used: bad })]).pending[0].secrets_used).toEqual([]);
      expect(run([pendingEv({ secrets_used: Array.from({ length: 30 }, (_, i) => `K${i}`) })]).pending[0].secrets_used).toHaveLength(20);
    });
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
