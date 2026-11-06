import { describe, expect, it } from "vitest";
import { decisionFrame, outcomeLabel, ruleRequestFrame, ruleToast, scopesFor, scopeWords, scoreBar } from "./inboxView";

describe("scoreBar", () => {
  it("computes fill and threshold marker with 25% headroom", () => {
    expect(scoreBar(2, 4)).toEqual({ pct: 40, thresholdPct: 80, over: false });
    expect(scoreBar(4, 2)).toEqual({ pct: 80, thresholdPct: 40, over: true });
  });
  it("is clamped to 0..100", () => {
    const b = scoreBar(1e300, 1e-300)!;
    expect(b.pct).toBeLessThanOrEqual(100);
    expect(b.thresholdPct).toBeGreaterThanOrEqual(0);
    expect(scoreBar(0, 3)!.pct).toBe(0);
  });
  it("is null (text only) for missing, NaN, infinite, negative or non-positive-threshold values", () => {
    for (const [s, t] of [[null, 3], [3, null], [NaN, 3], [3, NaN], [Infinity, 3], [3, Infinity], [-1, 3], [1, 0], [1, -2], ["1", 3], [undefined, undefined]] as const)
      expect(scoreBar(s, t), `${s},${t}`).toBeNull();
  });
});

describe("decisionFrame", () => {
  it("deny carries the trimmed note; empty or blank is omitted", () => {
    expect(decisionFrame("s", "c", "deny", "  use /project  ")).toEqual({ event: "inbox_decision", session_id: "s", call_id: "c", decision: "deny", note: "use /project" });
    expect(decisionFrame("s", "c", "deny", "   ")).not.toHaveProperty("note");
    expect(decisionFrame("s", "c", "deny")).not.toHaveProperty("note");
  });
  it("approve NEVER carries a note", () => {
    expect(decisionFrame("s", "c", "approve", "sneaky")).toEqual({ event: "inbox_decision", session_id: "s", call_id: "c", decision: "approve" });
  });
  it("caps the note at 200 characters", () => {
    expect((decisionFrame("s", "c", "deny", "x".repeat(500)) as { note: string }).note).toHaveLength(200);
  });
});

describe("ruleRequestFrame", () => {
  it("builds the confirmed frame for offered combinations", () => {
    expect(ruleRequestFrame("s", "c", "deny", "tool")).toEqual({ event: "inbox_rule_request", session_id: "s", call_id: "c", verdict: "deny", scope: "tool", confirm: true });
    expect(ruleRequestFrame("s", "c", "allow", "exact")).toMatchObject({ verdict: "allow", scope: "exact", confirm: true });
  });
  it("refuses allow + tool (any arguments) and unknown values", () => {
    expect(ruleRequestFrame("s", "c", "allow", "tool")).toBeNull();
    expect(ruleRequestFrame("s", "c", "nope" as never, "exact")).toBeNull();
    expect(scopesFor("allow")).toEqual(["exact", "tool_under"]);
    expect(scopesFor("ask")).toEqual(["exact", "tool_under", "tool"]);
  });
});

describe("words", () => {
  it("scopeWords states the scope", () => {
    expect(scopeWords("allow", "exact", "t", "fs")).toBe('Always allow calls of "t" on server "fs" with exactly these arguments.');
    expect(scopeWords("deny", "tool", "t", "")).toBe('Always deny every call of "t", with any arguments.');
  });
  it("outcomeLabel", () => {
    expect(outcomeLabel("approve", "auto")).toBe("auto-approved");
    expect(outcomeLabel("deny", "timeout")).toBe("timed out (denied)");
    expect(outcomeLabel("deny", "weird\nreason")).toBe("denied (weird reason)");
  });
  it("ruleToast: ok and every closed-set failure, unknown reason generic", () => {
    expect(ruleToast({ ok: true, rule_id: "ui-allow-ab12", reason: "ok" })).toBe("Rule ui-allow-ab12 added (applies to new sessions)");
    for (const r of ["not_writable", "not_confirmed", "unknown_call", "scope_not_allowed", "cannot_build", "invalid_policy", "write_failed", "log_unavailable", "rate_limited"] as const) {
      const t = ruleToast({ ok: false, rule_id: null, reason: r });
      expect(t.startsWith("Rule not added: "), r).toBe(true);
      expect(t).not.toBe("Rule not added");
      expect(t).not.toContain("_");
    }
    expect(ruleToast({ ok: false, rule_id: null, reason: "rate_limited" })).toBe("Rule not added: Too many rule requests; wait a minute");
    // anything outside the closed set (even if it got past the reducer) is generic and never echoed
    for (const raw of ["unknown", "<script>x</script>", "__proto__", "toString", "constructor"])
      expect(ruleToast({ ok: false, rule_id: null, reason: raw as never }), raw).toBe("Rule not added");
  });
});
