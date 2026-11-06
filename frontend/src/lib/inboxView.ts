// inboxView.ts — pure helpers for the Inbox cards: the score bar, outcome words, outgoing frames and toast texts.
// The UI never composes a policy rule: it only asks the hub for a (verdict, scope) on a call the hub has seen.

import type { RuleResult } from "./inboxRoute";
import { singleLine } from "./safeText";

export const MAX_NOTE = 200;

// ---------- score-vs-threshold bar ----------

export interface ScoreBar {
  /** Bar fill, 0..100. */
  pct: number;
  /** Threshold marker position, 0..100. */
  thresholdPct: number;
  over: boolean;
}

/** null (text only) unless both numbers are finite, score >= 0 and threshold > 0. The scale leaves 25% headroom past the larger value. */
export function scoreBar(score: unknown, threshold: unknown): ScoreBar | null {
  if (typeof score !== "number" || typeof threshold !== "number") return null;
  if (!Number.isFinite(score) || !Number.isFinite(threshold) || score < 0 || threshold <= 0) return null;
  const scale = Math.max(score, threshold) * 1.25;
  const clamp = (n: number) => Math.min(100, Math.max(0, n));
  return { pct: clamp((score / scale) * 100), thresholdPct: clamp((threshold / scale) * 100), over: score > threshold };
}

// ---------- outcome words ----------

export function outcomeLabel(decision: string, reason: string): string {
  const approved = decision === "approve";
  if (reason === "policy") return approved ? "allowed by policy" : "denied by policy";
  if (reason === "auto") return "auto-approved";
  if (reason === "cancelled") return "cancelled";
  if (reason === "timeout") return approved ? "approved (timeout)" : "timed out (denied)";
  if (reason === "human" || reason === "") return approved ? "approved" : "denied";
  return `${approved ? "approved" : "denied"} (${singleLine(reason, 40)})`;
}

// ---------- outgoing frames ----------

/** Deny carries the trimmed note (omitted when empty); Approve NEVER carries a note. */
export function decisionFrame(sessionId: string, callId: string, decision: "approve" | "deny", note?: string) {
  const base = { event: "inbox_decision" as const, session_id: sessionId, call_id: callId, decision };
  const n = decision === "deny" && typeof note === "string" ? note.trim().slice(0, MAX_NOTE).trim() : "";
  return n ? { ...base, note: n } : base;
}

export type Verdict = "allow" | "deny" | "ask";
export type Scope = "exact" | "tool_under" | "tool";

/** The scopes the UI offers (and the hub accepts) per verdict: allow never gets "tool" (any arguments). */
export function scopesFor(verdict: Verdict): Scope[] {
  return verdict === "allow" ? ["exact", "tool_under"] : ["exact", "tool_under", "tool"];
}

/** null when the combination is not offered. confirm is always true: this frame is only built from the confirm step. */
export function ruleRequestFrame(sessionId: string, callId: string, verdict: Verdict, scope: Scope) {
  if (!scopesFor(verdict).includes(scope)) return null;
  return { event: "inbox_rule_request" as const, session_id: sessionId, call_id: callId, verdict, scope, confirm: true as const };
}

const VERB: Record<Verdict, string> = { allow: "allow", deny: "deny", ask: "ask a human about" };

/** The scope in plain words, for the confirm step. */
export function scopeWords(verdict: Verdict, scope: Scope, tool: string, server: string): string {
  const t = `"${singleLine(tool, 80)}"`;
  const s = server ? ` on server "${singleLine(server, 60)}"` : "";
  const what =
    scope === "exact"
      ? `calls of ${t}${s} with exactly these arguments`
      : scope === "tool_under"
        ? `calls of ${t}${s} whose path argument is under the same folder`
        : `every call of ${t}${s}, with any arguments`;
  return `Always ${VERB[verdict]} ${what}.`;
}

export const SCOPE_LABEL: Record<Scope, string> = {
  exact: "exact arguments",
  tool_under: "this tool under the same folder",
  tool: "this tool, any arguments",
};

// ---------- toast ----------

const FAIL_WORDS: Record<string, string> = {
  not_writable: "the policy file is not writable (standing rules are switched off on the backend)",
  not_confirmed: "the request was not confirmed",
  unknown_call: "the backend no longer knows this call",
  scope_not_allowed: "that scope is not allowed for this verdict",
  cannot_build: "a rule cannot be built from this call's arguments",
  invalid_policy: "the resulting policy would be invalid",
  write_failed: "writing the policy file failed",
  log_unavailable: "the event log is unavailable",
};

export function ruleToast(r: RuleResult): string {
  if (r.ok) return `Rule ${r.rule_id ? singleLine(r.rule_id, 60) : "(unnamed)"} added (applies to new sessions)`;
  return `Rule not added: ${FAIL_WORDS[r.reason] ?? "unknown reason"}`;
}
