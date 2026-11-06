// inboxRoute.ts — pure reducer for the /inbox/ws UI events (see docs/plans/PROPOSAL-1-mcp-proxy.md).
//
// Everything on the wire is untrusted (the agent controls tool names, args, summaries). The reducer validates the
// shape of each event, coerces fields to plain strings/numbers, and ignores anything else WITHOUT throwing.
// Display-time sanitising (singleLine / AgentText) happens in the components.

import { singleLine } from "./safeText";

export const MAX_RESOLVED = 200;
export const MAX_PENDING = 2000;
/** The Inbox renders at most this many pending cards; the rest are counted in a visible "N more pending not shown" line. */
export const MAX_PENDING_RENDERED = 500;
export const MAX_SESSIONS = 200;
const DEFAULT_DEADLINE_S = 300;
const MAX_DEADLINE_S = 3600;
const MAX_ALERTS = 20;

export type InboxDecision = "approve" | "deny";

export interface InboxAlert {
  severity: "warning" | "critical";
  trigger: string;
  message: string;
  drift_score: number | null;
  threshold: number | null;
}

export const BOUNDARY_LAYERS = ["env", "rlimit", "no_new_privs", "netns", "landlock_net", "landlock_fs"] as const;
export type BoundaryLayer = (typeof BOUNDARY_LAYERS)[number];
export type BoundaryNetwork = "none" | "loopback" | "host";
export const MAX_BOUNDARY_SERVERS = 50;
export const MAX_SECRET_NAMES = 20;

export interface ServerBoundary {
  server: string;
  lifecycle: "session" | "per_call";
  layers: BoundaryLayer[];
  missing: BoundaryLayer[];
  /** null when the report had no valid value: the UI then makes no network claim. */
  network: BoundaryNetwork | null;
  /** Env-var NAMES the server may receive (never values). */
  secrets: string[];
}

export interface InboxSession {
  session_id: string;
  servers: string[];
  /** Enforcement boundary reported by the proxy; null = no (valid) boundary info, which the UI shows as "unsandboxed". */
  boundary: ServerBoundary[] | null;
  state: "open" | "closed";
}

export const MAX_RULE_ID = 60;
const MAX_DIGEST = 80;

/** One resolved call as summarised by the hub (no full args): session_history / earlier_denied items. */
export interface HistoryItem {
  call_id: string;
  server: string;
  tool: string;
  args_preview: string;
  decision: InboxDecision;
  reason: string;
  rule_id: string | null;
  note: string | null;
  ts: number | null;
}

export interface SessionSummary {
  approved: number;
  denied: number;
  auto: number;
  policy: number;
}

export type RuleFailReason =
  | "not_writable"
  | "not_confirmed"
  | "unknown_call"
  | "scope_not_allowed"
  | "cannot_build"
  | "invalid_policy"
  | "write_failed"
  | "log_unavailable"
  | "rate_limited"
  | "unknown";

export interface RuleResult {
  ok: boolean;
  rule_id: string | null;
  /** Closed set; anything else becomes "unknown". For ok results this is "ok". */
  reason: RuleFailReason | "ok";
}

export interface InboxCapabilities {
  policy_writable: boolean;
}

export const MAX_HISTORY = 10;
export const MAX_EARLIER_DENIED = 5;

export interface PendingCall {
  /** Credential names (env vars) this call will receive; shown as a warning before approving. */
  secrets_used: string[];
  session_summary: SessionSummary | null;
  /** Newest first, at most MAX_HISTORY. */
  session_history: HistoryItem[];
  /** Newest first, at most MAX_EARLIER_DENIED; denials only. */
  earlier_denied: HistoryItem[];
  /** Matched policy rule that made the hub hold this call (policy-file data; null = default verdict / no policy). */
  rule_id: string | null;
  policy_digest: string | null;
  session_id: string;
  call_id: string;
  server: string;
  tool: string;
  args: unknown;
  auto: boolean;
  alerts: InboxAlert[];
  deadline_s: number;
  /** Absolute ms timestamp when the backend will time the call out (received time + deadline_s). */
  deadline_at: number;
}

export interface ResolvedCall {
  /** The operator's note on a human denial (plain text, one line, <= 200). */
  note: string | null;
  /** True for items loaded from the durable event log (inbox_snapshot.recent), not resolved during this page's life. */
  history: boolean;
  /** Unix seconds from the log (history items only). */
  ts: number | null;
  rule_id: string | null;
  policy_digest: string | null;
  session_id: string;
  call_id: string;
  server: string;
  tool: string;
  decision: InboxDecision;
  reason: string;
  /** Filled by inbox_result (display only). */
  result: { status: "ok" | "error"; summary: string } | null;
}

export interface InboxState {
  sessions: Record<string, InboxSession>;
  /** Newest first. */
  pending: PendingCall[];
  /** Newest first, at most MAX_RESOLVED. */
  resolved: ResolvedCall[];
  /** From the latest inbox_snapshot; default false (standing rules hidden). */
  capabilities: InboxCapabilities;
  /** The last inbox_rule_result (global toast), or null. */
  ruleResult: RuleResult | null;
}

export const initialInboxState: InboxState = {
  sessions: {},
  pending: [],
  resolved: [],
  capabilities: { policy_writable: false },
  ruleResult: null,
};

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const id = (v: unknown): string | null => (typeof v === "string" && v.length > 0 && v.length <= 200 ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Policy-file data: strings only, one line, bounded; anything else (or empty) is null. */
function label(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  return singleLine(v, max) || null;
}

/** One entry of inbox_snapshot.recent (durable log). Every string is hostile: single line, capped. */
function parseRecent(v: unknown): ResolvedCall | null {
  if (!isRec(v)) return null;
  const session_id = id(v.session_id);
  const call_id = id(v.call_id);
  if (session_id === null || call_id === null) return null;
  const reason = typeof v.reason === "string" ? singleLine(v.reason, 40) : "";
  // only the exact string "approve" approves; restart / log_unavailable are always denials
  const approved = v.decision === "approve" && reason !== "restart" && reason !== "log_unavailable";
  return {
    note: label(v.note, 200),
    history: true,
    ts: num(v.ts),
    rule_id: label(v.rule_id, MAX_RULE_ID),
    policy_digest: null,
    session_id,
    call_id,
    server: typeof v.server === "string" ? singleLine(v.server, 120) : "",
    tool: typeof v.tool === "string" ? singleLine(v.tool, 200) : "",
    decision: approved ? "approve" : "deny",
    reason,
    result: null,
  };
}

/** Live items first (newest first), then the log's history (newest first), de-duplicated by session_id+call_id, capped. */
function mergeHistory(known: ResolvedCall[], recent: unknown): ResolvedCall[] {
  if (!Array.isArray(recent)) return known;
  const live = known.filter((r) => !r.history);
  const seen = new Set(live.map((r) => callKey(r.session_id, r.call_id)));
  const out = [...live];
  const add = (r: ResolvedCall) => {
    const k = callKey(r.session_id, r.call_id);
    if (seen.has(k)) return;
    seen.add(k);
    out.push(r);
  };
  for (const e of recent.slice(0, MAX_RESOLVED)) {
    const r = parseRecent(e);
    if (r) add(r);
  }
  // history loaded by an earlier snapshot that this one no longer lists is still history
  for (const r of known) if (r.history) add(r);
  return out.slice(0, MAX_RESOLVED);
}

const RULE_REASONS: ReadonlySet<string> = new Set([
  "not_writable", "not_confirmed", "unknown_call", "scope_not_allowed", "cannot_build", "invalid_policy", "write_failed", "log_unavailable", "rate_limited",
]);

function count(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1_000_000_000) : 0;
}

function parseSummary(v: unknown): SessionSummary | null {
  if (!isRec(v)) return null;
  return { approved: count(v.approved), denied: count(v.denied), auto: count(v.auto), policy: count(v.policy) };
}

function parseHistoryItem(v: unknown): HistoryItem | null {
  if (!isRec(v) || typeof v.tool !== "string") return null;
  return {
    call_id: label(v.call_id, 200) ?? "",
    server: typeof v.server === "string" ? singleLine(v.server, 120) : "",
    tool: singleLine(v.tool, 200),
    args_preview: typeof v.args_preview === "string" ? singleLine(v.args_preview, 120) : "",
    decision: v.decision === "approve" ? "approve" : "deny",
    reason: typeof v.reason === "string" ? singleLine(v.reason, 40) : "",
    rule_id: label(v.rule_id, MAX_RULE_ID),
    note: label(v.note, 200),
    ts: num(v.ts),
  };
}

function parseHistory(v: unknown, max: number, denialsOnly = false): HistoryItem[] {
  if (!Array.isArray(v)) return [];
  const out: HistoryItem[] = [];
  for (const e of v.slice(0, max * 4)) {
    const h = parseHistoryItem(e);
    if (h && (!denialsOnly || h.decision === "deny")) out.push(h);
    if (out.length >= max) break;
  }
  return out;
}

const SECRET_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/;

/** Env-var names only (closed pattern); anything else is dropped, at most MAX_SECRET_NAMES, duplicates removed. */
function parseSecretNames(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const n of v.slice(0, MAX_SECRET_NAMES * 4)) {
    if (typeof n === "string" && SECRET_NAME.test(n) && !out.includes(n)) out.push(n);
    if (out.length >= MAX_SECRET_NAMES) break;
  }
  return out;
}

function parseLayers(v: unknown): BoundaryLayer[] {
  if (!Array.isArray(v)) return [];
  return BOUNDARY_LAYERS.filter((l) => v.includes(l));
}

/** Array of per-server entries (not an object keyed by server name, so a server called "__proto__" is harmless). */
function parseBoundary(v: unknown): ServerBoundary[] | null {
  if (!isRec(v)) return null;
  const out: ServerBoundary[] = [];
  for (const key of Object.keys(v).slice(0, MAX_BOUNDARY_SERVERS)) {
    const b = v[key];
    if (!isRec(b)) continue;
    out.push({
      server: singleLine(key, 120),
      lifecycle: b.lifecycle === "per_call" ? "per_call" : "session",
      layers: parseLayers(b.layers),
      missing: parseLayers(b.missing),
      network: b.network === "none" || b.network === "loopback" || b.network === "host" ? b.network : null,
      secrets: parseSecretNames(b.secrets),
    });
  }
  return out.length > 0 ? out : null;
}

function parseAlert(v: unknown): InboxAlert | null {
  if (!isRec(v)) return null;
  const message = str(v.message);
  if (message === null) return null;
  return {
    severity: v.severity === "critical" ? "critical" : "warning",
    trigger: str(v.trigger) ?? "",
    message,
    drift_score: num(v.drift_score),
    threshold: num(v.threshold),
  };
}

function parseAlerts(v: unknown): InboxAlert[] {
  if (!Array.isArray(v)) return [];
  const out: InboxAlert[] = [];
  for (const a of v.slice(0, MAX_ALERTS)) {
    const p = parseAlert(a);
    if (p) out.push(p);
  }
  return out;
}

function parseServers(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === "string").slice(0, 50) : [];
}

function parsePending(v: unknown, now: number, sessionFallback?: string): PendingCall | null {
  if (!isRec(v)) return null;
  const session_id = id(v.session_id) ?? sessionFallback ?? null;
  const call_id = id(v.call_id);
  const tool = str(v.tool);
  if (session_id === null || call_id === null || tool === null) return null;
  const d = num(v.deadline_s);
  const deadline_s = d !== null && d > 0 ? Math.min(d, MAX_DEADLINE_S) : DEFAULT_DEADLINE_S;
  return {
    secrets_used: parseSecretNames(v.secrets_used),
    session_summary: parseSummary(v.session_summary),
    session_history: parseHistory(v.session_history, MAX_HISTORY),
    earlier_denied: parseHistory(v.earlier_denied, MAX_EARLIER_DENIED, true),
    rule_id: label(v.rule_id, MAX_RULE_ID),
    policy_digest: label(v.policy_digest, MAX_DIGEST),
    session_id,
    call_id,
    server: str(v.server) ?? "",
    tool,
    args: v.args ?? {},
    auto: v.auto === true,
    alerts: parseAlerts(v.alerts),
    deadline_s,
    deadline_at: now + deadline_s * 1000,
  };
}

export const callKey = (session_id: string, call_id: string): string => `${session_id}/${call_id}`;

const sameCall = (p: { session_id: string; call_id: string }, session_id: string, call_id: string) =>
  p.session_id === session_id && p.call_id === call_id;

function withSession(sessions: Record<string, InboxSession>, session_id: string): Record<string, InboxSession> {
  if (sessions[session_id]) return sessions;
  if (Object.keys(sessions).length >= MAX_SESSIONS) return sessions;
  return { ...sessions, [session_id]: { session_id, servers: [], boundary: null, state: "open" } };
}

/** Pure: returns a new state, or the SAME state object when the event changes nothing / is invalid. */
export function reduceInbox(state: InboxState, event: unknown, now: number = Date.now()): InboxState {
  if (!isRec(event) || typeof event.event !== "string") return state;
  switch (event.event) {
    case "inbox_snapshot": {
      if (!Array.isArray(event.sessions)) return state;
      const sessions: Record<string, InboxSession> = {};
      const pending: PendingCall[] = [];
      for (const s of event.sessions.slice(0, MAX_SESSIONS)) {
        if (!isRec(s)) continue;
        const session_id = id(s.session_id);
        if (session_id === null) continue;
        sessions[session_id] = { session_id, servers: parseServers(s.servers), boundary: parseBoundary(s.boundary), state: "open" };
        if (Array.isArray(s.pending)) {
          for (const p of s.pending) {
            const c = parsePending(p, now, session_id);
            // a snapshot entry belongs to the session it is listed under
            if (c) pending.push({ ...c, session_id });
          }
        }
      }
      // snapshot order is oldest first; show newest first
      return {
        sessions,
        pending: pending.reverse().slice(0, MAX_PENDING),
        resolved: mergeHistory(state.resolved, event.recent),
        capabilities: {
          policy_writable: isRec(event.capabilities) && event.capabilities.policy_writable === true,
        },
        ruleResult: state.ruleResult,
      };
    }
    case "inbox_pending": {
      const c = parsePending(event, now);
      if (!c) return state;
      if (state.pending.some((p) => sameCall(p, c.session_id, c.call_id))) return state;
      return {
        ...state,
        sessions: withSession(state.sessions, c.session_id),
        pending: [c, ...state.pending].slice(0, MAX_PENDING),
      };
    }
    case "inbox_alert": {
      const session_id = id(event.session_id);
      const call_id = id(event.call_id);
      const alert = parseAlert(event);
      if (session_id === null || call_id === null || alert === null) return state;
      if (!state.pending.some((p) => sameCall(p, session_id, call_id))) return state;
      return {
        ...state,
        pending: state.pending.map((p) =>
          sameCall(p, session_id, call_id) ? { ...p, alerts: [...p.alerts, alert].slice(-MAX_ALERTS) } : p,
        ),
      };
    }
    case "inbox_resolved": {
      const session_id = id(event.session_id);
      const call_id = id(event.call_id);
      if (session_id === null || call_id === null) return state;
      const prior = state.pending.find((p) => sameCall(p, session_id, call_id));
      const item: ResolvedCall = {
        note: label(event.note, 200),
        history: false,
        ts: null,
        rule_id: label(event.rule_id, MAX_RULE_ID) ?? prior?.rule_id ?? null,
        policy_digest: label(event.policy_digest, MAX_DIGEST) ?? prior?.policy_digest ?? null,
        session_id,
        call_id,
        server: prior?.server ?? "",
        tool: prior?.tool ?? "",
        // only the exact string "approve" approves (same semantics as the backend)
        decision: event.decision === "approve" ? "approve" : "deny",
        reason: str(event.reason) ?? "",
        result: null,
      };
      return {
        ...state,
        pending: state.pending.filter((p) => !sameCall(p, session_id, call_id)),
        resolved: [item, ...state.resolved.filter((r) => !sameCall(r, session_id, call_id))].slice(0, MAX_RESOLVED),
      };
    }
    case "inbox_result": {
      const session_id = id(event.session_id);
      const call_id = id(event.call_id);
      if (session_id === null || call_id === null) return state;
      if (!state.resolved.some((r) => sameCall(r, session_id, call_id))) return state;
      const result = {
        status: event.status === "ok" ? ("ok" as const) : ("error" as const),
        summary: (str(event.summary) ?? "").slice(0, 300),
      };
      return {
        ...state,
        resolved: state.resolved.map((r) => (sameCall(r, session_id, call_id) ? { ...r, result } : r)),
      };
    }
    case "inbox_rule_result": {
      const ok = event.ok === true;
      const reason = typeof event.reason === "string" && RULE_REASONS.has(event.reason) ? (event.reason as RuleFailReason) : "unknown";
      return { ...state, ruleResult: { ok, rule_id: label(event.rule_id, MAX_RULE_ID), reason: ok ? "ok" : reason } };
    }
    case "inbox_session": {
      const session_id = id(event.session_id);
      if (session_id === null || (event.state !== "open" && event.state !== "closed")) return state;
      const existing = state.sessions[session_id];
      if (!existing && Object.keys(state.sessions).length >= MAX_SESSIONS) return state;
      const servers = Array.isArray(event.servers) ? parseServers(event.servers) : (existing?.servers ?? []);
      return {
        ...state,
        sessions: { ...state.sessions, [session_id]: { session_id, servers, boundary: event.boundary !== undefined ? parseBoundary(event.boundary) : (existing?.boundary ?? null), state: event.state } },
      };
    }
    default:
      return state;
  }
}
