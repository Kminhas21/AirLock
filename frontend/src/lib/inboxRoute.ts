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
  /** D31: can the proxy have the kernel confine its auto-allowed path calls? false = its path allows are asked; null = not reported. */
  confinable: boolean | null;
  confine_why: string;
}

/** D31, display only: where the proxy says a symlinked path value leads ("path", "paths.1"). Nothing evaluates it. */
export interface PathLink {
  arg: string;
  real: string;
  /** Where the value leads when `..` is resolved before the links (as Node does); present only when it differs from `real`. */
  lexical?: string;
}
export const MAX_LINKS = 64;

/** D32: why the proxy could not confine a write-shaped call (closed set; anything else is dropped). */
export const WRITE_WHYS = ["unsupported", "bad_path", "outside_write_dir", "new_file", "symlink", "not_regular", "hard_link", "executable", "too_large", "no_before_image", "edits_too_large"] as const;
export type WriteWhy = (typeof WRITE_WHYS)[number];
/** What the proxy found for a write-shaped call (display only; the hub decides from `write_confinable`). */
export interface WriteInfo {
  confinable: boolean;
  why?: WriteWhy;
}
/** D32: one auto-allowed write as the proxy reports it after the call: which file, which inode, digests and sizes, and the before-image. */
export interface WriteRecord {
  path: string;
  dev: number;
  ino: number;
  size_before: number;
  sha256_before: string;
  size_after: number | null;
  sha256_after: string | null;
  replaced: boolean;
  undo: string;
}
export const MAX_WRITES = 64;

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
  /** Role >= approver. A snapshot WITHOUT the key (legacy hub) means true; present means exactly true. */
  can_decide: boolean;
}

export type Role = "viewer" | "approver" | "admin";

export interface Principal {
  id: string;
  tenant: string | null;
  role: Role | null;
}

export interface AuthState {
  /** "required" = the hub wants a credential (sign-in panel); "ok" = authenticated or no auth in use. */
  status: "none" | "required" | "ok";
  reason: "unauthorized" | "throttled" | null;
}

export interface Forbidden {
  action: "decide" | "rules" | "action";
  reason: "role" | "server" | null;
}

export const DEFAULT_CAPABILITIES: InboxCapabilities = { policy_writable: false, can_decide: true };
export const MAX_ESCALATION_LEVEL = 10;

export const MAX_HISTORY = 10;
export const MAX_EARLIER_DENIED = 5;

export interface PendingCall {
  agent_id: string | null;
  tenant: string | null;
  /** 0 = not escalated. */
  escalation_level: number;
  /** Age (seconds) the hub reported when it sent the event; null if absent. Live age = age_s + (now - received_at). */
  age_s: number | null;
  /** Local ms timestamp when this event was received. */
  received_at: number;
  /** Credential names (env vars) this call will receive; shown as a warning before approving. */
  secrets_used: string[];
  /** Where symlinked path values lead, as the proxy resolves them (a hint; the server may differ). */
  links: PathLink[];
  /** D32: a write-shaped call: what the proxy found (null = not reported / not a write). */
  write: WriteInfo | null;
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
  /** Operator id who decided (null for non-human resolutions). */
  operator: string | null;
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
  result: { status: "ok" | "error"; summary: string; writes?: WriteRecord[] } | null;
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
  principal: Principal | null;
  auth: AuthState;
  /** The last inbox_forbidden notice (auto-cleared by the store), or null. */
  forbidden: Forbidden | null;
}

export const initialInboxState: InboxState = {
  sessions: {},
  pending: [],
  resolved: [],
  capabilities: DEFAULT_CAPABILITIES,
  ruleResult: null,
  principal: null,
  auth: { status: "none", reason: null },
  forbidden: null,
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
    operator: ident(v.operator),
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
      confinable: typeof b.confinable === "boolean" ? b.confinable : null,
      confine_why: typeof b.confine_why === "string" ? singleLine(b.confine_why, 120) : "",
    });
  }
  return out.length > 0 ? out : null;
}

const IDENT = /^[A-Za-z0-9._@-]{1,64}$/;
const ident = (v: unknown): string | null => (typeof v === "string" && IDENT.test(v) ? v : null);
const ROLES: ReadonlySet<string> = new Set(["viewer", "approver", "admin"]);

function parsePrincipal(v: unknown): Principal | null {
  if (!isRec(v)) return null;
  const pid = ident(v.id);
  if (pid === null) return null;
  return { id: pid, tenant: ident(v.tenant), role: typeof v.role === "string" && ROLES.has(v.role) ? (v.role as Role) : null };
}

function level(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_ESCALATION_LEVEL ? v : null;
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

function parseLinks(v: unknown, lexical?: unknown): PathLink[] {
  if (!isRec(v)) return [];
  const lex = isRec(lexical) ? lexical : {};
  const out: PathLink[] = [];
  for (const k of Object.keys(v)) {
    const real = v[k];
    if (typeof real !== "string" || !real) continue;
    const other = lex[k];
    out.push({ arg: singleLine(k, 120), real: singleLine(real, 500), ...(typeof other === "string" && other ? { lexical: singleLine(other, 500) } : {}) });
    if (out.length >= MAX_LINKS) break;
  }
  return out;
}

function parseWrite(v: unknown): WriteInfo | null {
  if (!isRec(v) || typeof v.confinable !== "boolean") return null;
  const why = typeof v.why === "string" && (WRITE_WHYS as readonly string[]).includes(v.why) ? (v.why as WriteWhy) : undefined;
  return why && !v.confinable ? { confinable: false, why } : { confinable: v.confinable };
}

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;
const isHex64 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);

function parseWrites(v: unknown): WriteRecord[] | undefined {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_WRITES) return undefined;
  const out: WriteRecord[] = [];
  for (const w of v) {
    if (!isRec(w)) return undefined;
    const path = str(w.path);
    const undo = str(w.undo);
    if (!path || !undo || !isCount(w.dev) || !isCount(w.ino) || !isCount(w.size_before) || !isHex64(w.sha256_before)) return undefined;
    if (!(w.size_after === null || isCount(w.size_after)) || !(w.sha256_after === null || isHex64(w.sha256_after)) || typeof w.replaced !== "boolean") return undefined;
    out.push({ path: singleLine(path, 4096), dev: w.dev, ino: w.ino, size_before: w.size_before, sha256_before: w.sha256_before, size_after: w.size_after, sha256_after: w.sha256_after, replaced: w.replaced, undo: singleLine(undo, 4096) });
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
  const age = num(v.age_s);
  return {
    agent_id: ident(v.agent_id),
    tenant: ident(v.tenant),
    escalation_level: level(v.escalation_level) ?? 0,
    age_s: age !== null && age >= 0 && age <= 10_000_000 ? age : null,
    received_at: now,
    secrets_used: parseSecretNames(v.secrets_used),
    links: parseLinks(v.links, v.links_lexical),
    write: parseWrite(v.write),
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
          can_decide: !isRec(event.capabilities) || !("can_decide" in event.capabilities) || event.capabilities.can_decide === true,
        },
        ruleResult: state.ruleResult,
        principal: parsePrincipal(event.principal) ?? state.principal,
        auth: { status: "ok", reason: null },
        forbidden: state.forbidden,
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
        operator: ident(event.operator),
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
      const writes = parseWrites(event.writes);
      const result = {
        status: event.status === "ok" ? ("ok" as const) : ("error" as const),
        summary: (str(event.summary) ?? "").slice(0, 300),
        ...(writes ? { writes } : {}),
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
    case "auth_ok":
      return { ...state, principal: parsePrincipal(event.principal), auth: { status: "ok", reason: null } };
    case "auth_error":
      return { ...state, principal: null, auth: { status: "required", reason: event.reason === "throttled" ? "throttled" : "unauthorized" } };
    case "inbox_forbidden":
      return {
        ...state,
        forbidden: {
          action: event.action === "decide" || event.action === "rules" ? event.action : "action",
          reason: event.reason === "role" || event.reason === "server" ? event.reason : null,
        },
      };
    case "inbox_escalated": {
      const session_id = id(event.session_id);
      const call_id = id(event.call_id);
      const lvl = level(event.level);
      if (session_id === null || call_id === null || lvl === null) return state;
      if (!state.pending.some((p) => sameCall(p, session_id, call_id))) return state;
      return {
        ...state,
        pending: state.pending.map((p) => (sameCall(p, session_id, call_id) ? { ...p, escalation_level: Math.max(p.escalation_level, lvl) } : p)),
      };
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
