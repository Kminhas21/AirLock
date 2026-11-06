// Inbox.tsx — approval inbox for external (proxied) agent sessions.
//
// Everything about a call (session id, server, tool, args, alert text, reasons) is agent-controlled, so: single-value
// fields go through singleLine(), multi-line text through AgentText (numbered gutter), and NOTHING from the wire reaches
// a class name or attribute except data-call-id (an escaped React attribute). Class names below are constants or come
// from small closed sets (severity is coerced to "warning" | "critical" by the reducer).

import { useEffect, useId, useState } from "react";
import { useInboxStore } from "../stores/inboxStore";
import { callKey, MAX_PENDING_RENDERED, type InboxDecision, type PendingCall, type ResolvedCall } from "../lib/inboxRoute";
import { panelView, singleLine } from "../lib/safeText";
import { ruleToast, type Scope, type Verdict } from "../lib/inboxView";
import { AgentText } from "./AgentText";
import { BoundaryChips, SessionSoFar, StandingRules, WhyFlagged } from "./InboxPanels";

export interface InboxProps {
  /** Returns false when the decision could not be sent (socket not open). */
  onDecision: (sessionId: string, callId: string, decision: InboxDecision, note?: string) => boolean;
  /** Ask the hub to turn a call into a standing rule. Returns false when not sent. */
  onRuleRequest: (sessionId: string, callId: string, verdict: Verdict, scope: Scope) => boolean;
  /** Fixed clock for tests; the live view ticks once a second. */
  nowMs?: number;
}

/** Arguments are shown up to this many characters; beyond it Approve is disabled (a human must not approve unseen content). */
export const MAX_ARGS_PANEL = 200_000;
const MAX_TOOL_NAME = 200;

function prettyArgs(args: unknown): string {
  try {
    return JSON.stringify(args, null, 2) ?? "";
  } catch {
    return "(arguments could not be displayed)";
  }
}

function PendingCard({
  call,
  now,
  canDecide,
  notSent,
  policyWritable,
  onDecision,
  onRuleRequest,
}: {
  call: PendingCall;
  now: number;
  canDecide: boolean;
  notSent: boolean;
  policyWritable: boolean;
  onDecision: (decision: InboxDecision, note?: string) => void;
  onRuleRequest: (verdict: Verdict, scope: Scope) => boolean;
}) {
  const [note, setNote] = useState("");
  const noteId = useId();
  const argsText = prettyArgs(call.args);
  const hiddenChars = panelView(argsText, MAX_ARGS_PANEL).hiddenChars;
  const left = Math.max(0, Math.ceil((call.deadline_at - now) / 1000));
  return (
    <li className="inbox-card" data-testid="inbox-pending">
      <div className="inbox-card-head">
        <span className="inbox-tool" data-testid="inbox-tool">
          {singleLine(call.tool, MAX_TOOL_NAME)}
        </span>
        {call.auto && <span className="inbox-auto">auto</span>}
        {call.rule_id && (
          <span className="inbox-rule" data-testid="inbox-rule">
            held by rule {singleLine(call.rule_id, 60)}
          </span>
        )}
        <span className="inbox-countdown" data-testid="inbox-countdown">
          {left > 0 ? `${left}s left` : "expired"}
        </span>
      </div>
      <div className="inbox-meta">
        <span className="detail-label">Server</span> <span>{singleLine(call.server) || "-"}</span>
        <span className="detail-label">Session</span> <span>{singleLine(call.session_id)}</span>
      </div>
      {hiddenChars > 0 && (
        <div className="inbox-truncated" data-testid="inbox-truncated" role="alert">
          TRUNCATED: {hiddenChars} more characters not shown. Approve is disabled because you cannot see all of the arguments.
        </div>
      )}
      {call.secrets_used.length > 0 && (
        <div className="inbox-secrets" role="alert" data-testid="inbox-secrets-warning">
          This call will receive credentials: {call.secrets_used.join(", ")} (exist only during this call)
        </div>
      )}
      <AgentText text={argsText} max={MAX_ARGS_PANEL} />
      <WhyFlagged alerts={call.alerts} earlierDenied={call.earlier_denied} />
      <SessionSoFar summary={call.session_summary} history={call.session_history} />
      <div className="inbox-note-row">
        <label htmlFor={noteId} className="detail-label">
          Reason sent to the agent
        </label>
        <input
          id={noteId}
          className="inbox-note-input"
          data-testid="inbox-note"
          type="text"
          maxLength={200}
          value={note}
          placeholder="optional, used when you deny"
          onChange={(e) => setNote(e.target.value)}
        />
      </div>
      <div className="inbox-actions">
        <button
          className="btn-approve"
          data-testid="inbox-approve"
          data-call-id={call.call_id}
          disabled={!canDecide || hiddenChars > 0}
          onClick={() => onDecision("approve")}
        >
          Approve
        </button>
        <button
          className="btn-deny"
          data-testid="inbox-deny"
          data-call-id={call.call_id}
          disabled={!canDecide}
          onClick={() => onDecision("deny", note)}
        >
          Deny
        </button>
      </div>
      {policyWritable && (
        <StandingRules
          tool={call.tool}
          server={call.server}
          sessionId={call.session_id}
          callId={call.call_id}
          disabled={!canDecide}
          onRequest={(f) => onRuleRequest(f.verdict, f.scope)}
        />
      )}
      {notSent && (
        <div className="inbox-not-sent" data-testid="inbox-not-sent">
          Not sent, reconnecting. Try again once the connection is back.
        </div>
      )}
    </li>
  );
}

function ResolvedRow({ item }: { item: ResolvedCall }) {
  const approved = item.decision === "approve";
  // only the exact reason "cancelled" (the agent/proxy abandoned the call) gets the neutral label; everything else is a decision
  const cancelled = !approved && item.reason === "cancelled";
  const policy = item.reason === "policy";
  const rule = item.rule_id ? singleLine(item.rule_id, 60) : "";
  const cls = approved ? "approve" : cancelled ? "cancelled" : "deny";
  const text = policy
    ? `${approved ? "auto-allowed" : "denied"} by ${rule ? `rule ${rule}` : "policy"}`
    : !approved && item.reason === "restart"
      ? "DENIED (backend restarted)"
      : !approved && item.reason === "log_unavailable"
        ? "DENIED (log unavailable)"
        : approved
      ? "APPROVED"
      : cancelled
        ? "CANCELLED"
        : "DENIED";
  return (
    <li
      className="inbox-resolved-row"
      data-testid="inbox-resolved"
      data-reason={singleLine(item.reason, 40)}
      data-rule-id={policy && rule ? rule : undefined}
    >
      <span className={`inbox-decision ${policy ? "policy " : ""}${cls}`}>{text}</span>
      {item.history && (
        <span className="inbox-history" data-testid="inbox-history">
          history
        </span>
      )}
      <span className="inbox-tool">{singleLine(item.tool, MAX_TOOL_NAME) || "(unknown tool)"}</span>
      {item.note && (
        <span className="inbox-note-shown" data-testid="inbox-resolved-note">
          note: {singleLine(item.note, 200)}
        </span>
      )}
      {item.reason && <span className="inbox-reason">{singleLine(item.reason)}</span>}
      {item.result && (
        <span className="inbox-result">
          {item.result.status === "ok" ? "ok" : "error"}: {singleLine(item.result.summary, 200)}
        </span>
      )}
    </li>
  );
}

export function Inbox({ onDecision, onRuleRequest, nowMs }: InboxProps) {
  const sessions = useInboxStore((s) => s.sessions);
  const pending = useInboxStore((s) => s.pending);
  const resolved = useInboxStore((s) => s.resolved);
  const connection = useInboxStore((s) => s.connection);
  const snapshotReceived = useInboxStore((s) => s.snapshotReceived);
  const notSent = useInboxStore((s) => s.notSent);
  const markNotSent = useInboxStore((s) => s.markNotSent);
  const policyWritable = useInboxStore((s) => s.capabilities.policy_writable);
  const ruleResult = useInboxStore((s) => s.ruleResult);
  const clearRuleResult = useInboxStore((s) => s.clearRuleResult);

  const [tick, setTick] = useState(() => Date.now());
  useEffect(() => {
    if (nowMs !== undefined) return;
    const t = window.setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(t);
  }, [nowMs]);
  const now = nowMs ?? tick;

  const sessionList = Object.values(sessions);
  const connLabel =
    connection === "connected" ? "Connected" : connection === "reconnecting" ? "Reconnecting..." : "Disconnected";

  return (
    <div className="inbox-view" data-testid="inbox-view">
      <div className="inbox-header">
        <h2 className="inbox-title">Inbox</h2>
        <span className="inbox-conn" data-testid="inbox-connection" data-state={connection}>
          {connLabel}
        </span>
      </div>

      {ruleResult && (
        <div className={`inbox-toast ${ruleResult.ok ? "ok" : "err"}`} data-testid="inbox-rule-toast" role="status">
          <span>{ruleToast(ruleResult)}</span>
          <button className="inbox-toast-close" data-testid="inbox-rule-toast-dismiss" onClick={clearRuleResult}>
            Dismiss
          </button>
        </div>
      )}

      <section className="inbox-section">
        <h3 className="inbox-subtitle">Sessions</h3>
        {sessionList.length === 0 ? (
          <p className="inbox-empty">No sessions connected.</p>
        ) : (
          <ul className="inbox-sessions">
            {sessionList.map((s) => (
              <li className="inbox-session" data-testid="inbox-session" key={s.session_id}>
                <span className="inbox-session-id">{singleLine(s.session_id)}</span>
                <span className={s.state === "open" ? "inbox-state open" : "inbox-state closed"}>
                  {s.state === "open" ? "open" : "closed"}
                </span>
                <span className="inbox-servers">{s.servers.map((x) => singleLine(x, 40)).join(", ") || "no servers"}</span>
                <BoundaryChips session={s} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="inbox-section">
        <h3 className="inbox-subtitle">Pending approval ({pending.length})</h3>
        {pending.length === 0 ? (
          <p className="inbox-empty" data-testid="inbox-empty">
            No pending tool calls. Calls from connected agents will appear here.
          </p>
        ) : (
          <ul className="inbox-pending">
            {pending.slice(0, MAX_PENDING_RENDERED).map((c) => {
              const key = callKey(c.session_id, c.call_id);
              return (
                <PendingCard
                  call={c}
                  now={now}
                  canDecide={connection === "connected" && snapshotReceived}
                  notSent={key in notSent}
                  policyWritable={policyWritable}
                  onDecision={(d, n) => markNotSent(key, !onDecision(c.session_id, c.call_id, d, n))}
                  onRuleRequest={(v, sc) => onRuleRequest(c.session_id, c.call_id, v, sc)}
                  key={key}
                />
              );
            })}
          </ul>
        )}
        {pending.length > MAX_PENDING_RENDERED && (
          <p className="inbox-more" data-testid="inbox-more-pending">
            {pending.length - MAX_PENDING_RENDERED} more pending not shown
          </p>
        )}
      </section>

      <section className="inbox-section">
        <h3 className="inbox-subtitle">Recently resolved</h3>
        {resolved.length === 0 ? (
          <p className="inbox-empty">Nothing resolved yet.</p>
        ) : (
          <ul className="inbox-resolved">
            {resolved.map((r) => (
              <ResolvedRow item={r} key={`${r.session_id}/${r.call_id}`} />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
