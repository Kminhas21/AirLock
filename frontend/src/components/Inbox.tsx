// Inbox.tsx — approval inbox for external (proxied) agent sessions.
//
// Everything about a call (session id, server, tool, args, alert text, reasons) is agent-controlled, so: single-value
// fields go through singleLine(), multi-line text through AgentText (numbered gutter), and NOTHING from the wire reaches
// a class name or attribute except data-call-id (an escaped React attribute). Class names below are constants or come
// from small closed sets (severity is coerced to "warning" | "critical" by the reducer).

import { useEffect, useState } from "react";
import { useInboxStore } from "../stores/inboxStore";
import type { InboxAlert, InboxDecision, PendingCall, ResolvedCall } from "../lib/inboxRoute";
import { singleLine, stripUnsafe } from "../lib/safeText";
import { AgentText } from "./AgentText";

export interface InboxProps {
  onDecision: (callId: string, decision: InboxDecision) => void;
  /** Fixed clock for tests; the live view ticks once a second. */
  nowMs?: number;
}

function prettyArgs(args: unknown): string {
  try {
    return JSON.stringify(args, null, 2) ?? "";
  } catch {
    return "(arguments could not be displayed)";
  }
}

function AlertBox({ alert }: { alert: InboxAlert }) {
  const critical = alert.severity === "critical";
  return (
    <div className={`alert-banner inbox-alert ${critical ? "critical" : "warning"}`}>
      <span className="alert-icon">{critical ? "!!" : "!"}</span>
      <div className="alert-content">
        <span className="alert-label">{critical ? "CRITICAL ALERT" : "WARNING"}</span>
        <span className="alert-message">{stripUnsafe(alert.message)}</span>
      </div>
      {alert.trigger && (
        <div className="alert-meta">
          <span className="alert-trigger">Trigger: {singleLine(alert.trigger)}</span>
        </div>
      )}
    </div>
  );
}

function PendingCard({
  call,
  now,
  canDecide,
  onDecision,
}: {
  call: PendingCall;
  now: number;
  canDecide: boolean;
  onDecision: InboxProps["onDecision"];
}) {
  const left = Math.max(0, Math.ceil((call.deadline_at - now) / 1000));
  return (
    <li className="inbox-card" data-testid="inbox-pending">
      <div className="inbox-card-head">
        <span className="inbox-tool" data-testid="inbox-tool">
          {singleLine(call.tool)}
        </span>
        {call.auto && <span className="inbox-auto">auto</span>}
        <span className="inbox-countdown" data-testid="inbox-countdown">
          {left > 0 ? `${left}s left` : "expired"}
        </span>
      </div>
      <div className="inbox-meta">
        <span className="detail-label">Server</span> <span>{singleLine(call.server) || "-"}</span>
        <span className="detail-label">Session</span> <span>{singleLine(call.session_id)}</span>
      </div>
      <AgentText text={prettyArgs(call.args)} />
      {call.alerts.map((a, i) => (
        <AlertBox alert={a} key={i} />
      ))}
      <div className="inbox-actions">
        <button
          className="btn-approve"
          data-testid="inbox-approve"
          data-call-id={call.call_id}
          disabled={!canDecide}
          onClick={() => onDecision(call.call_id, "approve")}
        >
          Approve
        </button>
        <button
          className="btn-deny"
          data-testid="inbox-deny"
          data-call-id={call.call_id}
          disabled={!canDecide}
          onClick={() => onDecision(call.call_id, "deny")}
        >
          Deny
        </button>
      </div>
    </li>
  );
}

function ResolvedRow({ item }: { item: ResolvedCall }) {
  const approved = item.decision === "approve";
  return (
    <li className="inbox-resolved-row" data-testid="inbox-resolved">
      <span className={approved ? "inbox-decision approve" : "inbox-decision deny"}>{approved ? "APPROVED" : "DENIED"}</span>
      <span className="inbox-tool">{singleLine(item.tool) || "(unknown tool)"}</span>
      {item.reason && <span className="inbox-reason">{singleLine(item.reason)}</span>}
      {item.result && (
        <span className="inbox-result">
          {item.result.status === "ok" ? "ok" : "error"}: {singleLine(item.result.summary, 200)}
        </span>
      )}
    </li>
  );
}

export function Inbox({ onDecision, nowMs }: InboxProps) {
  const sessions = useInboxStore((s) => s.sessions);
  const pending = useInboxStore((s) => s.pending);
  const resolved = useInboxStore((s) => s.resolved);
  const connection = useInboxStore((s) => s.connection);

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
            {pending.map((c) => (
              <PendingCard
                call={c}
                now={now}
                canDecide={connection === "connected"}
                onDecision={onDecision}
                key={`${c.session_id}/${c.call_id}`}
              />
            ))}
          </ul>
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
