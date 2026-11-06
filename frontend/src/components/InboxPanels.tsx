// InboxPanels.tsx — operator panels of an Inbox card: "Why flagged", "Session so far", standing rules.
// Everything shown here is agent- or policy-controlled: plain text only, single line (singleLine) wherever labelled.
// Class names are constants; the only dynamic style is a numeric percentage computed by lib/inboxView.scoreBar.

import { useId, useState } from "react";
import { signInErrorText } from "../lib/inboxView";
import type { HistoryItem, InboxAlert, InboxSession, SessionSummary } from "../lib/inboxRoute";
import { outcomeLabel, ruleRequestFrame, SCOPE_LABEL, scopesFor, scopeWords, scoreBar, type Scope, type Verdict } from "../lib/inboxView";
import { singleLine, stripUnsafe } from "../lib/safeText";

// ---------- Why flagged ----------

function ScoreBarView({ alert }: { alert: InboxAlert }) {
  const bar = scoreBar(alert.drift_score, alert.threshold);
  if (!bar) {
    return null;
  }
  return (
    <div className="inbox-bar" data-testid="inbox-score-bar">
      <div className="inbox-bar-track">
        <div className={`inbox-bar-fill${bar.over ? " over" : ""}`} data-testid="inbox-score-fill" style={{ width: `${bar.pct}%` }} />
        <div className="inbox-bar-threshold" data-testid="inbox-score-threshold" style={{ left: `${bar.thresholdPct}%` }} />
      </div>
      <span className="inbox-bar-text">
        score {alert.drift_score!.toFixed(2)} / threshold {alert.threshold!.toFixed(2)}
      </span>
    </div>
  );
}

function HistoryLine({ item, testid }: { item: HistoryItem; testid: string }) {
  return (
    <li className="inbox-hist-item" data-testid={testid}>
      <span className="inbox-tool">{singleLine(item.tool, 200)}</span>
      {item.server && <span className="inbox-hist-server">{singleLine(item.server, 120)}</span>}
      {item.args_preview && <span className="inbox-hist-args">{singleLine(item.args_preview, 120)}</span>}
      <span className={`inbox-hist-outcome ${item.decision === "approve" ? "approve" : "deny"}`}>{outcomeLabel(item.decision, item.reason)}</span>
      {item.rule_id && <span className="inbox-hist-rule">rule {singleLine(item.rule_id, 60)}</span>}
      {item.note && <span className="inbox-hist-note">note: {singleLine(item.note, 200)}</span>}
    </li>
  );
}

export function WhyFlagged({ alerts, earlierDenied }: { alerts: InboxAlert[]; earlierDenied: HistoryItem[] }) {
  if (alerts.length === 0 && earlierDenied.length === 0) return null;
  return (
    <section className="inbox-why" data-testid="inbox-why">
      <h4 className="inbox-panel-title">Why flagged</h4>
      {alerts.map((a, i) => {
        const critical = a.severity === "critical";
        return (
          <div className={`alert-banner inbox-alert ${critical ? "critical" : "warning"}`} data-testid="inbox-alert" key={i}>
            <span className="alert-icon">{critical ? "!!" : "!"}</span>
            <div className="alert-content">
              <span className="alert-label">{critical ? "CRITICAL ALERT" : "WARNING"}</span>
              {a.trigger && <span className="alert-trigger">Trigger: {singleLine(a.trigger)}</span>}
              <ScoreBarView alert={a} />
              <span className="alert-message">{stripUnsafe(a.message)}</span>
            </div>
          </div>
        );
      })}
      {earlierDenied.length > 0 && (
        <div className="inbox-earlier" data-testid="inbox-earlier-denied">
          <span className="detail-label">Earlier denied in this session</span>
          <ul className="inbox-hist-list">
            {earlierDenied.map((h, i) => (
              <HistoryLine item={h} testid="inbox-earlier-item" key={i} />
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

// ---------- Session so far ----------

export function SessionSoFar({ summary, history }: { summary: SessionSummary | null; history: HistoryItem[] }) {
  if (!summary && history.length === 0) return null;
  return (
    <details className="inbox-sofar" data-testid="inbox-session-so-far">
      <summary>Session so far</summary>
      {summary && (
        <div className="inbox-counters" data-testid="inbox-counters">
          <span>approved {summary.approved}</span>
          <span>denied {summary.denied}</span>
          <span>auto {summary.auto}</span>
          <span>policy {summary.policy}</span>
        </div>
      )}
      <ul className="inbox-hist-list">
        {history.slice(0, 10).map((h, i) => (
          <HistoryLine item={h} testid="inbox-history-item" key={i} />
        ))}
      </ul>
    </details>
  );
}

// ---------- Standing rules ----------

const VERDICTS: Verdict[] = ["allow", "deny", "ask"];
const BUTTON_TEXT: Record<Verdict, string> = { allow: "Always allow like this", deny: "Always deny", ask: "Always ask" };

export interface StandingRulesProps {
  tool: string;
  server: string;
  sessionId: string;
  callId: string;
  disabled: boolean;
  /** Returns false when the frame could not be sent. */
  onRequest: (frame: NonNullable<ReturnType<typeof ruleRequestFrame>>) => boolean;
  /** Test hook: start inside the confirm step. */
  initial?: { verdict: Verdict; scope: Scope };
}

export function StandingRules({ tool, server, sessionId, callId, disabled, onRequest, initial }: StandingRulesProps) {
  const [pick, setPick] = useState<{ verdict: Verdict; scope: Scope } | null>(initial ?? null);
  const [failed, setFailed] = useState(false);
  const group = useId();

  const confirm = () => {
    if (!pick) return;
    const frame = ruleRequestFrame(sessionId, callId, pick.verdict, pick.scope);
    if (!frame) return;
    setFailed(!onRequest(frame));
    setPick(null);
  };

  return (
    <div className="inbox-standing" data-testid="inbox-standing">
      {!pick && (
        <div className="inbox-standing-buttons">
          {VERDICTS.map((v) => (
            <button
              className="inbox-rule-btn"
              data-testid={`inbox-rule-${v}`}
              disabled={disabled}
              key={v}
              onClick={() => {
                setFailed(false);
                setPick({ verdict: v, scope: "exact" });
              }}
            >
              {BUTTON_TEXT[v]}
            </button>
          ))}
        </div>
      )}
      {pick && (
        <div className="inbox-confirm" data-testid="inbox-rule-confirm-step">
          <fieldset className="inbox-scope-choice">
            <legend>Scope</legend>
            {scopesFor(pick.verdict).map((sc) => (
              <label className="inbox-scope-option" key={sc}>
                <input
                  type="radio"
                  name={group}
                  data-testid={`inbox-rule-scope-${sc}`}
                  checked={pick.scope === sc}
                  onChange={() => setPick({ verdict: pick.verdict, scope: sc })}
                />{" "}
                {SCOPE_LABEL[sc]}
              </label>
            ))}
          </fieldset>
          <p className="inbox-confirm-text" data-testid="inbox-rule-confirm-text">
            {scopeWords(pick.verdict, pick.scope, tool, server)} Applies to new sessions only.
          </p>
          <div className="inbox-confirm-actions">
            <button className="inbox-rule-btn confirm" data-testid="inbox-rule-confirm" disabled={disabled} onClick={confirm}>
              Confirm
            </button>
            <button className="inbox-rule-btn" data-testid="inbox-rule-cancel" onClick={() => setPick(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {failed && (
        <div className="inbox-not-sent" data-testid="inbox-rule-not-sent">
          Rule request not sent, reconnecting.
        </div>
      )}
    </div>
  );
}

// ---------- Boundary chips ----------

/** One chip row per session: what each downstream server is confined to. No boundary info or no layers => red "unsandboxed". */
export function BoundaryChips({ session }: { session: InboxSession }) {
  const entries =
    session.boundary ??
    (session.servers.length > 0 ? session.servers : [""]).map((server) => ({
      server: singleLine(server, 120),
      lifecycle: "session" as const,
      layers: [],
      missing: [],
      network: null,
      secrets: [],
    }));
  return (
    <div className="inbox-boundary" data-testid="inbox-boundary">
      <span className="detail-label">Boundary</span>
      {entries.map((b, i) => (
        <span className="inbox-boundary-server" key={i}>
          {b.network && (
            <span className="inbox-boundary-chip net" data-testid="inbox-boundary-chip">
              {b.server ? `${b.server}: ` : ""}net {b.network}
            </span>
          )}
          {b.layers.includes("landlock_fs") && (
            <span className="inbox-boundary-chip fs" data-testid="inbox-boundary-chip">
              {b.network ? "" : b.server ? `${b.server}: ` : ""}fs sandboxed
            </span>
          )}
          {b.lifecycle === "per_call" && (
            <span className="inbox-boundary-chip lifecycle" data-testid="inbox-boundary-chip">
              {b.network || b.layers.includes("landlock_fs") ? "" : b.server ? `${b.server}: ` : ""}fresh worker per call
            </span>
          )}
          {b.layers.length === 0 && (
            <span className="inbox-boundary-chip unsandboxed" data-testid="inbox-boundary-chip">
              {b.server ? `${b.server}: ` : ""}unsandboxed
            </span>
          )}
          {b.missing.length > 0 && (
            <span className="inbox-boundary-chip weak" data-testid="inbox-boundary-weak">
              {b.server ? `${b.server}: ` : ""}weaker than requested: {b.missing.join(", ")}
            </span>
          )}
        </span>
      ))}
    </div>
  );
}

// ---------- Sign in ----------

/** Shown when the hub wants a credential. The credential is handed to onSignIn (sent as the first WebSocket frame), never put in a URL. */
export function SignInPanel({ reason, onSignIn }: { reason: "unauthorized" | "throttled" | null; onSignIn: (credential: string) => void }) {
  const [token, setToken] = useState("");
  const id = useId();
  const error = signInErrorText(reason);
  return (
    <form
      className="inbox-signin"
      data-testid="inbox-signin"
      onSubmit={(e) => {
        e.preventDefault();
        const t = token.trim();
        if (!t) return;
        setToken("");
        onSignIn(t);
      }}
    >
      <label htmlFor={id} className="detail-label">
        Operator token or JWT
      </label>
      <input id={id} className="inbox-note-input" data-testid="inbox-signin-input" type="password" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} />
      {error && (
        <div className="inbox-signin-error" data-testid="inbox-signin-error" role="alert">
          {error}
        </div>
      )}
      <button className="inbox-rule-btn confirm" data-testid="inbox-signin-submit" type="submit">
        Sign in
      </button>
    </form>
  );
}
