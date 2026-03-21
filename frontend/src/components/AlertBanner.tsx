// AlertBanner.tsx — Placeholder for the alignment alert banner.
// Will be fully built in task B7 with slide-up animation and auto-dismiss.

import { useSessionStore } from "../stores/sessionStore";

export function AlertBanner() {
  const activeAlert = useSessionStore((s) => s.activeAlert);

  if (!activeAlert) return null;

  return (
    <div
      className={`alert-banner ${activeAlert.severity}`}
      onClick={() => useSessionStore.getState().handleAlignmentAlertEvent}
    >
      <span className="alert-icon">
        {activeAlert.severity === "critical" ? "!!" : "!"}
      </span>
      <span className="alert-message">
        <strong>ALIGNMENT ALERT:</strong> {activeAlert.message}
      </span>
      <span className="alert-score">
        Drift: {activeAlert.drift_score.toFixed(2)} / Threshold:{" "}
        {activeAlert.threshold}
      </span>
    </div>
  );
}
