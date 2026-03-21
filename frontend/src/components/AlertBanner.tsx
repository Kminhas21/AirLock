// AlertBanner.tsx — Alignment alert banner that slides up from the bottom.
//
// When the Seismograph detects behavioral drift or circumvention, it sends
// an alignment_alert event. This component shows a banner with the alert
// message, severity, and drift score. It auto-dismisses after 8 seconds
// or when clicked.

import { useEffect } from "react";
import { useSessionStore } from "../stores/sessionStore";

export function AlertBanner() {
  const activeAlert = useSessionStore((s) => s.activeAlert);

  // Auto-dismiss after 8 seconds
  useEffect(() => {
    if (!activeAlert) return;

    const timer = setTimeout(() => {
      // Clear the active alert (but keep it in the alerts history array)
      useSessionStore.setState({ activeAlert: null });
    }, 8000);

    return () => clearTimeout(timer);
  }, [activeAlert]);

  if (!activeAlert) return null;

  const dismiss = () => {
    useSessionStore.setState({ activeAlert: null });
  };

  return (
    <div className={`alert-banner ${activeAlert.severity}`} onClick={dismiss}>
      <span className="alert-icon">
        {activeAlert.severity === "critical" ? "!!" : "!"}
      </span>
      <div className="alert-content">
        <span className="alert-label">
          {activeAlert.severity === "critical"
            ? "CRITICAL ALERT"
            : "WARNING"}
        </span>
        <span className="alert-message">{activeAlert.message}</span>
      </div>
      <div className="alert-meta">
        <span className="alert-trigger">Trigger: {activeAlert.trigger}</span>
        <span className="alert-score">
          Drift: {activeAlert.drift_score.toFixed(2)} / Threshold:{" "}
          {activeAlert.threshold}
        </span>
      </div>
      <span className="alert-dismiss">Click to dismiss</span>
    </div>
  );
}
