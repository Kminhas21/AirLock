// DriftMonitor.tsx — Placeholder for the Drift Monitor panel.
// Will be fully built in task B6 with Plotly 3D scatter and drift score chart.

import { useSessionStore } from "../stores/sessionStore";

export function DriftMonitor() {
  const driftPoints = useSessionStore((s) => s.driftPoints);
  const currentDriftScore = useSessionStore((s) => s.currentDriftScore);

  return (
    <div className="panel drift-monitor-panel">
      <h2 className="panel-title">Drift Monitor</h2>
      {driftPoints.length === 0 ? (
        <p className="panel-placeholder">
          Behavioral drift data will appear here as the agent acts. A 3D scatter
          plot will show the agent's trajectory through embedding space.
        </p>
      ) : (
        <div className="placeholder-drift">
          <p>
            Drift Score: <strong>{currentDriftScore.toFixed(2)}</strong>
            {currentDriftScore > 2.5 && (
              <span style={{ color: "#EF4444", marginLeft: 8 }}>
                THRESHOLD BREACHED
              </span>
            )}
          </p>
          <div className="drift-points-list">
            {driftPoints.map((pt) => (
              <div
                key={pt.stepIndex}
                className={`drift-point-row ${
                  pt.baselineBreached ? "breached" : ""
                }`}
              >
                Step {pt.stepIndex}: distance={pt.mahalanobisDistance.toFixed(2)},
                persistence={pt.metrics.goal_persistence.toFixed(2)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
