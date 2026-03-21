// DriftMonitor.tsx — Behavioral drift visualization with two charts:
//
// 1. 2D Scatter Plot (top): Shows the agent's trajectory projected to 2D (PC1 vs PC2).
// 2. Drift Score Chart (bottom): Mahalanobis distance over time with threshold line.
//
// We use 2D scatter instead of scatter3d to avoid WebGL initialization issues
// that can crash the app in some browsers/environments.

import { useMemo } from "react";
// react-plotly.js is a CJS module. Under Vite's ESM handling, the default
// export sometimes comes through as { default: PlotComponent } instead of
// PlotComponent directly. This workaround handles both cases.
import PlotImport from "react-plotly.js";
const Plot = (typeof (PlotImport as any).default !== "undefined"
  ? (PlotImport as any).default
  : PlotImport) as typeof PlotImport;
import { useSessionStore } from "../stores/sessionStore";

const BASELINE_SIZE = 3;
const DRIFT_THRESHOLD = 2.5;

export function DriftMonitor() {
  const driftPoints = useSessionStore((s) => s.driftPoints);
  const currentDriftScore = useSessionStore((s) => s.currentDriftScore);
  const setSelectedNode = useSessionStore((s) => s.setSelectedNode);

  // --- 2D Scatter Data (PC1 vs PC2) ---
  const scatterData = useMemo(() => {
    if (driftPoints.length === 0) return [];

    const baseline = driftPoints.slice(0, BASELINE_SIZE);
    const trail = driftPoints.slice(BASELINE_SIZE);
    const traces: object[] = [];

    // Trajectory line connecting all points
    if (driftPoints.length > 1) {
      traces.push({
        type: "scatter",
        mode: "lines",
        x: driftPoints.map((p) => p.x),
        y: driftPoints.map((p) => p.y),
        line: { color: "#4b5563", width: 2 },
        showlegend: false,
        hoverinfo: "skip",
      });
    }

    // Baseline cluster — larger cyan markers
    if (baseline.length > 0) {
      traces.push({
        type: "scatter",
        mode: "markers+text",
        name: "Baseline",
        x: baseline.map((p) => p.x),
        y: baseline.map((p) => p.y),
        marker: { size: 14, color: "#06b6d4", symbol: "circle" },
        text: baseline.map((p) => `S${p.stepIndex}`),
        textposition: "top center",
        textfont: { color: "#06b6d4", size: 10 },
        hovertext: baseline.map(
          (p) =>
            `Step ${p.stepIndex} | ${p.nodeId} | Dist: ${p.mahalanobisDistance.toFixed(2)}`
        ),
        hoverinfo: "text",
        customdata: baseline.map((p) => p.nodeId),
      });
    }

    // Post-baseline points — colored by step index
    if (trail.length > 0) {
      traces.push({
        type: "scatter",
        mode: "markers+text",
        name: "Agent Steps",
        x: trail.map((p) => p.x),
        y: trail.map((p) => p.y),
        marker: {
          size: 10,
          color: trail.map((p) =>
            p.mahalanobisDistance > DRIFT_THRESHOLD ? "#ef4444" : "#f59e0b"
          ),
        },
        text: trail.map((p) => `S${p.stepIndex}`),
        textposition: "top center",
        textfont: { color: "#9ca3af", size: 10 },
        hovertext: trail.map(
          (p) =>
            `Step ${p.stepIndex} | ${p.nodeId} | Dist: ${p.mahalanobisDistance.toFixed(2)} | Persistence: ${p.metrics.goal_persistence.toFixed(2)}`
        ),
        hoverinfo: "text",
        customdata: trail.map((p) => p.nodeId),
      });
    }

    return traces;
  }, [driftPoints]);

  // --- Drift Score Line Chart Data ---
  const driftLineData = useMemo(() => {
    if (driftPoints.length === 0) return [];

    return [
      {
        type: "scatter",
        mode: "lines+markers",
        x: driftPoints.map((p) => p.stepIndex),
        y: driftPoints.map((p) => p.mahalanobisDistance),
        marker: {
          color: driftPoints.map((p) =>
            p.mahalanobisDistance > DRIFT_THRESHOLD ? "#ef4444" : "#22c55e"
          ),
          size: 8,
        },
        line: { color: "#4b5563", width: 2 },
        name: "Drift Score",
        hovertext: driftPoints.map(
          (p) => `Step ${p.stepIndex}: ${p.mahalanobisDistance.toFixed(2)}`
        ),
        hoverinfo: "text",
      },
    ];
  }, [driftPoints]);

  // Handle clicking a point to highlight the corresponding kill chain node
  const handlePointClick = (event: any) => {
    const point = event?.points?.[0];
    if (point?.customdata) {
      setSelectedNode(point.customdata as string);
    }
  };

  const darkAxisStyle = {
    gridcolor: "#2a2d37",
    zerolinecolor: "#2a2d37",
    color: "#6b7280",
  };

  const maxStep =
    driftPoints.length > 0
      ? Math.max(...driftPoints.map((p) => p.stepIndex), 5)
      : 5;

  return (
    <div className="panel drift-monitor-panel">
      <h2 className="panel-title">
        Drift Monitor
        {currentDriftScore > 0 && (
          <span
            className={`drift-score-badge ${
              currentDriftScore > DRIFT_THRESHOLD ? "breached" : ""
            }`}
          >
            Score: {currentDriftScore.toFixed(2)}
          </span>
        )}
      </h2>

      {driftPoints.length === 0 ? (
        <p className="panel-placeholder">
          Behavioral drift data will appear here as the agent acts. A scatter
          plot will show the agent's trajectory through embedding space.
        </p>
      ) : (
        <div className="drift-charts">
          {/* 2D Scatter Plot — Embedding Space */}
          <div className="chart-container scatter3d-container">
            <Plot
              data={scatterData as any}
              layout={{
                autosize: true,
                margin: { l: 40, r: 16, t: 8, b: 40 },
                paper_bgcolor: "transparent",
                plot_bgcolor: "transparent",
                xaxis: { ...darkAxisStyle, title: { text: "PC1", font: { size: 11 } } },
                yaxis: { ...darkAxisStyle, title: { text: "PC2", font: { size: 11 } } },
                showlegend: false,
                font: { color: "#9ca3af", size: 10 },
              }}
              config={{ displayModeBar: false, responsive: true }}
              style={{ width: "100%", height: "100%" }}
              onClick={handlePointClick}
              useResizeHandler
            />
          </div>

          {/* Drift Score Line Chart */}
          <div className="chart-container line-chart-container">
            <Plot
              data={driftLineData as any}
              layout={{
                autosize: true,
                margin: { l: 40, r: 16, t: 8, b: 32 },
                paper_bgcolor: "transparent",
                plot_bgcolor: "transparent",
                xaxis: {
                  ...darkAxisStyle,
                  title: { text: "Step", font: { size: 11 } },
                  dtick: 1,
                },
                yaxis: {
                  ...darkAxisStyle,
                  title: { text: "Drift", font: { size: 11 } },
                },
                showlegend: false,
                font: { color: "#9ca3af", size: 10 },
                shapes: [
                  {
                    type: "line",
                    x0: 0,
                    x1: maxStep,
                    y0: DRIFT_THRESHOLD,
                    y1: DRIFT_THRESHOLD,
                    line: { color: "#ef4444", width: 2, dash: "dash" },
                  },
                ],
                annotations: [
                  {
                    x: 0.02,
                    y: DRIFT_THRESHOLD,
                    xref: "paper",
                    yref: "y",
                    text: "threshold",
                    showarrow: false,
                    font: { color: "#ef4444", size: 10 },
                    yshift: 12,
                  },
                ],
              }}
              config={{ displayModeBar: false, responsive: true }}
              style={{ width: "100%", height: "100%" }}
              useResizeHandler
            />
          </div>
        </div>
      )}
    </div>
  );
}
