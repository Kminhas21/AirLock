// DriftMonitor.tsx — Behavioral drift visualization with two charts:
//
// 1. 3D Scatter Plot (top): Shows the agent's trajectory through embedding space.
//    Each point is an agent step projected to 3D via PCA. Points are colored from
//    blue (early) to red (late). The first 3 points are the "baseline" cluster
//    shown as larger cyan markers. A line connects points in order.
//
// 2. Drift Score Chart (bottom): A 2D line chart showing Mahalanobis distance
//    over time. A horizontal red dashed line marks the threshold (2.5).
//    Points above the threshold turn red.

import { useMemo } from "react";
import Plot from "react-plotly.js";
import { useSessionStore } from "../stores/sessionStore";

// How many initial points form the baseline cluster
const BASELINE_SIZE = 3;
const DRIFT_THRESHOLD = 2.5;

export function DriftMonitor() {
  const driftPoints = useSessionStore((s) => s.driftPoints);
  const currentDriftScore = useSessionStore((s) => s.currentDriftScore);
  const setSelectedNode = useSessionStore((s) => s.setSelectedNode);

  // Split points into baseline and post-baseline
  const baselinePoints = driftPoints.slice(0, BASELINE_SIZE);
  const trailPoints = driftPoints.slice(BASELINE_SIZE);

  // --- 3D Scatter Data ---
  const scatter3dData = useMemo(() => {
    const traces: Plotly.Data[] = [];

    // Line connecting all points in order (trajectory)
    if (driftPoints.length > 1) {
      traces.push({
        type: "scatter3d" as const,
        mode: "lines" as const,
        x: driftPoints.map((p) => p.x),
        y: driftPoints.map((p) => p.y),
        z: driftPoints.map((p) => p.z),
        line: { color: "#4b5563", width: 2 },
        showlegend: false,
        hoverinfo: "skip" as const,
      });
    }

    // Baseline cluster — larger cyan markers
    if (baselinePoints.length > 0) {
      traces.push({
        type: "scatter3d" as const,
        mode: "markers" as const,
        name: "Baseline",
        x: baselinePoints.map((p) => p.x),
        y: baselinePoints.map((p) => p.y),
        z: baselinePoints.map((p) => p.z),
        marker: {
          size: 8,
          color: "#06b6d4", // cyan
          symbol: "circle",
        },
        text: baselinePoints.map(
          (p) => `Step ${p.stepIndex}<br>Node: ${p.nodeId}<br>Distance: ${p.mahalanobisDistance.toFixed(2)}`
        ),
        hoverinfo: "text" as const,
        customdata: baselinePoints.map((p) => p.nodeId),
      });
    }

    // Post-baseline points — colored by step index (blue to red)
    if (trailPoints.length > 0) {
      traces.push({
        type: "scatter3d" as const,
        mode: "markers" as const,
        name: "Agent Steps",
        x: trailPoints.map((p) => p.x),
        y: trailPoints.map((p) => p.y),
        z: trailPoints.map((p) => p.z),
        marker: {
          size: 6,
          color: trailPoints.map((p) => p.stepIndex),
          colorscale: [
            [0, "#3b82f6"],
            [0.5, "#f59e0b"],
            [1, "#ef4444"],
          ],
          showscale: false,
        },
        text: trailPoints.map(
          (p) =>
            `Step ${p.stepIndex}<br>Node: ${p.nodeId}<br>Distance: ${p.mahalanobisDistance.toFixed(2)}<br>Persistence: ${p.metrics.goal_persistence.toFixed(2)}`
        ),
        hoverinfo: "text" as const,
        customdata: trailPoints.map((p) => p.nodeId),
      });
    }

    return traces;
  }, [driftPoints, baselinePoints, trailPoints]);

  // --- Drift Score Line Chart Data ---
  const driftLineData = useMemo((): Plotly.Data[] => {
    if (driftPoints.length === 0) return [];

    // Points colored: green below threshold, red above
    const colors = driftPoints.map((p) =>
      p.mahalanobisDistance > DRIFT_THRESHOLD ? "#ef4444" : "#22c55e"
    );

    return [
      // The line
      {
        type: "scatter" as const,
        mode: "lines+markers" as const,
        x: driftPoints.map((p) => p.stepIndex),
        y: driftPoints.map((p) => p.mahalanobisDistance),
        marker: { color: colors, size: 8 },
        line: { color: "#4b5563", width: 2 },
        name: "Drift Score",
        text: driftPoints.map(
          (p) => `Step ${p.stepIndex}: ${p.mahalanobisDistance.toFixed(2)}`
        ),
        hoverinfo: "text" as const,
      },
    ];
  }, [driftPoints]);

  // --- Handle clicking a point to highlight the corresponding kill chain node ---
  const handlePointClick = (event: Readonly<Plotly.PlotMouseEvent>) => {
    const point = event.points[0];
    if (point?.customdata) {
      setSelectedNode(point.customdata as string);
    }
  };

  // --- Shared Plotly layout settings ---
  const darkAxisStyle = {
    gridcolor: "#2a2d37",
    zerolinecolor: "#2a2d37",
    color: "#6b7280",
  };

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
          Behavioral drift data will appear here as the agent acts. A 3D scatter
          plot will show the agent's trajectory through embedding space.
        </p>
      ) : (
        <div className="drift-charts">
          {/* 3D Scatter Plot */}
          <div className="chart-container scatter3d-container">
            <Plot
              data={scatter3dData}
              layout={{
                autosize: true,
                margin: { l: 0, r: 0, t: 0, b: 0 },
                paper_bgcolor: "transparent",
                scene: {
                  bgcolor: "#1a1d27",
                  xaxis: { ...darkAxisStyle, title: "PC1" },
                  yaxis: { ...darkAxisStyle, title: "PC2" },
                  zaxis: { ...darkAxisStyle, title: "PC3" },
                },
                showlegend: false,
                font: { color: "#9ca3af", size: 10 },
              }}
              config={{
                displayModeBar: false,
                responsive: true,
              }}
              style={{ width: "100%", height: "100%" }}
              onClick={handlePointClick}
              useResizeHandler
            />
          </div>

          {/* Drift Score Line Chart */}
          <div className="chart-container line-chart-container">
            <Plot
              data={driftLineData}
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
                // Threshold line
                shapes: [
                  {
                    type: "line",
                    x0: 0,
                    x1: Math.max(...driftPoints.map((p) => p.stepIndex), 5),
                    y0: DRIFT_THRESHOLD,
                    y1: DRIFT_THRESHOLD,
                    line: {
                      color: "#ef4444",
                      width: 2,
                      dash: "dash",
                    },
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
              config={{
                displayModeBar: false,
                responsive: true,
              }}
              style={{ width: "100%", height: "100%" }}
              useResizeHandler
            />
          </div>
        </div>
      )}
    </div>
  );
}
