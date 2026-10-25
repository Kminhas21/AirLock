// NodeDetail.tsx — Side drawer that shows full details for a selected node.
//
// Opens when you click a node in the kill chain or a point in the drift monitor.
// Shows: node ID, type, tool name, full reasoning context, tool parameters
// (pretty-printed JSON), risk level, decision status, and result text.

import { useSessionStore } from "../stores/sessionStore";

export function NodeDetail() {
  const selectedNodeId = useSessionStore((s) => s.selectedNodeId);
  const nodes = useSessionStore((s) => s.nodes);
  const driftPoints = useSessionStore((s) => s.driftPoints);
  const setSelectedNode = useSessionStore((s) => s.setSelectedNode);

  if (!selectedNodeId) return null;

  // Find the selected node's data
  const node = nodes.find((n) => n.id === selectedNodeId);
  if (!node) return null;

  const data = node.data;

  // Find matching drift point if one exists
  const driftPoint = driftPoints.find((p) => p.nodeId === selectedNodeId);

  // Risk level color
  const riskColor =
    data.riskLevel === "critical" || data.riskLevel === "high"
      ? "#ef4444"
      : data.riskLevel === "medium"
        ? "#f59e0b"
        : "#3b82f6";

  return (
    <div className="node-detail-overlay" onClick={() => setSelectedNode(null)}>
      <div className="node-detail-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="detail-header">
          <h3 className="detail-title">{selectedNodeId}</h3>
          <button
            className="detail-close"
            onClick={() => setSelectedNode(null)}
          >
            Close
          </button>
        </div>

        {/* Node type badge */}
        <div className="detail-row">
          <span className="detail-label">Type</span>
          <span
            className="detail-type-badge"
            style={{ color: riskColor, borderColor: riskColor }}
          >
            {data.nodeType.toUpperCase()}
          </span>
        </div>

        {/* Tool name */}
        {data.toolName && (
          <div className="detail-row">
            <span className="detail-label">Tool</span>
            <span className="detail-value">{data.toolName}</span>
          </div>
        )}

        {/* Risk level */}
        {data.riskLevel && (
          <div className="detail-row">
            <span className="detail-label">Risk Level</span>
            <span className="detail-value" style={{ color: riskColor }}>
              {data.riskLevel.toUpperCase()}
            </span>
          </div>
        )}

        {/* Decision */}
        {data.decision && (
          <div className="detail-row">
            <span className="detail-label">Decision</span>
            <span
              className="detail-value"
              style={{
                color:
                  data.decision === "approve" ? "#22c55e" : "#ef4444",
              }}
            >
              {data.decision.toUpperCase()}
            </span>
          </div>
        )}

        {/* Reasoning context */}
        {(data.reasoningContext || data.reasoningText) && (
          <div className="detail-section">
            <span className="detail-label">Reasoning</span>
            <pre className="detail-code">
              {data.reasoningContext || data.reasoningText}
            </pre>
          </div>
        )}

        {/* Tool parameters */}
        {data.toolParams && (
          <div className="detail-section">
            <span className="detail-label">Parameters</span>
            <pre className="detail-code">
              {JSON.stringify(data.toolParams, null, 2)}
            </pre>
          </div>
        )}

        {/* Result */}
        {data.result && (
          <div className="detail-section">
            <span className="detail-label">Result</span>
            <pre className="detail-code">{data.result}</pre>
          </div>
        )}

        {/* Agent response (post-denial) */}
        {data.agentResponse && (
          <div className="detail-section">
            <span className="detail-label">Agent Response</span>
            <pre className="detail-code">{data.agentResponse}</pre>
          </div>
        )}

        {/* Drift data */}
        {driftPoint && (
          <div className="detail-section">
            <span className="detail-label">Drift Metrics</span>
            <div className="detail-metrics">
              <div className="metric-row">
                <span>Mahalanobis Distance</span>
                <span
                  style={{
                    color:
                      driftPoint.mahalanobisDistance > 2.5
                        ? "#ef4444"
                        : "#22c55e",
                  }}
                >
                  {driftPoint.mahalanobisDistance.toFixed(3)}
                </span>
              </div>
              <div className="metric-row">
                <span>Compliance</span>
                <span>{driftPoint.metrics.compliance_score.toFixed(3)}</span>
              </div>
              <div className="metric-row">
                <span>Goal Persistence</span>
                <span
                  style={{
                    color:
                      driftPoint.metrics.goal_persistence > 0.3
                        ? "#f59e0b"
                        : "#9ca3af",
                  }}
                >
                  {driftPoint.metrics.goal_persistence.toFixed(3)}
                </span>
              </div>
              <div className="metric-row">
                <span>Hedging Density</span>
                <span>{driftPoint.metrics.hedging_density.toFixed(3)}</span>
              </div>
              <div className="metric-row">
                <span>Response Length</span>
                <span>{driftPoint.metrics.response_length}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
