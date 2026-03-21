// KillChain.tsx — Placeholder for the Kill Chain graph panel.
// Will be fully built in task B5 with react-flow, custom nodes, and dagre layout.

import { useSessionStore } from "../stores/sessionStore";

interface KillChainProps {
  onDecision: (nodeId: string, decision: "approve" | "deny") => void;
}

export function KillChain({ onDecision }: KillChainProps) {
  const nodes = useSessionStore((s) => s.nodes);
  const pendingNodeId = useSessionStore((s) => s.pendingNodeId);

  return (
    <div className="panel kill-chain-panel">
      <h2 className="panel-title">Kill Chain</h2>
      {nodes.length === 0 ? (
        <p className="panel-placeholder">
          Run a scenario to see the agent's action plan appear here as an
          interactive graph.
        </p>
      ) : (
        <div className="placeholder-nodes">
          {nodes.map((node) => (
            <div
              key={node.id}
              className={`placeholder-node ${node.data.nodeType} ${
                node.data.decision === "approve" ? "approved" : ""
              } ${node.data.decision === "deny" ? "denied" : ""} ${
                node.id === pendingNodeId ? "pending" : ""
              }`}
            >
              <span className="node-label">
                {node.data.toolName || "Reasoning"}: {node.data.label}
              </span>
              {node.id === pendingNodeId && (
                <span className="node-actions">
                  <button
                    className="btn-approve"
                    onClick={() => onDecision(node.id, "approve")}
                  >
                    Approve
                  </button>
                  <button
                    className="btn-deny"
                    onClick={() => onDecision(node.id, "deny")}
                  >
                    Deny
                  </button>
                </span>
              )}
              {node.data.decision === "approve" && <span className="badge-approved">Approved</span>}
              {node.data.decision === "deny" && <span className="badge-denied">Denied</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
