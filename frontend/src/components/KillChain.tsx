// KillChain.tsx — Interactive directed graph showing the agent's action plan.
//
// Uses @xyflow/react (react-flow v12) to render nodes as a graph.
// Uses dagre to auto-layout nodes top-to-bottom so they don't overlap.
//
// Node types:
// - ReasoningNode: Blue, shows the agent's thinking
// - ToolNode: Amber/red based on risk, has Approve/Deny buttons when pending
// - ReplanNode: Same as ToolNode but with dashed orange border (appears after denial)

import { useCallback, useEffect, useMemo } from "react";
import {
  ReactFlow,
  Background,
  type Node,
  type Edge,
  type NodeTypes,
  type NodeProps,
  useReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { useSessionStore, type NodeData } from "../stores/sessionStore";

// ===== DAGRE LAYOUT =====
// dagre is a library that automatically positions nodes in a directed graph.
// Without it, all nodes would stack on top of each other at position (0,0).
// We run this every time the node list changes.

const NODE_WIDTH = 280;
const NODE_HEIGHT = 80;

function getLayoutedElements(nodes: Node<NodeData>[], edges: Edge[]) {
  if (nodes.length === 0) return { nodes: [], edges: [] };

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({
    rankdir: "TB", // Top-to-Bottom layout
    ranksep: 60, // Vertical spacing between rows
    nodesep: 40, // Horizontal spacing between nodes in the same row
  });

  // Tell dagre about each node's size
  nodes.forEach((node) => {
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  // Tell dagre about each edge
  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target);
  });

  // Run the layout algorithm
  dagre.layout(g);

  // Apply the calculated positions back to our react-flow nodes
  const layoutedNodes = nodes.map((node) => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: {
        x: pos.x - NODE_WIDTH / 2,
        y: pos.y - NODE_HEIGHT / 2,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// ===== CUSTOM NODE: Reasoning =====
// Blue rounded rectangle showing the agent's chain-of-thought text.

function ReasoningNode({ data, id }: NodeProps<Node<NodeData>>) {
  const selectedNodeId = useSessionStore((s) => s.selectedNodeId);
  const setSelectedNode = useSessionStore((s) => s.setSelectedNode);
  const isSelected = selectedNodeId === id;

  return (
    <div
      className={`flow-node reasoning-node ${isSelected ? "selected" : ""}`}
      onClick={() => setSelectedNode(isSelected ? null : id)}
    >
      <div className="flow-node-header">
        <span className="flow-node-type-badge reasoning-badge">REASONING</span>
      </div>
      <div className="flow-node-body">{data.label}</div>
    </div>
  );
}

// ===== CUSTOM NODE: Tool Call =====
// Colored by risk level. Shows Approve/Deny buttons when pending.

function ToolNode({ data, id }: NodeProps<Node<NodeData>>) {
  const pendingNodeId = useSessionStore((s) => s.pendingNodeId);
  const selectedNodeId = useSessionStore((s) => s.selectedNodeId);
  const setSelectedNode = useSessionStore((s) => s.setSelectedNode);
  const isPending = pendingNodeId === id;
  const isSelected = selectedNodeId === id;

  // We need to get the onDecision callback from the component tree.
  // We'll use a global event approach since react-flow custom nodes
  // can't easily receive props from the parent component.
  const handleApprove = (e: React.MouseEvent) => {
    e.stopPropagation();
    window.dispatchEvent(
      new CustomEvent("sentinel-decision", {
        detail: { nodeId: id, decision: "approve" },
      })
    );
  };

  const handleDeny = (e: React.MouseEvent) => {
    e.stopPropagation();
    window.dispatchEvent(
      new CustomEvent("sentinel-decision", {
        detail: { nodeId: id, decision: "deny" },
      })
    );
  };

  const riskClass =
    data.riskLevel === "high" || data.riskLevel === "critical"
      ? "risk-high"
      : "risk-medium";

  return (
    <div
      className={`flow-node tool-node ${riskClass} ${
        isPending ? "pending" : ""
      } ${data.decision === "approve" ? "approved" : ""} ${
        data.decision === "deny" ? "denied" : ""
      } ${data.isAlertTarget ? "alert-target" : ""} ${
        isSelected ? "selected" : ""
      }`}
      onClick={() => setSelectedNode(isSelected ? null : id)}
    >
      <div className="flow-node-header">
        <span className={`flow-node-type-badge ${riskClass}-badge`}>
          {data.toolName?.toUpperCase()}
        </span>
        <span className="risk-label">{data.riskLevel}</span>
        {data.decision === "approve" && (
          <span className="decision-badge approved-badge">Approved</span>
        )}
        {data.decision === "deny" && (
          <span className="decision-badge denied-badge">Denied</span>
        )}
      </div>
      <div className="flow-node-body">
        {data.toolParams
          ? JSON.stringify(data.toolParams).slice(0, 60) + "..."
          : data.label}
      </div>
      {isPending && (
        <div className="flow-node-actions">
          <button className="btn-approve" onClick={handleApprove}>
            Approve
          </button>
          <button className="btn-deny" onClick={handleDeny}>
            Deny
          </button>
        </div>
      )}
    </div>
  );
}

// ===== CUSTOM NODE: Replan =====
// Same as ToolNode but with a dashed orange border.

function ReplanNode(props: NodeProps<Node<NodeData>>) {
  return (
    <div className="replan-wrapper">
      <ToolNode {...props} />
    </div>
  );
}

// ===== NODE TYPE REGISTRY =====
// react-flow needs to know which component to render for each node type.

const nodeTypes: NodeTypes = {
  reasoning: ReasoningNode,
  tool: ToolNode,
  replan: ReplanNode,
};

// ===== INNER COMPONENT (needs ReactFlowProvider) =====

function KillChainInner({
  onDecision,
}: {
  onDecision: (nodeId: string, decision: "approve" | "deny") => void;
}) {
  const storeNodes = useSessionStore((s) => s.nodes);
  const storeEdges = useSessionStore((s) => s.edges);
  const { fitView } = useReactFlow();

  // Apply dagre layout whenever nodes/edges change
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(
    () => getLayoutedElements(storeNodes, storeEdges),
    [storeNodes, storeEdges]
  );

  // Auto-fit the view when nodes change
  useEffect(() => {
    if (layoutedNodes.length > 0) {
      // Small timeout to let react-flow render the nodes first
      const timer = setTimeout(() => fitView({ padding: 0.2 }), 50);
      return () => clearTimeout(timer);
    }
  }, [layoutedNodes.length, fitView]);

  // Listen for decision events from custom nodes
  useEffect(() => {
    const handler = (e: Event) => {
      const { nodeId, decision } = (e as CustomEvent).detail;
      onDecision(nodeId, decision);
    };
    window.addEventListener("sentinel-decision", handler);
    return () => window.removeEventListener("sentinel-decision", handler);
  }, [onDecision]);

  return (
    <ReactFlow
      nodes={layoutedNodes}
      edges={layoutedEdges}
      nodeTypes={nodeTypes}
      fitView
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      minZoom={0.3}
      maxZoom={1.5}
      defaultEdgeOptions={{
        style: { stroke: "#4b5563", strokeWidth: 2 },
        type: "default",
      }}
    >
      <Background color="#2a2d37" gap={20} />
    </ReactFlow>
  );
}

// ===== EXPORTED COMPONENT =====

interface KillChainProps {
  onDecision: (nodeId: string, decision: "approve" | "deny") => void;
}

export function KillChain({ onDecision }: KillChainProps) {
  const nodes = useSessionStore((s) => s.nodes);

  // Stabilize the callback reference so it doesn't change on every render
  const stableOnDecision = useCallback(onDecision, [onDecision]);

  return (
    <div className="panel kill-chain-panel">
      <h2 className="panel-title">Kill Chain</h2>
      {nodes.length === 0 ? (
        <p className="panel-placeholder">
          Run a scenario to see the agent's action plan appear here as an
          interactive graph.
        </p>
      ) : (
        <div style={{ flex: 1, minHeight: 0 }}>
          <ReactFlowProvider>
            <KillChainInner onDecision={stableOnDecision} />
          </ReactFlowProvider>
        </div>
      )}
    </div>
  );
}
