// sessionStore.ts — Zustand store that holds ALL application state.
//
// Think of this as a central "database" for the UI. Every component reads from
// here and the WebSocket hook writes to here. This means components don't need
// to pass data to each other through props — they all share this store.

import { create } from "zustand";
import type { Node, Edge } from "@xyflow/react";
import type {
  ReasoningEvent,
  ToolPendingEvent,
  ToolResolvedEvent,
  DriftUpdateEvent,
  AlignmentAlertEvent,
  Decision,
} from "../types/contracts";

// ---------- Types for our stored data ----------

/** Extra data we attach to each react-flow node beyond what react-flow needs. */
export type NodeData = {
  label: string;
  nodeType: "reasoning" | "tool_call" | "replan";
  toolName?: string;
  toolParams?: Record<string, unknown>;
  riskLevel?: string;
  reasoningContext?: string;
  reasoningText?: string;
  decision?: Decision;
  result?: string;
  agentResponse?: string;
  isPending: boolean;
  isAlertTarget: boolean;
};

/** One point on the drift monitor chart. */
export interface DriftPoint {
  stepIndex: number;
  nodeId: string;
  x: number;
  y: number;
  z: number;
  mahalanobisDistance: number;
  baselineBreached: boolean;
  metrics: {
    compliance_score: number;
    goal_persistence: number;
    hedging_density: number;
    response_length: number;
  };
}

// ---------- Store interface ----------

interface SessionState {
  // Kill chain graph
  nodes: Node<NodeData>[];
  edges: Edge[];
  pendingNodeId: string | null;

  // Drift monitor
  driftPoints: DriftPoint[];
  currentDriftScore: number;

  // Alerts
  alerts: AlignmentAlertEvent[];
  activeAlert: AlignmentAlertEvent | null;

  // Session
  isRunning: boolean;
  selectedNodeId: string | null;

  // Actions — these are functions that update the state
  handleReasoningEvent: (e: ReasoningEvent) => void;
  handleToolPendingEvent: (e: ToolPendingEvent) => void;
  handleToolResolvedEvent: (e: ToolResolvedEvent) => void;
  handleDriftUpdateEvent: (e: DriftUpdateEvent) => void;
  handleAlignmentAlertEvent: (e: AlignmentAlertEvent) => void;
  setSelectedNode: (id: string | null) => void;
  setIsRunning: (running: boolean) => void;
  reset: () => void;
}

// ---------- Helper: calculate position for a new node ----------
// We'll use dagre for proper layout later in the KillChain component.
// Here we just need to add nodes — dagre will position them.

let nodeYCounter = 0;

// ---------- The store ----------

export const useSessionStore = create<SessionState>((set) => ({
  // Initial state
  nodes: [],
  edges: [],
  pendingNodeId: null,
  driftPoints: [],
  currentDriftScore: 0,
  alerts: [],
  activeAlert: null,
  isRunning: false,
  selectedNodeId: null,

  // --- Action: handle a "reasoning" event from the server ---
  // Adds a blue reasoning node to the kill chain graph.
  handleReasoningEvent: (e) =>
    set((state) => {
      const newNode: Node<NodeData> = {
        id: e.node_id,
        type: "reasoning",
        position: { x: 0, y: nodeYCounter++ * 120 },
        data: {
          label: e.text.slice(0, 80) + (e.text.length > 80 ? "..." : ""),
          nodeType: "reasoning",
          reasoningText: e.text,
          isPending: false,
          isAlertTarget: false,
        },
      };

      const newEdges = [...state.edges];
      if (e.parent_id) {
        newEdges.push({
          id: `edge-${e.parent_id}-${e.node_id}`,
          source: e.parent_id,
          target: e.node_id,
          type: "default",
          animated: false,
        });
      }

      return { nodes: [...state.nodes, newNode], edges: newEdges };
    }),

  // --- Action: handle a "tool_pending" event ---
  // Adds a tool node with approve/deny buttons. This is the node that
  // "pauses" and waits for the user to click Approve or Deny.
  handleToolPendingEvent: (e) =>
    set((state) => {
      const isReplan = e.node_type === "replan";
      const newNode: Node<NodeData> = {
        id: e.node_id,
        type: isReplan ? "replan" : "tool",
        position: { x: 0, y: nodeYCounter++ * 120 },
        data: {
          label: e.tool_name,
          nodeType: isReplan ? "replan" : "tool_call",
          toolName: e.tool_name,
          toolParams: e.tool_params,
          riskLevel: e.risk_level,
          reasoningContext: e.reasoning_context,
          isPending: true,
          isAlertTarget: false,
        },
      };

      const newEdges = [...state.edges];
      if (e.parent_id) {
        // If this is a replan node, the edge from the denied parent is dashed red
        const parentNode = state.nodes.find((n) => n.id === e.parent_id);
        const isDenialFork =
          parentNode?.data?.decision === "deny" || isReplan;

        newEdges.push({
          id: `edge-${e.parent_id}-${e.node_id}`,
          source: e.parent_id,
          target: e.node_id,
          type: "default",
          animated: isDenialFork,
          style: isDenialFork
            ? { stroke: "#EF4444", strokeDasharray: "5,5" }
            : undefined,
        });
      }

      return {
        nodes: [...state.nodes, newNode],
        edges: newEdges,
        pendingNodeId: e.node_id,
      };
    }),

  // --- Action: handle a "tool_resolved" event ---
  // Updates an existing node with the decision result (approved or denied).
  handleToolResolvedEvent: (e) =>
    set((state) => ({
      nodes: state.nodes.map((node) =>
        node.id === e.node_id
          ? {
              ...node,
              data: {
                ...node.data,
                decision: e.decision,
                result: e.result,
                agentResponse: e.agent_response,
                isPending: false,
              },
            }
          : node
      ),
      pendingNodeId:
        state.pendingNodeId === e.node_id ? null : state.pendingNodeId,
    })),

  // --- Action: handle a "drift_update" event ---
  // Adds a point to the drift monitor charts.
  handleDriftUpdateEvent: (e) =>
    set((state) => ({
      driftPoints: [
        ...state.driftPoints,
        {
          stepIndex: e.step_index,
          nodeId: e.node_id,
          x: e.coordinates.x,
          y: e.coordinates.y,
          z: e.coordinates.z,
          mahalanobisDistance: e.mahalanobis_distance,
          baselineBreached: e.baseline_breached,
          metrics: e.metrics,
        },
      ],
      currentDriftScore: e.mahalanobis_distance,
    })),

  // --- Action: handle an "alignment_alert" event ---
  // Shows the alert banner and highlights the linked node in the kill chain.
  handleAlignmentAlertEvent: (e) =>
    set((state) => ({
      alerts: [...state.alerts, e],
      activeAlert: e,
      // Mark the linked node as an alert target (pulsing red border)
      nodes: state.nodes.map((node) =>
        node.id === e.linked_node_id
          ? { ...node, data: { ...node.data, isAlertTarget: true } }
          : node
      ),
    })),

  // --- Action: select a node (for the detail drawer) ---
  setSelectedNode: (id) => set({ selectedNodeId: id }),

  // --- Action: set running state ---
  setIsRunning: (running) => set({ isRunning: running }),

  // --- Action: reset everything for a new session ---
  reset: () => {
    nodeYCounter = 0;
    set({
      nodes: [],
      edges: [],
      pendingNodeId: null,
      driftPoints: [],
      currentDriftScore: 0,
      alerts: [],
      activeAlert: null,
      isRunning: false,
      selectedNodeId: null,
    });
  },
}));
