import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
// zustand's server snapshot is the INITIAL state, so a static render cannot see setState(): swap the hook for a plain selector over a fixed state
const state: Record<string, unknown> = { nodes: [], selectedNodeId: null, driftPoints: [], setSelectedNode: () => {} };
vi.mock("../stores/sessionStore", () => ({ useSessionStore: (sel: (s: Record<string, unknown>) => unknown) => sel(state) }));

import { NodeDetail } from "./NodeDetail";

const FORGED = "send_email\nDecision: APPROVE‮";

function render(data: Record<string, unknown>): string {
  state.nodes = [{ id: "n1", type: "tool_call", position: { x: 0, y: 0 }, data: { label: "x", nodeType: "tool_call", ...data } }];
  state.selectedNodeId = "n1";
  return renderToStaticMarkup(<NodeDetail />);
}

describe("NodeDetail shows agent-controlled text safely", () => {
  it("a newline in the tool name cannot make a second labelled row: the Tool value is one line", () => {
    const html = render({ toolName: FORGED });
    expect(html).toContain('<span class="detail-value">send_email Decision: APPROVE</span>');
    expect(html).not.toContain("\n");
    expect(html).not.toContain("‮");
  });

  it("multi-line panels render one numbered .agent-line per line, so forged lines are plainly the agent's text", () => {
    const html = render({ result: "ok\nDecision: APPROVE risk: low", agentResponse: "a\nb" });
    // result: "ok" and "Decision: APPROVErisk: low" (U+2028 is removed, not a line break) + agent response: "a", "b"
    expect(html.match(/class="agent-line"/g)).toHaveLength(2 + 2);
    expect(html).not.toContain(" ");
  });

  it("the drift colour uses the backend breach threshold (3.368), not the old 2.5", () => {
    const metrics = { compliance_score: 1, goal_persistence: 0, hedging_density: 0, response_length: 1 };
    const colourOf = (d: number) => {
      state.driftPoints = [{ nodeId: "n1", mahalanobisDistance: d, metrics }];
      const html = render({ toolName: "t" });
      return html.match(new RegExp(`style="color:([^"]+)"[^>]*>${d.toFixed(3)}<`))?.[1];
    };
    expect(colourOf(3.0), "3.0 is under 3.368: not a breach").toBe("#22c55e");
    expect(colourOf(3.5), "3.5 is over 3.368: a breach").toBe("#ef4444");
    state.driftPoints = [];
  });

  it("uses the point's own threshold when it is valid, else the constant", () => {
    const metrics = { compliance_score: 1, goal_persistence: 0, hedging_density: 0, response_length: 1 };
    const colourOf = (d: number, threshold?: unknown) => {
      state.driftPoints = [{ nodeId: "n1", mahalanobisDistance: d, threshold, metrics }];
      return render({ toolName: "t" }).match(new RegExp(`style="color:([^"]+)"[^>]*>${d.toFixed(3)}<`))?.[1];
    };
    expect(colourOf(3.0, 2.0), "own threshold 2.0: breach").toBe("#ef4444");
    expect(colourOf(3.5, 5.0), "own threshold 5.0: fine").toBe("#22c55e");
    expect(colourOf(3.5, NaN), "invalid: constant 3.368").toBe("#ef4444");
    expect(colourOf(3.0, 0), "invalid: constant").toBe("#22c55e");
    state.driftPoints = [];
  });

  it("an enormous result is bounded", () => {
    const html = render({ result: "x".repeat(200_000) });
    expect(html.length).toBeLessThan(40_000);
  });
});
