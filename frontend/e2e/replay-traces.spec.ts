import { expect, test } from "@playwright/test";
import { API, LLM, evs, loadExpected, loadTraces, recordFrames, replayIds } from "./helpers/traces";

// Parity mode: the real UI + WebSocket + backend replay recorded evaluation traces; the live monitor's alerts must
// equal the offline detector's (EXPECTED_ALERTS_JSON, from eval.dump_expectations) and arrive BEFORE the human decision.

const traces = loadTraces();
const ids = replayIds(traces);
const expected = loadExpected(ids);
const EXPECT_EMBEDDER = process.env.EXPECT_EMBEDDER ?? "minilm";

test("backend reports the expected embedder (a silent stub fallback must fail)", async ({ request }) => {
  const h = await (await request.get(`${API}/health`)).json();
  expect(h.status).toBe("ok");
  expect(h.embedder, JSON.stringify(h)).toBe(EXPECT_EMBEDDER);
});

for (const id of ids) {
  test(`replay ${id}: live alerts == offline expectations, before the decision`, async ({ page, request }) => {
    const trace = traces.find((t) => t.id === id)!;
    const exp = expected[id];
    expect(exp, `no expectations for ${id}`).toBeTruthy();
    const info = await (await request.get(`${LLM}/_trace_info?id=${id}`)).json();
    const nTurns: number = info.turns.length;
    // the human acts strictly per the recorded decisions
    const decisions = trace.steps.filter((s) => s.proposal).map((s) => s.proposal!.decision);
    expect(info.turns.map((t: { decision: string }) => t.decision)).toEqual(decisions);
    expect(exp.decisions).toEqual(decisions);

    const frames = recordFrames(page);
    await page.goto("/");
    await expect(page.locator(".connection-dot.connected")).toBeVisible();
    await page.fill(".task-input", `TRACE:${id}`);
    await page.click(".run-button");

    for (let k = 0; k < nTurns; k++) {
      await expect.poll(() => evs(frames, "tool_pending", "in").length, { timeout: 20_000, message: `pending #${k}` }).toBeGreaterThan(k);
      const btn = decisions[k] === "approve" ? ".btn-approve" : ".btn-deny";
      await expect(page.locator(btn).first()).toBeVisible();
      await page.locator(btn).first().click();
      await expect.poll(() => evs(frames, "tool_resolved", "in").length, { timeout: 20_000, message: `resolved #${k}` }).toBeGreaterThan(k);
    }
    await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 20_000 });

    // ---- (d) exactly one session_complete, and it is the last server frame
    const complete = evs(frames, "session_complete", "in");
    expect(complete).toHaveLength(1);
    expect(frames.filter((f) => f.dir === "in").at(-1)!.data.event).toBe("session_complete");

    // node -> proposal ordinal, and the decision actually sent for each
    const pending = evs(frames, "tool_pending", "in");
    expect(pending).toHaveLength(nTurns);
    const ordinal = new Map(pending.map((f, k) => [f.data.node_id as string, k]));
    const decisionFrame = new Map(evs(frames, "tool_decision", "out").map((f) => [f.data.node_id as string, f]));
    pending.forEach((p, k) => {
      expect(decisionFrame.get(p.data.node_id as string)?.data.decision, `decision for pending #${k}`).toBe(decisions[k]);
    });

    // ---- alerts that the offline detector can be compared with: everything but goal_persistence
    const alerts = evs(frames, "alignment_alert", "in").filter((f) => f.data.trigger !== "goal_persistence");
    const stepOf = (nodeId: string) => info.turns[ordinal.get(nodeId)!].proposal_step as number;
    for (const a of alerts) {
      const nodeId = a.data.linked_node_id as string;
      expect(ordinal.has(nodeId), `alert ${a.data.trigger} refers to a non-proposal node ${nodeId}`).toBe(true);
      const dec = decisionFrame.get(nodeId)!;
      // (b) alert-before-decision, in frame order and in time
      expect(a.seq, `alert for ${nodeId} must precede its decision`).toBeLessThan(dec.seq);
      expect(a.t).toBeLessThanOrEqual(dec.t);
      expect(a.seq).toBeLessThan(pending[ordinal.get(nodeId)!].seq); // emitted before its own tool_pending
    }
    // (a) set equality with the offline expectations (steps alerted before their decision)
    const liveSteps = [...new Set(alerts.map((a) => stepOf(a.data.linked_node_id as string)))].sort((x, y) => x - y);
    expect(liveSteps, `live alert steps vs offline ${JSON.stringify(exp.alert_steps)} (${trace.category})`).toEqual(
      [...exp.alert_steps].sort((x, y) => x - y),
    );
    // (c) no alert after the decision of the node it is about (a later alert must belong to a NEW proposal)
    for (const a of evs(frames, "alignment_alert", "in")) {
      const nodeId = a.data.linked_node_id as string;
      const dec = decisionFrame.get(nodeId);
      if (dec) expect(a.seq, `late alert ${a.data.trigger} for already-decided ${nodeId}`).toBeLessThan(dec.seq);
    }
  });
}
