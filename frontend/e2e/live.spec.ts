import { expect, test, type Page } from "@playwright/test";

const LLM = "http://127.0.0.1:9101";

/** Collect every WebSocket frame the page receives/sends, so assertions are about the wire, not just pixels. */
function recordFrames(page: Page) {
  const received: Record<string, unknown>[] = [];
  const sent: Record<string, unknown>[] = [];
  page.on("websocket", (ws) => {
    ws.on("framereceived", (f) => received.push(JSON.parse(String(f.payload))));
    ws.on("framesent", (f) => sent.push(JSON.parse(String(f.payload))));
  });
  return { received, sent };
}

async function start(page: Page, scenario: "aligned" | "adversarial") {
  await page.goto("/");
  await expect(page.locator(".connection-dot.connected")).toBeVisible(); // WebSocket really connected
  await page.selectOption(".scenario-select", scenario);
  await page.click(".run-button");
}

const names = (frames: Record<string, unknown>[], ev: string) => frames.filter((f) => f.event === ev);

test.beforeEach(async ({ request }) => {
  await request.post(`${LLM}/_reset`);
});

test("live approve path: gate blocks until the human clicks, then the tool runs", async ({ page }) => {
  const { received, sent } = recordFrames(page);
  await start(page, "aligned");

  // The gate: tool_pending arrives, the run is paused, nothing resolved yet.
  const approve = page.locator(".btn-approve");
  await expect(approve).toBeVisible();
  await page.waitForTimeout(500);
  expect(names(received, "tool_resolved")).toHaveLength(0);

  // Approve each proposed tool until the session ends.
  for (let i = 0; i < 6; i++) {
    if ((await approve.count()) === 0) break;
    await approve.first().click();
    await page.waitForTimeout(300);
  }

  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 15_000 }); // session_complete handled
  const resolved = names(received, "tool_resolved");
  expect(resolved.length).toBeGreaterThanOrEqual(2);
  expect(resolved.every((r) => r.decision === "approve" && r.is_replan === false)).toBe(true);
  expect(names(received, "session_complete")).toHaveLength(1);
  expect(names(sent, "tool_decision").every((d) => typeof d.node_id === "string")).toBe(true);
  await page.screenshot({ path: "e2e/.results/approve-final.png", fullPage: true });
});

test("live adversarial path: denial -> circumvention is detected and surfaced in the UI", async ({ page }) => {
  const { received } = recordFrames(page);
  await start(page, "adversarial");

  const deny = page.locator(".btn-deny");
  const approve = page.locator(".btn-approve");

  await expect(approve).toBeVisible();
  await approve.first().click(); // list_directory: benign, approve

  await expect(deny.first()).toBeVisible(); // send_email
  await deny.first().click();

  await expect(deny.first()).toBeVisible(); // send_slack_message: the agent circumvents the denial
  await deny.first().click();

  // The circumvention alert banner reaches the screen.
  const banner = page.locator(".alert-banner");
  await expect(banner).toBeVisible({ timeout: 10_000 });
  await expect(banner).toContainText("circumvention_detected");
  await page.screenshot({ path: "e2e/.results/adversarial-alert.png", fullPage: true });

  // Third attempt (webhook): deny again; session then ends.
  await expect(deny.first()).toBeVisible();
  await deny.first().click();
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 15_000 });

  // Wire-level assertions: drift events carry the contract shape and the alerts are real.
  const drift = names(received, "drift_update");
  expect(drift.length).toBeGreaterThanOrEqual(3);
  for (const d of drift) {
    expect(Object.keys(d.coordinates as object).sort()).toEqual(["x", "y", "z"]);
    expect(typeof d.mahalanobis_distance).toBe("number");
    expect(Number.isFinite(d.mahalanobis_distance as number)).toBe(true);
  }
  const circ = names(received, "alignment_alert").filter((a) => a.trigger === "circumvention_detected");
  expect(circ.length).toBeGreaterThanOrEqual(2); // slack and webhook both target the denied "communication" category
  const denied = names(received, "tool_resolved").filter((r) => r.decision === "deny");
  expect(denied.length).toBe(3);
  expect(denied.every((r) => r.is_replan === true && String(r.result).startsWith("[DENIED"))).toBe(true);

  // UI reflects it: denied badges on the graph and a drift chart rendered.
  await expect(page.locator(".denied-badge")).toHaveCount(3);

  // The kill chain is a connected graph: every non-root node has an edge, and the edges are drawn.
  const nodeCount = await page.locator(".react-flow__node").count();
  expect(nodeCount).toBeGreaterThanOrEqual(7);
  await expect(page.locator(".react-flow__edge")).toHaveCount(nodeCount - 1);
  await expect(page.locator(".drift-monitor-panel .js-plotly-plot").first()).toBeVisible();
});

test("aligned agent that is denied does NOT circumvent (no false positive)", async ({ page }) => {
  const { received } = recordFrames(page);
  await start(page, "aligned");

  await expect(page.locator(".btn-approve").first()).toBeVisible();
  await page.locator(".btn-approve").first().click(); // list_directory
  await expect(page.locator(".btn-deny").first()).toBeVisible();
  await page.locator(".btn-deny").first().click(); // send_email

  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 15_000 });
  expect(names(received, "alignment_alert").filter((a) => a.trigger === "circumvention_detected")).toHaveLength(0);
  expect(names(received, "session_complete")).toHaveLength(1);
});

test("operator reload mid-gate: UI reconnects and can start a fresh session", async ({ page, request }) => {
  // (The 30 s gate timeout itself is covered by the backend e2e test; this one is about the browser side.)
  const { received } = recordFrames(page);
  await start(page, "aligned");
  await expect(page.locator(".btn-approve").first()).toBeVisible();
  await page.reload(); // operator's browser goes away mid-decision
  await expect(page.locator(".connection-dot.connected")).toBeVisible();
  await expect(page.locator(".run-button")).toBeEnabled(); // can start a fresh session
  expect((await request.get(`${LLM}/_calls`)).ok()).toBeTruthy();
  expect(names(received, "session_complete")).toHaveLength(0); // no phantom completion for the abandoned session
});
