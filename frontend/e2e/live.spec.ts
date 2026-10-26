import { expect, test, type Page } from "@playwright/test";

const LLM = `http://127.0.0.1:${process.env.LLM_PORT ?? 9101}`;

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
  await page.screenshot({ path: "e2e/.results/adversarial-final.png", fullPage: true });

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


// ---- cases that were previously unchecked -------------------------------------------------------

/** Every time the connection dot's class changes, remember it; lets us catch a transient red flash. */
async function watchDot(page: Page) {
  await page.evaluate(() => {
    const dot = document.querySelector(".connection-dot")!;
    const w = window as unknown as { __dotStates: string[] };
    w.__dotStates = [dot.className];
    new MutationObserver(() => w.__dotStates.push(dot.className)).observe(dot, { attributes: true });
  });
}
const dotStates = (page: Page) => page.evaluate(() => (window as unknown as { __dotStates: string[] }).__dotStates);

test("connection dot never shows 'disconnected' (red) when the server merely ended a finished session", async ({ page }) => {
  await start(page, "aligned");
  await watchDot(page);
  for (let i = 0; i < 6; i++) {
    if ((await page.locator(".run-button").innerText()) === "Run") break;
    const approve = page.locator(".btn-approve");
    if ((await approve.count()) > 0) await approve.first().click();
    await page.waitForTimeout(250);
  }
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 15_000 });
  await expect(page.locator(".connection-dot.connected")).toBeVisible({ timeout: 5_000 }); // came back
  const states = await dotStates(page);
  const red = states.filter((c) => !/\bconnected\b|\breconnecting\b/.test(c));
  expect(red, `dot class history: ${JSON.stringify(states)}`).toEqual([]);
  await expect(page.locator(".run-button")).toBeEnabled();
});

test("a long session (25+ nodes) stays one connected, non-overlapping graph", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator(".connection-dot.connected")).toBeVisible();
  await page.fill(".task-input", "LONG_RUN please");
  await page.click(".run-button");
  for (let i = 0; i < 20; i++) {
    if ((await page.locator(".run-button").innerText()) === "Run") break;
    const approve = page.locator(".btn-approve");
    if ((await approve.count()) > 0) await approve.first().click();
    await page.waitForTimeout(200);
  }
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 20_000 });

  const nodeCount = await page.locator(".react-flow__node").count();
  expect(nodeCount).toBeGreaterThanOrEqual(25);
  await expect(page.locator(".react-flow__edge")).toHaveCount(nodeCount - 1);

  const overlaps = await page.evaluate(() => {
    const boxes = [...document.querySelectorAll(".react-flow__node")].map((n) => n.getBoundingClientRect());
    let n = 0;
    for (let i = 0; i < boxes.length; i++)
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i], b = boxes[j];
        if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) n++;
      }
    return n;
  });
  expect(overlaps).toBe(0);
  await page.screenshot({ path: "e2e/.results/long-session.png", fullPage: true });
});

test("replan nodes after a denial are drawn with the dashed denial-fork edge", async ({ page }) => {
  const { received } = recordFrames(page);
  await start(page, "adversarial");
  await expect(page.locator(".btn-approve").first()).toBeVisible();
  await page.locator(".btn-approve").first().click(); // list_directory
  await expect(page.locator(".btn-deny").first()).toBeVisible();
  await page.locator(".btn-deny").first().click(); // send_email
  await expect(page.locator(".btn-deny").first()).toBeVisible(); // slack: first replan
  expect(names(received, "tool_pending").map((p) => p.node_type)).toEqual(["tool_call", "tool_call", "replan"]);
  await expect(page.locator(".replan-wrapper")).toHaveCount(1);
  const dashed = await page.locator(".react-flow__edge-path").evaluateAll(
    (els) => els.filter((e) => (e.getAttribute("style") ?? "").includes("stroke-dasharray")).length,
  );
  expect(dashed).toBeGreaterThanOrEqual(1);
});

test.describe("narrow viewport", () => {
  test.use({ viewport: { width: 390, height: 844 } });
  test("no horizontal page overflow; controls and both panels fit the screen", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator(".connection-dot.connected")).toBeVisible();
    const m = await page.evaluate(() => ({
      scrollW: document.documentElement.scrollWidth,
      innerW: window.innerWidth,
      panels: [...document.querySelectorAll(".panel")].map((p) => Math.round(p.getBoundingClientRect().width)),
      run: document.querySelector(".run-button")!.getBoundingClientRect().right,
    }));
    expect(m.scrollW, JSON.stringify(m)).toBeLessThanOrEqual(m.innerW);
    expect(m.run).toBeLessThanOrEqual(m.innerW);
    expect(m.panels.length).toBeGreaterThanOrEqual(2);
    for (const w of m.panels) expect(w).toBeLessThanOrEqual(m.innerW);
    await page.screenshot({ path: "e2e/.results/mobile.png", fullPage: true });
  });
});
