import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { freePort, ROOT, sh, shooter, startStack, type Stack } from "./lib";

// W10: is the drift monitor LIVE, REAL and NOVEL?
//  * real embedding model: /health says minilm, and an INDEPENDENT recomputation (fresh MiniLM + the seismograph code, outside the server) reproduces
//    the numbers the browser plotted;
//  * novel: the LLM stand-in invents fresh text per run (tests/browser/novel_llm.py), nothing in it appears in any recorded trace or cached run;
//  * live websockets: the UI sends mode "live" (never "replay"), and the chart is exactly the drift_update frames received for THIS run;
//  * not cached: a second run on the same page replaces the first run's points.
// The same checks run against a REAL model through OpenRouter when OPENROUTER_API_KEY is set (skipped otherwise).

interface Drift { node_id: string; step_index: number; coordinates: { x: number; y: number }; mahalanobis_distance: number }
const RECORDED = [path.join(ROOT, "eval/final/traces.json"), ...(existsSync(path.join(ROOT, "demo/cached_runs")) ? readdirSync(path.join(ROOT, "demo/cached_runs")).map((f) => path.join(ROOT, "demo/cached_runs", f)) : [])];
const recordedText = RECORDED.filter((f) => existsSync(f)).map((f) => readFileSync(f, "utf8")).join("\n");

function recorder(page: Page) {
  const got: Record<string, unknown>[] = [], sent: Record<string, unknown>[] = [];
  page.on("websocket", (ws) => {
    if (!ws.url().endsWith("/ws")) return;
    ws.on("framereceived", (f) => got.push(JSON.parse(String(f.payload))));
    ws.on("framesent", (f) => sent.push(JSON.parse(String(f.payload))));
  });
  return { got, sent };
}

/** Click Run and decide every pending tool call (approve the first two, deny the rest) until the run ends. */
async function driveRun(page: Page, task: string, scenario = "adversarial", maxSeconds = 150) {
  await expect(page.locator(".connection-dot.connected")).toBeVisible({ timeout: 30_000 });
  await page.selectOption(".scenario-select", scenario);
  await page.click(".run-button");
  let decided = 0;
  const end = Date.now() + maxSeconds * 1000;
  while (Date.now() < end) {
    if ((await page.locator(".run-button").innerText()).trim() === "Run" && decided > 0) return decided;
    const approve = page.locator(".btn-approve"), deny = page.locator(".btn-deny");
    if ((await deny.count()) > 0) {
      if (decided < 2) await approve.first().click(); else await deny.first().click();
      decided++;
    }
    await page.waitForTimeout(250);
  }
  throw new Error("run did not finish");
}

/** What the browser actually plotted: the two Plotly charts' data (read from the live Plotly graph div). */
async function plotted(page: Page) {
  return page.evaluate(() => {
    const gds = [...document.querySelectorAll<HTMLElement & { data?: { x: number[]; y: number[]; name?: string; mode?: string }[] }>(".js-plotly-plot")];
    const traj = gds.flatMap((g) => g.data ?? []).find((t) => t.mode === "lines" && t.name === undefined);
    const drift = gds.flatMap((g) => g.data ?? []).find((t) => t.name === "Drift Score");
    return { x: traj?.x ?? [], y: traj?.y ?? [], dist: drift?.y ?? [], steps: drift?.x ?? [] };
  });
}

function checkRun(frames: Record<string, unknown>[], chart: Awaited<ReturnType<typeof plotted>>, label: string) {
  const drift = frames.filter((f) => f.event === "drift_update") as unknown as Drift[];
  expect(drift.length, `${label}: the run produced drift updates`).toBeGreaterThanOrEqual(4);
  // the chart IS the wire: same count, same values, same order
  expect(chart.dist, `${label}: drift line == wire`).toHaveLength(drift.length);
  drift.forEach((d, i) => {
    expect(chart.dist[i]).toBeCloseTo(d.mahalanobis_distance, 9);
    expect(chart.x[i]).toBeCloseTo(d.coordinates.x, 9);
    expect(chart.y[i]).toBeCloseTo(d.coordinates.y, 9);
  });
  // independent recomputation with a fresh real MiniLM
  // The text the server embedded for each step: the model's reasoning, or (when it returned tool calls with no text) "Calling tools: a, b"
  // built from the tool_pending frames of that turn (server/agent_loop.py).
  const reasoning = new Map((frames.filter((f) => f.event === "reasoning") as { node_id: string; text: string }[]).map((r) => [r.node_id, r.text]));
  const toolsAfter: string[][] = [];
  for (const f of frames) {
    if (f.event === "drift_update") toolsAfter.push([]);
    else if (f.event === "tool_pending" && toolsAfter.length) toolsAfter[toolsAfter.length - 1].push(f.tool_name as string);
  }
  const pairs = drift.map((d, i) => [d.node_id, reasoning.get(d.node_id) ?? `Calling tools: ${toolsAfter[i].join(", ")}`]);
  const modelText = drift.map((d) => reasoning.get(d.node_id)).filter((t): t is string => typeof t === "string");
  const r = sh("python", [path.join(process.cwd(), "journeys/tools/recompute_drift.py")], { input: JSON.stringify(pairs) });
  expect(r.code, r.out.slice(-800)).toBe(0);
  const again = JSON.parse(r.stdout.trim().split("\n").pop() as string) as Drift[];
  again.forEach((a, i) => {
    expect(a.mahalanobis_distance).toBeCloseTo(drift[i].mahalanobis_distance, 4);
    expect(a.coordinates.x).toBeCloseTo(drift[i].coordinates.x, 4);
    expect(a.coordinates.y).toBeCloseTo(drift[i].coordinates.y, 4);
  });
  const texts = modelText;
  texts.forEach((t) => expect(recordedText.includes(t), `not in any recorded trace/cached run: ${t.slice(0, 50)}`).toBe(false));
  return texts;
}

test.describe("W10 live drift", () => {
  test("novel responses, real MiniLM: chart == wire == independent recomputation; a second run replaces the first", async ({ page }) => {
    const shot = shooter("W10-live-drift-novel");
    const port = await freePort();
    const llm: ChildProcess = spawn("python", [path.join(ROOT, "tests/browser/novel_llm.py"), String(port)], { cwd: ROOT });
    for (let i = 0; i < 80; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/_texts`)).ok) break; } catch { /* wait */ } await new Promise((r) => setTimeout(r, 250)); }
    const stack: Stack = await startStack({ OPENROUTER_API_KEY: "test-key", OPENROUTER_BASE_URL: `http://127.0.0.1:${port}/v1` });
    try {
      const health = await (await fetch(`${stack.url}/health`)).json();
      expect(health.embedder).toBe("minilm");
      await page.goto(stack.url);
      const rec = recorder(page);
      await driveRun(page, "Summarize the project files and send a status report to alice@team.com");
      const chart1 = await plotted(page);
      const first = rec.got.splice(0);
      const texts1 = checkRun(first, chart1, "run 1");
      await shot(page, "run-1-drift-chart-from-live-novel-text");
      const started1 = rec.sent.filter((f) => f.event === "start_task");
      expect(started1.every((f) => f.mode === "live")).toBe(true);

      await driveRun(page, "Summarize the project files and send a status report to alice@team.com");
      const chart2 = await plotted(page);
      const second = rec.got.splice(0);
      const texts2 = checkRun(second, chart2, "run 2");
      await shot(page, "run-2-replaced-the-first-run");
      expect(chart2.dist).not.toEqual(chart1.dist);                           // different text -> different numbers: nothing is cached
      expect(texts2.filter((t) => texts1.includes(t))).toHaveLength(0);          // the second run's text is new
      const produced = (await (await fetch(`http://127.0.0.1:${port}/_texts`)).json()) as string[];
      [...texts1, ...texts2].forEach((t) => expect(produced).toContain(t));     // every plotted step came from the LLM call made just now
      expect(rec.sent.filter((f) => f.event === "start_task").every((f) => f.mode === "live")).toBe(true);
    } finally { llm.kill(); await stack.stop(); }
  });

  test("a REAL model through OpenRouter: the same checks on text nobody scripted", async ({ page }) => {
    test.skip(!process.env.OPENROUTER_API_KEY, "set OPENROUTER_API_KEY to run the real-model smoke test");
    const shot = shooter("W10-live-drift-real-model");
    const stack = await startStack({ OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY as string, SENTINEL_DEFAULT_MODEL: "gpt-4o-mini" });
    try {
      expect((await (await fetch(`${stack.url}/health`)).json()).embedder).toBe("minilm");
      await page.goto(stack.url);
      const rec = recorder(page);
      await driveRun(page, "Summarize the project files and send a status report to alice@team.com", "adversarial", 170);
      const chart = await plotted(page);
      const frames = rec.got.splice(0);
      checkRun(frames, chart, "real model");
      expect(frames.some((f) => f.event === "error"), "no error event from the provider").toBe(false);
      await shot(page, "real-model-drift-chart");
      expect(rec.sent.filter((f) => f.event === "start_task").every((f) => f.mode === "live")).toBe(true);
    } finally { await stack.stop(); }
  });
});
