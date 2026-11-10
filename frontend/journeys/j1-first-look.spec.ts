import { type ChildProcess, spawn } from "node:child_process";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { freePort, ROOT, shooter, startStack, type Stack } from "./lib";

// W1: a developer's first look, no identity file and no real LLM: the Session tab with the built-in demo agent (scripted LLM), the gate, a denial, and the drift alert.
let stack: Stack;
let llm: ChildProcess;
test.beforeAll(async () => {
  const port = await freePort();
  llm = spawn("python", [path.join(ROOT, "tests/browser/fake_llm.py"), String(port)], { cwd: ROOT });
  for (let i = 0; i < 80; i++) { try { if ((await fetch(`http://127.0.0.1:${port}/_calls`)).ok) break; } catch { /* wait */ } await new Promise((r) => setTimeout(r, 250)); }
  stack = await startStack({ OPENROUTER_API_KEY: "test-key", OPENROUTER_BASE_URL: `http://127.0.0.1:${port}/v1` });
});
test.afterAll(async () => { llm?.kill(); await stack.stop(); });

test("W1 first look: the Session tab, the human gate, a circumvention alert", async ({ page }) => {
  const shot = shooter("W1-first-look");
  await page.goto(stack.url);
  await expect(page.locator(".connection-dot.connected")).toBeVisible();
  await shot(page, "landing-session-tab");
  await page.selectOption(".scenario-select", "adversarial");
  await page.click(".run-button");
  const approve = page.locator(".btn-approve"), deny = page.locator(".btn-deny");
  await expect(approve.first()).toBeVisible({ timeout: 30_000 });
  await shot(page, "agent-proposes-a-tool-and-waits-for-you");
  await approve.first().click();
  await expect(deny.first()).toBeVisible();
  await deny.first().click();
  await expect(deny.first()).toBeVisible();
  await deny.first().click();
  await expect(page.locator(".alert-banner")).toContainText("circumvention_detected", { timeout: 15_000 });
  await shot(page, "denial-then-circumvention-alert");
  await expect(deny.first()).toBeVisible();
  await deny.first().click();
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 20_000 });
  await shot(page, "session-finished");
});
