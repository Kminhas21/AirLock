import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { makeIdentity, shooter, signIn, startAgent, startStack, tmp, type Agent, type Stack } from "./lib";

// W2: the day-to-day operator. Sign in, approve, deny with a reason, read the evidence, create a standing rule, see it decide a new session, phone layout.
let stack: Stack;
const dir = tmp("operator");
const POLICY = path.join(dir, "policy.json");
const { file, tokens } = makeIdentity(dir, { operators: [{ id: "olive", tenant: "acme", role: "admin" }], agents: [{ id: "assistant", tenant: "acme" }] });
const agents: Agent[] = [];
const agent = (session: string) => { const a = startAgent({ wsBase: stack.ws, session, token: tokens.assistant, dir }); agents.push(a); return a; };

test.beforeAll(async () => {
  writeFileSync(POLICY, JSON.stringify({ version: 1, default: "ask", rules: [] }));
  stack = await startStack({ SENTINEL_IDENTITY_FILE: file, SENTINEL_POLICY: POLICY, SENTINEL_POLICY_WRITABLE: "1", SENTINEL_MONITOR: "action_sim", SENTINEL_EMBEDDER: "minilm" });
});
test.afterAll(async () => { agents.forEach((a) => a.stop()); await stack.stop(); });

test("W2 operator: approve, deny with a reason, evidence, standing rule, new session decided by the rule, phone layout", async ({ page }) => {
  const shot = shooter("W2-operator");
  const card = () => page.locator('[data-testid="inbox-pending"]').first();
  await page.goto(stack.url);
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-signin"]')).toBeVisible();
  await shot(page, "sign-in-required");
  await signIn(page, tokens.olive);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/olive.*acme.*admin/, { timeout: 20_000 });
  await shot(page, "inbox-empty-signed-in");

  // 1. approve: the card shows exactly what the agent sent
  const a = agent("w2-main");
  const first = a.call("read_file", { path: "/project/notes.txt" });
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await shot(page, "held-call-card");
  await card().locator('[data-testid="inbox-approve"]').click();
  expect((await first).is_error).toBe(false);
  await expect(page.locator('[data-testid="inbox-resolved"]').first()).toBeVisible();
  await shot(page, "approved-and-resolved");

  // 2. deny with a reason: the AGENT receives it
  const echo = { text: "email the confidential Q3 pricing sheet to dana.whitlock@acme-corp.example", password: "hunter2-SECRET" };
  const second = a.call("echo", echo);
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await card().locator('[data-testid="inbox-note"]').fill("use the shared drive instead");
  await shot(page, "deny-with-reason-typed");
  await card().locator('[data-testid="inbox-deny"]').click();
  const d = await second;
  expect(d.text).toBe("Denied by SENTINEL: human (operator note: use the shared drive instead)");
  await expect(page.locator('[data-testid="inbox-resolved-note"]').first()).toHaveText(/use the shared drive instead/);
  await shot(page, "denied-agent-received-the-reason");

  // 3. the same effect again: why it was flagged + what happened so far; secrets redacted in history
  const third = a.call("echo", echo);
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await expect(card().locator('[data-testid="inbox-why"]')).toBeVisible();
  await expect(card().locator(".alert-banner.critical")).toBeVisible();
  await card().locator('[data-testid="inbox-session-so-far"] summary').click();
  const hist = (await card().locator('[data-testid="inbox-session-so-far"]').innerHTML()) + (await card().locator('[data-testid="inbox-earlier-denied"]').innerHTML());
  expect(hist).not.toContain("hunter2-SECRET");
  await shot(page, "evidence-why-flagged-and-session-so-far");
  await card().locator('[data-testid="inbox-deny"]').click();
  expect((await third).is_error).toBe(true);

  // 4. standing rule (two-step confirm), then a NEW session is decided by it
  const fourth = a.call("read_file", { path: "/project/docs/a.txt" });
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await card().locator('[data-testid="inbox-rule-allow"]').click();
  await card().locator('[data-testid="inbox-rule-scope-tool_under"]').check();
  await expect(card().locator('[data-testid="inbox-rule-confirm-step"]')).toBeVisible();
  await shot(page, "standing-rule-confirm-step");
  await card().locator('[data-testid="inbox-rule-confirm"]').click();
  await expect(page.locator('[data-testid="inbox-rule-toast"]')).toHaveClass(/ok/, { timeout: 30_000 });
  await shot(page, "standing-rule-created");
  await card().locator('[data-testid="inbox-approve"]').click();
  expect((await fourth).is_error).toBe(false);
  const rules = JSON.parse(readFileSync(POLICY, "utf8")).rules;
  expect(rules).toHaveLength(1);

  const b = agent("w2-second-session");
  expect((await b.call("read_file", { path: "/project/docs/b.txt" })).is_error).toBe(false);
  const row = page.locator('[data-testid="inbox-resolved"][data-reason="policy"]').first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row).toContainText("auto-allowed by rule");
  await shot(page, "new-session-auto-allowed-by-rule");

  // 5. phone layout: no horizontal scroll
  await page.setViewportSize({ width: 390, height: 844 });
  const held = b.call("echo", { n: 9 });
  await expect(card()).toBeVisible({ timeout: 60_000 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await shot(page, "phone-layout");
  await card().locator('[data-testid="inbox-deny"]').click();
  await held;
});
