import { mkdirSync } from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { DOWNSTREAM, makeIdentity, ROOT, shooter, signIn, startAgent, startStack, tmp, type Stack } from "./lib";

// W5: running risky servers safely. Landlock + network-namespace sandbox, a per-call worker, a just-in-time secret, and the warning before it is used.
const SECRET = "sk-live-0123456789-VERY-SECRET";
let stack: Stack;
const dir = tmp("boundary");
const allowed = path.join(dir, "allowed");
const { file, tokens } = makeIdentity(dir, { operators: [{ id: "sam", tenant: "acme", role: "approver" }], agents: [{ id: "assistant", tenant: "acme" }] });
test.beforeAll(async () => { mkdirSync(allowed); stack = await startStack({ SENTINEL_IDENTITY_FILE: file }); });
test.afterAll(async () => { await stack.stop(); });

test("W5 boundary: sandbox chips, credential warning (name never value), unsandboxed session flagged", async ({ page }) => {
  const shot = shooter("W5-boundary");
  await page.goto(stack.url);
  await page.click('[data-testid="tab-inbox"]');
  await signIn(page, tokens.sam);
  await expect(page.locator('[data-testid="inbox-identity"]')).toBeVisible({ timeout: 20_000 });
  const sandboxed = { command: "python", args: [path.join(ROOT, "tests/proxy/fake_downstream_probe.py")], lifecycle: "per_call", call_timeout_s: 30,
    sandbox: { read: [path.join(ROOT, "tests/proxy")], write: [allowed], network: "none", env_allow: [], require: true },
    secrets: { API_TOKEN: { from_env: "E2E_HOST_SECRET", tools: ["whoami_env"] } } };
  const agent = startAgent({ wsBase: stack.ws, session: "w5-sandboxed", token: tokens.assistant, dir, servers: { fs: sandboxed }, passthrough: { E2E_HOST_SECRET: SECRET } });
  const call = agent.call("whoami_env", { secret_var: "API_TOKEN" });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 60_000 });
  const session = page.locator('[data-testid="inbox-session"]', { hasText: "w5-sandboxed" });
  const chips = (await session.locator('[data-testid="inbox-boundary-chip"]').allInnerTexts()).join(" | ");
  expect(chips).toContain("net none");
  expect(chips).toContain("fs sandboxed");
  await expect(card.locator('[data-testid="inbox-secrets-warning"]')).toContainText("API_TOKEN");
  expect(await page.content()).not.toContain(SECRET);
  await shot(page, "sandbox-chips-and-credential-warning");
  await card.locator('[data-testid="inbox-approve"]').click();
  const done = await call;
  expect(JSON.parse(done.text).secret).toBe(SECRET);            // the approved worker had it...
  expect(await page.content()).not.toContain(SECRET);           // ...the page never did
  await shot(page, "approved-secret-value-never-shown");
  agent.stop();

  const plain = startAgent({ wsBase: stack.ws, session: "w5-unsandboxed", token: tokens.assistant, dir, servers: { fs: { command: "python", args: [DOWNSTREAM] } } });
  const c2 = plain.call("echo", { n: 1 });
  await expect(page.locator('[data-testid="inbox-pending"]').first()).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('[data-testid="inbox-session"]', { hasText: "w5-unsandboxed" }).locator('[data-testid="inbox-boundary-chip"].unsandboxed').first()).toBeVisible();
  await shot(page, "unsandboxed-session-flagged-red");
  await page.locator('[data-testid="inbox-pending"]').first().locator('[data-testid="inbox-deny"]').click();
  await c2;
  plain.stop();
});
