import { copyFileSync, existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { DOWNSTREAM, makeIdentity, ROOT, shooter, signIn, startAgent, startStack, tmp, type Stack } from "./lib";

// W4: the policy author's rules decide: allow needs no click, deny never reaches the downstream, ask is held with its rule; the proxy's own auto flag is ignored.
let stack: Stack;
const dir = tmp("policy");
const LOG = path.join(dir, "downstream.log");
const { file, tokens } = makeIdentity(dir, { operators: [{ id: "pat", tenant: "acme", role: "approver" }], agents: [{ id: "assistant", tenant: "acme" }] });
const calls = () => (existsSync(LOG) ? readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).tool) : []);
test.beforeAll(async () => {
  copyFileSync(path.join(ROOT, "tests/e2e/data/policy_e2e.json"), path.join(dir, "policy.json"));
  stack = await startStack({ SENTINEL_IDENTITY_FILE: file, SENTINEL_POLICY: path.join(dir, "policy.json"), SENTINEL_MONITOR: "action_sim", SENTINEL_EMBEDDER: "minilm" });
});
test.afterAll(async () => { await stack.stop(); });

test("W4 policy author: allow / deny / ask rules decide, and the proxy's auto flag is ignored", async ({ page }) => {
  const shot = shooter("W4-policy");
  await page.goto(stack.url);
  await page.click('[data-testid="tab-inbox"]');
  await signIn(page, tokens.pat);
  await expect(page.locator('[data-testid="inbox-identity"]')).toBeVisible({ timeout: 20_000 });
  const agent = startAgent({ wsBase: stack.ws, session: "w4-policy", token: tokens.assistant, dir, autoApprove: ["fs:echo"],
    servers: { fs: { command: "python", args: [DOWNSTREAM], env: { FAKE_DOWNSTREAM_LOG: LOG } } } });

  // D31: a rule may auto-allow only what needs no confinement here (this server is not sandboxed, so a path read would ask): an echo of a bare counter
  expect((await agent.call("echo", { n: 0 })).is_error).toBe(false);
  const allowed = page.locator('[data-testid="inbox-resolved"][data-rule-id="allow-echo-n"]').first();
  await expect(allowed).toHaveText(/auto-allowed by rule allow-echo-n/, { timeout: 30_000 });
  await expect(page.locator('[data-testid="inbox-pending"]')).toHaveCount(0);
  await shot(page, "allow-rule-no-click-needed");

  const denied = await agent.call("write_file", { path: "/etc/passwd" });
  expect(denied.text).toBe("Denied by SENTINEL: policy");
  await expect(page.locator('[data-testid="inbox-resolved"][data-rule-id="deny-write-outside"]')).toHaveText(/denied by rule deny-write-outside/);
  await shot(page, "deny-rule-never-reaches-the-tool");

  const held = agent.call("echo", { x: 1 });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 30_000 });
  await expect(card.locator('[data-testid="inbox-rule"]')).toHaveText("held by rule ask-echo");
  expect(calls()).toEqual(["echo"]);                           // only the allowed call reached the downstream
  await shot(page, "ask-rule-held-for-a-human-despite-auto-approve-flag");
  await card.locator('[data-testid="inbox-approve"]').click();
  expect((await held).is_error).toBe(false);
  await shot(page, "all-three-outcomes-in-the-history");
  agent.stop();
});
