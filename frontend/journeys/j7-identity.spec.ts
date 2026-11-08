import { expect, test } from "@playwright/test";
import { makeIdentity, shooter, signIn, startAgent, startStack, tmp, type Stack } from "./lib";

// W7: team / multi-tenant. Wrong token refused, viewer read-only, unanswered call escalates, other tenant sees nothing, approvals name the operator.
let stack: Stack;
const dir = tmp("identity");
const { file, tokens } = makeIdentity(dir, {
  tenants: { acme: { escalation_after_s: 2 } },
  operators: [{ id: "bob", tenant: "acme", role: "approver" }, { id: "vera", tenant: "acme", role: "viewer" }, { id: "gina", tenant: "globex", role: "approver" }],
  agents: [{ id: "ci-acme", tenant: "acme" }, { id: "ci-globex", tenant: "globex" }],
});
test.beforeAll(async () => { stack = await startStack({ SENTINEL_IDENTITY_FILE: file }); });
test.afterAll(async () => { await stack.stop(); });

test("W7 team: sign-in, viewer read-only, escalation, tenant isolation, who decided", async ({ page }) => {
  const shot = shooter("W7-identity");
  await page.goto(stack.url);
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-signin"]')).toBeVisible();
  await signIn(page, "definitely-not-a-token");
  await expect(page.locator('[data-testid="inbox-signin-error"]')).toBeVisible({ timeout: 15_000 });
  expect(await page.content()).not.toContain("definitely-not-a-token");
  await shot(page, "wrong-token-refused");

  const agent = startAgent({ wsBase: stack.ws, session: "w7-acme", token: tokens["ci-acme"], dir });
  const result = agent.call("echo", { n: 1 });
  await signIn(page, tokens.vera);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/vera.*acme.*viewer/, { timeout: 15_000 });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 60_000 });
  await expect(card.locator('[data-testid="inbox-approve"]')).toBeDisabled();
  await shot(page, "viewer-sees-the-call-but-cannot-decide");
  await expect(card.locator('[data-testid="inbox-escalated"]')).toBeVisible({ timeout: 20_000 });
  await shot(page, "unanswered-call-escalated");

  await page.locator('[data-testid="inbox-signout"]').click();
  await signIn(page, tokens.gina);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/gina.*globex.*approver/, { timeout: 15_000 });
  await expect(page.locator('[data-testid="inbox-pending"]')).toHaveCount(0);
  await shot(page, "other-tenant-sees-nothing-of-acme");

  await page.locator('[data-testid="inbox-signout"]').click();
  await signIn(page, tokens.bob);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/bob.*acme.*approver/, { timeout: 15_000 });
  const c2 = page.locator('[data-testid="inbox-pending"]').first();
  await expect(c2).toBeVisible({ timeout: 30_000 });
  await shot(page, "approver-sees-escalated-call");
  await c2.locator('[data-testid="inbox-approve"]').click();
  expect((await result).is_error).toBe(false);
  await expect(page.locator('[data-testid="inbox-resolved"]').first().locator('[data-testid="inbox-operator"]')).toContainText("bob");
  await shot(page, "approved-by-bob-recorded");
  agent.stop();
});
