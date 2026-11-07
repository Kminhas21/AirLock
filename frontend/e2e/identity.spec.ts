import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { API_PORT, REPO_ROOT } from "./helpers/traces";

// Identity, tenancy and escalation in a real browser (stage "browser identity" of scripts/verify.sh; skipped elsewhere). The backend runs with an
// identity file (scripts/make_identity_fixture.py): tenants acme + globex, operators bob (approver), vera (viewer), gina (globex), per-agent tokens,
// escalation level 1 after 2 s. No legacy token is configured, so the Inbox must ask the operator to sign in.
test.skip(process.env.IDENTITY_STAGE !== "1", "identity stage only (IDENTITY_STAGE=1)");

const TOKENS = JSON.parse(readFileSync(process.env.IDENTITY_TOKENS ?? "/dev/null", "utf8") || "{}") as Record<string, string>;
const DOWNSTREAM = path.join(REPO_ROOT, "tests/proxy/fake_downstream.py");
const dir = mkdtempSync(path.join(tmpdir(), "identity-"));

function startAgent(sessionId: string, agentToken: string) {
  const cfg = path.join(dir, `${sessionId}.json`);
  writeFileSync(cfg, JSON.stringify({ session_id: sessionId, backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`, servers: { fs: { command: "python", args: [DOWNSTREAM] } } }));
  const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", cfg], {
    cwd: REPO_ROOT, env: { ...process.env, SENTINEL_AGENT_TOKEN: agentToken, SENTINEL_AGENT_PASSTHROUGH: "SENTINEL_AGENT_TOKEN" },
  });
  let buf = "";
  const waiters: ((r: { is_error: boolean; text: string }) => void)[] = [];
  p.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) waiters.shift()?.(JSON.parse(line));
    }
  });
  return {
    call: (tool: string, args: unknown) => new Promise<{ is_error: boolean; text: string }>((resolve) => {
      waiters.push(resolve);
      p.stdin.write(JSON.stringify({ tool, args }) + "\n");
    }),
    stop: () => { p.stdin.end(); },
  };
}

async function signIn(page: import("@playwright/test").Page, token: string) {
  await page.locator('[data-testid="inbox-signin-input"]').fill(token);
  await page.locator('[data-testid="inbox-signin-submit"]').click();
}

test("operators sign in, viewers are read-only, unanswered calls escalate, approvals name the operator, and tenants are isolated", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');

  // 1. nobody is signed in: the Inbox asks for a credential and a wrong one is refused with a message
  await expect(page.locator('[data-testid="inbox-signin"]')).toBeVisible();
  await signIn(page, "definitely-not-a-token");
  await expect(page.locator('[data-testid="inbox-signin-error"]')).toBeVisible({ timeout: 15_000 });
  expect(await page.content()).not.toContain("definitely-not-a-token");        // the credential is never echoed into the page

  // 2. an acme agent (own token) asks for something; the viewer sees it but cannot decide
  const agent = startAgent("pw-id-acme", TOKENS["ci-acme"]);
  const result = agent.call("echo", { n: 1 });
  await signIn(page, TOKENS["vera"]);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/vera.*acme.*viewer/, { timeout: 15_000 });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 60_000 });
  await expect(card.locator('[data-testid="inbox-agent"]')).toContainText("ci-acme");
  await expect(page.locator('[data-testid="inbox-readonly"]')).toBeVisible();
  await expect(card.locator('[data-testid="inbox-approve"]')).toBeDisabled();
  await expect(card.locator('[data-testid="inbox-deny"]')).toBeDisabled();
  // nobody answers: the card escalates (level 1 after 2 s) and shows its age
  await expect(card.locator('[data-testid="inbox-escalated"]')).toBeVisible({ timeout: 20_000 });
  await expect(card.locator('[data-testid="inbox-age"]')).toBeVisible();

  // 3. the other tenant's operator sees nothing of acme
  await page.locator('[data-testid="inbox-signout"]').click();
  await expect(page.locator('[data-testid="inbox-signin"]')).toBeVisible();
  await signIn(page, TOKENS["gina"]);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/gina.*globex.*approver/, { timeout: 15_000 });
  await expect(page.locator('[data-testid="inbox-pending"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="inbox-session"]', { hasText: "pw-id-acme" })).toHaveCount(0);

  // 4. the acme approver decides; the resolved row names who did it
  await page.locator('[data-testid="inbox-signout"]').click();
  await signIn(page, TOKENS["bob"]);
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/bob.*acme.*approver/, { timeout: 15_000 });
  const card2 = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card2).toBeVisible({ timeout: 30_000 });
  await expect(card2.locator('[data-testid="inbox-approve"]')).toBeEnabled();
  await card2.locator('[data-testid="inbox-approve"]').click();
  expect((await result).is_error).toBe(false);
  await expect(page.locator('[data-testid="inbox-resolved"]').first().locator('[data-testid="inbox-operator"]')).toContainText("bob");
  agent.stop();
});
