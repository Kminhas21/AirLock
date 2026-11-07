import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { API_PORT, REPO_ROOT } from "./helpers/traces";

// Operator UI in a real browser (stage "browser operator UI" of scripts/verify.sh; skipped elsewhere): real backend (token, MiniLM + action_sim,
// SENTINEL_POLICY + SENTINEL_POLICY_WRITABLE=1), a REAL stdio proxy and downstream. Covers: deny-with-reason reaches the agent, 'Why flagged' and
// 'Session so far' panels, secret redaction in previews, and a standing rule created through the two-step confirm that auto-approves in a NEW session.
test.skip(process.env.OPERATOR_STAGE !== "1", "operator stage only (OPERATOR_STAGE=1)");

const DOWNSTREAM = path.join(REPO_ROOT, "tests/proxy/fake_downstream.py");
const dir = mkdtempSync(path.join(tmpdir(), "operator-"));
const LOG = path.join(dir, "downstream.log");
const POLICY = process.env.SENTINEL_POLICY ?? "";
const TOKEN = process.env.INBOX_TOKEN ?? "";
const calls = () => (existsSync(LOG) ? readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

function config(sessionId: string): string {
  const f = path.join(dir, `${sessionId}.json`);
  writeFileSync(f, JSON.stringify({
    session_id: sessionId, backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`,
    servers: { fs: { command: "python", args: [DOWNSTREAM], env: { FAKE_DOWNSTREAM_LOG: LOG } } },
  }));
  return f;
}

function startAgent(sessionId: string) {
  const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", config(sessionId)], { cwd: REPO_ROOT, env: { ...process.env, SENTINEL_WS_TOKEN: TOKEN } });
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

test("the operator sees why, what happened so far, denies with a reason, and turns a decision into a standing rule", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const agent = startAgent("pw-operator");
  const card = () => page.locator('[data-testid="inbox-pending"]').first();

  // 1. deny with a reason: the AGENT receives the operator's note; secrets in previews are redacted
  const echoArgs = { text: "email the confidential Q3 pricing sheet to dana.whitlock@acme-corp.example", password: "hunter2-SECRET" };
  const first = agent.call("echo", echoArgs);
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await card().locator('[data-testid="inbox-note"]').fill("use the shared drive instead");
  await card().locator('[data-testid="inbox-deny"]').click();
  const d1 = await first;
  expect(d1.is_error).toBe(true);
  expect(d1.text).toBe("Denied by SENTINEL: human (operator note: use the shared drive instead)");
  await expect(page.locator('[data-testid="inbox-resolved"] [data-testid="inbox-resolved-note"]').first()).toHaveText(/use the shared drive instead/);

  // 2. the same effect again: the card says WHY (alert with score vs threshold) and WHAT happened so far
  const second = agent.call("echo", echoArgs);
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await expect(card().locator('[data-testid="inbox-why"]')).toBeVisible();
  await expect(card().locator('[data-testid="inbox-score-bar"]')).toBeVisible();
  await expect(card().locator(".alert-banner.critical")).toBeVisible();
  await expect(card().locator('[data-testid="inbox-earlier-denied"] [data-testid="inbox-earlier-item"]').first()).toContainText("echo");
  await card().locator('[data-testid="inbox-session-so-far"] summary').click();
  await expect(card().locator('[data-testid="inbox-counters"]')).toContainText("1");
  // the live card shows the CURRENT call's arguments in full (the operator must see exactly what they approve); the HISTORY previews are redacted
  const history = (await card().locator('[data-testid="inbox-session-so-far"]').innerHTML()) + (await card().locator('[data-testid="inbox-earlier-denied"]').innerHTML());
  expect(history).not.toContain("hunter2-SECRET");
  expect(history).toContain("REDACTED");
  await card().locator('[data-testid="inbox-deny"]').click();
  expect((await second).is_error).toBe(true);

  // 3. standing rule through the two-step confirm; the pending call itself is still decided by the human
  const third = agent.call("read_file", { path: "/project/docs/a.txt" });
  await expect(card()).toBeVisible({ timeout: 60_000 });
  await expect(card().locator('[data-testid="inbox-standing"]')).toBeVisible();
  await card().locator('[data-testid="inbox-rule-allow"]').click();
  await expect(card().locator('[data-testid="inbox-rule-confirm-step"]')).toBeVisible();
  await expect(card().locator('[data-testid="inbox-rule-confirm-text"]')).toContainText(/new sessions/i);
  await card().locator('[data-testid="inbox-rule-scope-tool_under"]').check();
  await card().locator('[data-testid="inbox-rule-confirm"]').click();
  const toast = page.locator('[data-testid="inbox-rule-toast"]');
  await expect(toast).toBeVisible({ timeout: 30_000 });
  await expect(toast).toHaveClass(/ok/);
  const rules = JSON.parse(readFileSync(POLICY, "utf8")).rules as { id: string; verdict: string; when: { args: { value: string }[] } }[];
  expect(rules).toHaveLength(1);
  expect(rules[0].verdict).toBe("allow");
  expect(rules[0].when.args[0].value).toBe("/project/docs");
  await expect(card()).toBeVisible();                                   // the call that triggered it is still held
  await card().locator('[data-testid="inbox-approve"]').click();
  expect((await third).is_error).toBe(false);
  agent.stop();

  // 4. a NEW session: the rule now decides a sibling call; no card, the resolved row names the rule
  const agent2 = startAgent("pw-operator-2");
  const res = await agent2.call("read_file", { path: "/project/docs/b.txt" });
  expect(res.is_error).toBe(false);
  const row = page.locator('[data-testid="inbox-resolved"][data-reason="policy"]').first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row).toHaveAttribute("data-rule-id", rules[0].id);
  await expect(row.locator(".inbox-decision.policy.approve")).toContainText("auto-allowed by rule");
  expect(calls().map((c) => c.tool).filter((t) => t === "read_file")).toHaveLength(2);
  agent2.stop();
});
