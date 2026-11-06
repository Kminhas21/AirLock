import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { API_PORT, REPO_ROOT } from "./helpers/traces";

// Policy engine in a real browser (stage "browser inbox policy" of scripts/verify.sh; skipped elsewhere): real backend with SENTINEL_POLICY
// (tests/e2e/data/policy_e2e.json), real MiniLM + action_sim (a working monitor, so an allow can stand), a REAL stdio proxy and downstream.
test.skip(process.env.POLICY_STAGE !== "1", "policy stage only (POLICY_STAGE=1)");

const DOWNSTREAM = path.join(REPO_ROOT, "tests/proxy/fake_downstream.py");
const dir = mkdtempSync(path.join(tmpdir(), "policy-"));
const LOG = path.join(dir, "downstream.log");
const CFG = path.join(dir, "proxy.json");
// the proxy-side auto_approve says echo is auto: with a policy configured the hub must ignore it
writeFileSync(CFG, JSON.stringify({
  session_id: "pw-policy", backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`,
  servers: { fs: { command: "python", args: [DOWNSTREAM], env: { FAKE_DOWNSTREAM_LOG: LOG } } }, auto_approve: ["fs:echo"],
}));
const calls = () => (existsSync(LOG) ? readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const TOKEN = process.env.INBOX_TOKEN ?? "";

function startAgent() {
  const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", CFG], { cwd: REPO_ROOT, env: { ...process.env, SENTINEL_WS_TOKEN: TOKEN } });
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

test("rules decide: allow needs no click, deny never reaches the downstream, ask is held with its rule; the proxy's auto flag is ignored", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const agent = startAgent();

  // allow: no card is ever shown; the resolved row names the rule
  const ok = await agent.call("read_file", { path: "/project/a.txt" });
  expect(ok.is_error).toBe(false);
  const allowed = page.locator('[data-testid="inbox-resolved"][data-reason="policy"]').first();
  await expect(allowed).toBeVisible({ timeout: 30_000 });
  await expect(allowed).toHaveAttribute("data-rule-id", "allow-read-project");
  await expect(allowed.locator(".inbox-decision.policy.approve")).toHaveText("auto-allowed by rule allow-read-project");
  await expect(page.locator('[data-testid="inbox-pending"]')).toHaveCount(0);

  // deny: immediate, never forwarded
  const denied = await agent.call("write_file", { path: "/etc/passwd" });
  expect(denied.is_error).toBe(true);
  expect(denied.text).toBe("Denied by SENTINEL: policy");
  await expect(page.locator('[data-testid="inbox-resolved"][data-rule-id="deny-write-outside"] .inbox-decision.policy.deny'))
    .toHaveText("denied by rule deny-write-outside");
  expect(calls().map((c) => c.tool), "only the allowed read reached the downstream").toEqual(["read_file"]);

  // ask rule (and the proxy's auto flag for echo is ignored): held, labelled with the rule, the human decides
  const held = agent.call("echo", { n: 1 });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 30_000 });
  await expect(card.locator('[data-testid="inbox-rule"]')).toHaveText("held by rule ask-echo");
  expect(calls().map((c) => c.tool)).toEqual(["read_file"]);
  await card.locator('[data-testid="inbox-deny"]').click();
  expect((await held).is_error).toBe(true);
  agent.stop();
});
