import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { API_PORT, REPO_ROOT } from "./helpers/traces";

// Enforcement boundary in a real browser (stage "browser boundary" of scripts/verify.sh; skipped elsewhere): a REAL stdio proxy with a Landlock +
// network-namespace sandboxed per-call downstream holding a just-in-time secret, a REAL backend, and an UNSANDBOXED second session for contrast.
test.skip(process.env.BOUNDARY_STAGE !== "1", "boundary stage only (BOUNDARY_STAGE=1)");

const SECRET = "sk-live-0123456789-VERY-SECRET";
const PROBE = path.join(REPO_ROOT, "tests/proxy/fake_downstream_probe.py");
const PLAIN = path.join(REPO_ROOT, "tests/proxy/fake_downstream.py");
const TOKEN = process.env.INBOX_TOKEN ?? "";
const dir = mkdtempSync(path.join(tmpdir(), "boundary-"));
const allowed = path.join(dir, "allowed");
mkdirSync(allowed);

function config(sessionId: string, servers: Record<string, unknown>): string {
  const f = path.join(dir, `${sessionId}.json`);
  writeFileSync(f, JSON.stringify({ session_id: sessionId, backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`, servers }));
  return f;
}
const sandboxed = () => ({
  command: "python", args: [PROBE], lifecycle: "per_call", call_timeout_s: 30,
  sandbox: { read: [path.join(REPO_ROOT, "tests/proxy")], write: [allowed], network: "none", env_allow: [], require: true },
  secrets: { API_TOKEN: { from_env: "E2E_HOST_SECRET", tools: ["whoami_env"] } },
});

function startAgent(cfg: string) {
  const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", cfg], {
    cwd: REPO_ROOT, env: { ...process.env, SENTINEL_WS_TOKEN: TOKEN, E2E_HOST_SECRET: SECRET, SENTINEL_AGENT_PASSTHROUGH: "E2E_HOST_SECRET" },
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

test("the operator sees the sandbox boundary and is warned before a call receives a credential; an unsandboxed session is flagged", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const agent = startAgent(config("pw-boundary", { fs: sandboxed() }));

  // 1. a credentialed call: chips describe the sandbox, a warning names the credential (never its value), the human decides
  const call = agent.call("whoami_env", { secret_var: "API_TOKEN" });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 60_000 });
  const session = page.locator('[data-testid="inbox-session"]', { hasText: "pw-boundary" });
  await expect(session.locator('[data-testid="inbox-boundary"]')).toBeVisible();
  const chips = (await session.locator('[data-testid="inbox-boundary-chip"]').allInnerTexts()).join(" | ");
  expect(chips).toContain("net none");
  expect(chips).toContain("fs sandboxed");
  expect(chips).toContain("fresh worker per call");
  await expect(session.locator(".inbox-boundary-chip.unsandboxed, [data-testid='inbox-boundary-chip'].unsandboxed")).toHaveCount(0);
  const warning = card.locator('[data-testid="inbox-secrets-warning"]');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText("API_TOKEN");
  expect(await page.content()).not.toContain(SECRET);                                    // the credential VALUE never reaches the page
  await card.locator('[data-testid="inbox-approve"]').click();
  const done = await call;
  expect(done.is_error).toBe(false);
  expect(JSON.parse(done.text).secret).toBe(SECRET);                                      // the approved call's worker had it; the page still never saw it
  expect(await page.content()).not.toContain(SECRET);
  agent.stop();

  // 2. an unsandboxed session is flagged in red
  const plain = startAgent(config("pw-plain", { fs: { command: "python", args: [PLAIN] } }));
  const c2 = plain.call("echo", { n: 1 });
  await expect(page.locator('[data-testid="inbox-pending"]').first()).toBeVisible({ timeout: 60_000 });
  const plainSession = page.locator('[data-testid="inbox-session"]', { hasText: "pw-plain" });
  await expect(plainSession.locator('[data-testid="inbox-boundary-chip"].unsandboxed').first()).toBeVisible();
  await expect(page.locator('[data-testid="inbox-secrets-warning"]')).toHaveCount(0);
  await page.locator('[data-testid="inbox-pending"]').first().locator('[data-testid="inbox-deny"]').click();
  expect((await c2).is_error).toBe(true);
  plain.stop();
});
