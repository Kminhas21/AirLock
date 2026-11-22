import { copyFileSync, existsSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { makeIdentity, ROOT, SHOTS, sh, shooter, signIn, startAgent, startStack, tmp, type Stack } from "./lib";

// W6: audit and incident review. A keyed, hash-chained event log survives a restart; the CLI verifies it and detects tampering with a copy.
let stack: Stack;
const dir = tmp("audit");
const DB = path.join(dir, "events.db");
const KEY = "journey-audit-log-key-123456";
const { file, tokens } = makeIdentity(dir, { operators: [{ id: "ada", tenant: "acme", role: "approver" }], agents: [{ id: "assistant", tenant: "acme" }] });
const cli = (...a: string[]) => sh("python", ["-m", "eventlog_cli", ...a], { cwd: path.join(ROOT, "server"), env: { ...process.env, SENTINEL_LOG_KEY: KEY } });
test.beforeAll(async () => { stack = await startStack({ SENTINEL_IDENTITY_FILE: file, SENTINEL_EVENT_LOG: DB, SENTINEL_LOG_KEY: KEY }); });
test.afterAll(async () => { await stack.stop(); });

test("W6 audit: decisions are logged, the log verifies, tampering is detected, pending calls become denied history after a restart", async ({ page }) => {
  const shot = shooter("W6-audit");
  await page.goto(stack.url);
  await page.click('[data-testid="tab-inbox"]');
  await signIn(page, tokens.ada);
  await expect(page.locator('[data-testid="inbox-identity"]')).toBeVisible({ timeout: 20_000 });
  const agent = startAgent({ wsBase: stack.ws, session: "w6-audit", token: tokens.assistant, dir });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  const a = agent.call("read_file", { path: "/project/q3.txt" });
  await expect(card).toBeVisible({ timeout: 60_000 });
  await card.locator('[data-testid="inbox-approve"]').click();
  await a;
  const b = agent.call("write_file", { path: "/etc/hosts", content: "x" });
  await expect(card).toBeVisible({ timeout: 60_000 });
  await card.locator('[data-testid="inbox-note"]').fill("not on this host");
  await card.locator('[data-testid="inbox-deny"]').click();
  await b;
  const c = agent.call("echo", { n: 3 });                       // left PENDING when the hub goes down
  await expect(card).toBeVisible({ timeout: 60_000 });
  await shot(page, "before-restart-one-call-still-pending");

  await stack.stop();                                           // graceful stop: final checkpoint
  agent.stop();
  void c;
  const verify = cli("verify", DB);
  const show = cli("export", DB, "--jsonl");
  expect(verify.code, verify.out).toBe(0);
  // tamper with a COPY: flip the recorded approval to a denial
  const evil = path.join(dir, "tampered.db");
  copyFileSync(DB, evil);
  if (existsSync(DB + ".anchor")) copyFileSync(DB + ".anchor", evil + ".anchor");
  const t = sh("python", ["-c", `import sqlite3;c=sqlite3.connect(${JSON.stringify(evil)});c.execute("update events set payload=replace(payload,'approve','deny') where kind='decision'");c.commit()`]);
  expect(t.code, t.out).toBe(0);
  const bad = cli("verify", evil);
  expect(bad.code, bad.out).toBe(1);
  writeFileSync(path.join(SHOTS, "W6-audit", "cli-evidence.txt"),
    `$ python -m eventlog_cli verify events.db\n${verify.out}(exit ${verify.code})\n\n$ python -m eventlog_cli export events.db --jsonl\n${show.out}\n$ (a copy with an approval flipped to a denial)\n$ python -m eventlog_cli verify tampered.db\n${bad.out}(exit ${bad.code})\n`);

  await stack.restart().catch((e) => { throw new Error(`restart failed: ${e}\n${stack.log().slice(-3000)}`); });
  await page.reload();
  await page.click('[data-testid="tab-inbox"]');
  if (await page.locator('[data-testid="inbox-signin"]').isVisible()) await signIn(page, tokens.ada);   // the browser may remember the sign-in
  await expect(page.locator('[data-testid="inbox-identity"]')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('[data-testid="inbox-resolved"]').first()).toBeVisible({ timeout: 20_000 });
  await shot(page, "after-restart-history-restored-pending-call-denied");
});
