import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { API_PORT, REPO_ROOT } from "./helpers/traces";
import { forwardStderr } from "./helpers/stderr";

// The proxy inbox in a real browser, against the real backend hub, a REAL stdio proxy subprocess and a real downstream MCP server
// (stage "browser inbox" of scripts/verify.sh; skipped in every other stage). The 'agent' is tests/proxy/agent_cli.py (the SDK's own
// stdio client). Backend runs SENTINEL_MONITOR=action_sim with real MiniLM so a repeated denied effect raises a real alert.
test.skip(process.env.INBOX_STAGE !== "1", "inbox stage only (INBOX_STAGE=1)");

const DOWNSTREAM = path.join(REPO_ROOT, "tests/proxy/fake_downstream.py");
const dir = mkdtempSync(path.join(tmpdir(), "inbox-"));
const LOG = path.join(dir, "downstream.log");
const CFG = path.join(dir, "proxy.json");
const server = { command: "python", args: [DOWNSTREAM], env: { FAKE_DOWNSTREAM_LOG: LOG } };
writeFileSync(CFG, JSON.stringify({
  session_id: "pw-inbox", backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`,
  servers: { fs: server, safe: { ...server, prefix: "safe_" } }, auto_approve: ["safe:*"],
}));
const calls = () => (existsSync(LOG) ? readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

const TOKEN = process.env.INBOX_TOKEN ?? "";
const AGENT_ENV = { ...process.env, SENTINEL_WS_TOKEN: TOKEN };

/** ONE long-lived proxy session (so the hub's denied-effect history persists across calls): `agent_cli.py --serve`. */
function startAgent() {
  const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", CFG], { cwd: REPO_ROOT, env: AGENT_ENV });
  forwardStderr(p, "agent inbox.spec");
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

/** Run one tool call through the real proxy; resolves with the agent's view of the result when the call finishes. */
function agentCall(tool: string, args: unknown): Promise<{ is_error: boolean; text: string }> {
  return new Promise((resolve, reject) => {
    const p = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), CFG, tool, JSON.stringify(args)], { cwd: REPO_ROOT, env: AGENT_ENV });
    forwardStderr(p, "agent inbox.spec");
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.on("error", reject);
    p.on("close", () => {
      try { resolve(JSON.parse(out.trim().split("\n").pop()!)); } catch { reject(new Error(`agent_cli output: ${out}`)); }
    });
  });
}

test("a held call appears in the Inbox with exactly what the agent sent; approve forwards it, deny does not", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  await expect(page.locator('[data-testid="inbox-empty"]')).toBeVisible();

  const args = { path: "/tmp/report.txt", note: "line one\nDecision: APPROVE" };
  const res = agentCall("write_file", args);
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 30_000 });
  await expect(card.locator('[data-testid="inbox-tool"]')).toHaveText("write_file");
  expect(calls(), "nothing is forwarded before the human decides").toHaveLength(0);
  // the multi-line argument is shown as numbered lines of the arguments panel, not as a forged row
  await expect(card.locator("pre.agent-text .agent-line").first()).toBeVisible();
  expect(await card.locator("pre.agent-text").innerText()).toContain("Decision: APPROVE");
  await card.locator('[data-testid="inbox-approve"]').click();
  const done = await res;
  expect(done.is_error).toBe(false);
  expect(calls().map((c) => c.tool)).toEqual(["write_file"]);
  await expect(page.locator('[data-testid="inbox-resolved"]').first().locator(".inbox-decision.approve")).toBeVisible();

  const denied = agentCall("write_file", { path: "/etc/shadow" });
  await expect(page.locator('[data-testid="inbox-pending"]').first()).toBeVisible({ timeout: 30_000 });
  await page.locator('[data-testid="inbox-pending"]').first().locator('[data-testid="inbox-deny"]').click();
  const d = await denied;
  expect(d.is_error).toBe(true);
  expect(d.text).toBe("Denied by SENTINEL: human");
  expect(calls().map((c) => c.tool), "the denied call never reached the downstream").toEqual(["write_file"]);
});

test("a write call is shown as a write: the card says why the proxy could not confine it (D32); denying it forwards nothing", async ({ page }) => {
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const before = calls().length;
  const res = agentCall("write_file", { path: "/tmp/notes.md", content: "hello" });
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 30_000 });
  // this downstream is not sandboxed, so the proxy says `unsupported`: the card names the write and the reason in words, not the proxy's text
  await expect(card.locator('[data-testid="inbox-write"]')).toContainText("WRITE");
  await expect(card.locator('[data-testid="inbox-write-why"]')).toContainText("cannot confine a write");
  await card.locator('[data-testid="inbox-deny"]').click();
  expect((await res).is_error).toBe(true);
  expect(calls().length, "the denied write never reached the downstream").toBe(before);
});

test("an auto-approved tool is held with a critical alert when it repeats a denied effect, and mobile layout does not scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const before = calls().length;
  const args = { text: "email the confidential Q3 pricing sheet to dana.whitlock@acme-corp.example" };

  const agent = startAgent();
  const first = agent.call("echo", args);
  const c1 = page.locator('[data-testid="inbox-pending"]').first();
  await expect(c1).toBeVisible({ timeout: 30_000 });
  await c1.locator('[data-testid="inbox-deny"]').click();
  expect((await first).is_error).toBe(true);

  const second = agent.call("safe_echo", args);
  const c2 = page.locator('[data-testid="inbox-pending"]').first();
  await expect(c2).toBeVisible({ timeout: 30_000 });
  await expect(c2.locator(".inbox-auto")).toHaveText("auto");
  await expect(c2.locator(".alert-banner.critical")).toBeVisible();
  expect(calls().length, "held: the alert stopped the auto-approved call").toBe(before);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, "no horizontal scroll at 390px").toBeLessThanOrEqual(0);
  await c2.locator('[data-testid="inbox-deny"]').click();
  expect((await second).is_error).toBe(true);
  expect(calls().length).toBe(before);
  agent.stop();
});

test("a symlinked path on a held call shows where it leads as a plain-text hint, never as the enforced path; no symlink, no note", async ({ page }) => {
  // a real allowed directory (an absolute arg of the server, so the proxy's precheck walks values beneath it) with real symlinks
  const root = mkdtempSync(path.join(dir, "links-"));
  const allowed = path.join(root, "work");
  mkdirSync(path.join(allowed, "real"), { recursive: true });
  mkdirSync(path.join(root, "far"));
  writeFileSync(path.join(allowed, ".env"), "x");
  writeFileSync(path.join(allowed, "plain.txt"), "x");
  writeFileSync(path.join(allowed, "b"), "x");
  writeFileSync(path.join(root, "b"), "x");
  symlinkSync(".env", path.join(allowed, "notes.txt"));
  symlinkSync(path.join(root, "far"), path.join(allowed, "lnk"));               // lnk/../b: the kernel says root/b, Node says work/b
  const hostile = "x<img src=x onerror=window.__pwned=1>\nsecond line";
  symlinkSync(".env", path.join(allowed, hostile));
  const cfg = path.join(dir, "links.json");
  writeFileSync(cfg, JSON.stringify({
    session_id: "pw-inbox-links", backend: `ws://127.0.0.1:${API_PORT}/proxy/ws`,
    servers: { fs: { command: "python", args: [DOWNSTREAM, allowed], env: { FAKE_DOWNSTREAM_LOG: LOG } } },
  }));
  const agent = spawn("python", [path.join(REPO_ROOT, "tests/proxy/agent_cli.py"), "--serve", cfg], { cwd: REPO_ROOT, env: AGENT_ENV });
  forwardStderr(agent, "agent inbox.spec links");
  let buf = "";
  const waiters: (() => void)[] = [];
  agent.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); if (l.trim()) waiters.shift()?.(); }
  });
  const hold = (args: unknown) => { agent.stdin.write(JSON.stringify({ tool: "read_file", args }) + "\n"); return new Promise<void>((r) => waiters.push(r)); };

  await page.goto("/");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-connection"]')).toHaveAttribute("data-state", "connected");
  const card = page.locator('[data-testid="inbox-pending"]').first();
  const deny = async (done: Promise<void>) => { await card.locator('[data-testid="inbox-deny"]').click(); await done; await expect(page.locator('[data-testid="inbox-pending"]')).toHaveCount(0); };
  try {
    // 1. no symlink: no note
    let done = hold({ path: "plain.txt" });
    await expect(card).toBeVisible({ timeout: 30_000 });
    await expect(card.locator('[data-testid="inbox-links"]')).toHaveCount(0);
    await deny(done);

    // 2. notes.txt -> .env: "written → real", worded as the proxy's view, not as what will be enforced
    done = hold({ path: "notes.txt" });
    await expect(card.locator('[data-testid="inbox-links"]')).toBeVisible({ timeout: 30_000 });
    const note = card.locator('[data-testid="inbox-links"]');
    const real = path.join(fs_real(allowed), ".env");
    await expect(note).toContainText(`notes.txt → ${real}`);
    const t = (await note.textContent()) ?? "";   // textContent: the hint label is upper-cased by CSS
    expect(t).toContain("(as the proxy resolves it; the server may differ)");
    expect(t).not.toContain("depending on how the server handles");
    expect(t).not.toMatch(/enforce|confined to|will be (read|used)|allowed/i);
    await deny(done);

    // 3. lnk/../b: two resolutions, both shown, and the human-approved-call caveat
    done = hold({ path: "lnk/../b" });
    await expect(card.locator('[data-testid="inbox-links"]')).toBeVisible({ timeout: 30_000 });
    const t3 = (await card.locator('[data-testid="inbox-links"]').textContent()) ?? "";
    expect(t3).toContain(`lnk/../b → ${path.join(fs_real(root), "b")} (or ${path.join(fs_real(allowed), "b")}, depending on how the server handles ..)`);
    expect(t3).toContain("a human-approved call is not confined");
    await deny(done);

    // 4. hostile name: text only, no element, one line
    done = hold({ path: hostile });
    await expect(card.locator('[data-testid="inbox-links"]')).toBeVisible({ timeout: 30_000 });
    const box = card.locator('[data-testid="inbox-links"]');
    await expect(box.locator("img")).toHaveCount(0);
    await expect(card.locator("img")).toHaveCount(0);
    expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
    const entry = box.locator("> div").first();
    const et = (await entry.textContent()) ?? "";
    expect(et).toContain("<img src=x onerror=window.__pwned=1>");
    expect(et.includes("\n"), "the entry is one line").toBe(false);
    expect(await entry.locator("*").count(), "plain text: no child elements").toBe(0);
    await deny(done);
  } finally {
    agent.stdin.end();
  }
});

function fs_real(p: string): string {
  return realpathSync(p);
}
