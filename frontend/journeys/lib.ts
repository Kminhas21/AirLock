import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Page } from "@playwright/test";

export const ROOT = path.resolve(process.cwd(), "..");
export const DIST = path.join(process.cwd(), "dist");
export const SHOTS = process.env.JOURNEY_SHOTS ?? path.join(process.cwd(), "journeys/.shots");
export const DOWNSTREAM = path.join(ROOT, "tests/proxy/fake_downstream.py");

export function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => { const p = (s.address() as net.AddressInfo).port; s.close(() => res(p)); });
    s.on("error", rej);
  });
}
export const tmp = (p: string) => mkdtempSync(path.join(tmpdir(), `journey-${p}-`));

/** Numbered, named screenshots for one journey: journeys/.shots/<journey>/NN-name.png. Returns the file path. */
export function shooter(journey: string) {
  const dir = path.join(SHOTS, journey);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  let n = 0;
  return async (page: Page, name: string) => {
    const f = path.join(dir, `${String(++n).padStart(2, "0")}-${name}.png`);
    await page.screenshot({ path: f });
    return f;
  };
}

export interface IdentitySpec {
  tenants?: Record<string, { escalation_after_s?: number }>;
  operators: { id: string; tenant: string; role: "viewer" | "approver" | "admin" }[];
  agents: { id: string; tenant: string }[];
}
/** Writes an identity file (token SHA-256 digests only, like identity_cli) and returns the plaintext tokens by id. */
export function makeIdentity(dir: string, spec: IdentitySpec): { file: string; tokens: Record<string, string> } {
  const tokens: Record<string, string> = {};
  for (const x of [...spec.operators, ...spec.agents]) tokens[x.id] = randomBytes(24).toString("base64url");
  const sha = (t: string) => createHash("sha256").update(t).digest("hex");
  const tenants: Record<string, unknown> = {};
  for (const t of new Set([...spec.operators.map((o) => o.tenant), ...spec.agents.map((a) => a.tenant), ...Object.keys(spec.tenants ?? {})])) {
    const esc = spec.tenants?.[t]?.escalation_after_s;
    tenants[t] = { name: t, ...(esc ? { escalation: { levels: [{ after_s: esc, notify: [] }] } } : {}) };
  }
  const file = path.join(dir, "identity.json");
  writeFileSync(file, JSON.stringify({
    version: 1, tenants,
    operators: spec.operators.map((o) => ({ ...o, token_sha256: sha(tokens[o.id]) })),
    agents: spec.agents.map((a) => ({ ...a, token_sha256: sha(tokens[a.id]) })),
  }, null, 1), { mode: 0o600 });
  return { file, tokens };
}

async function waitHealthy(url: string, proc?: ChildProcess, seconds = 90) {
  for (let i = 0; i < seconds * 4; i++) {
    if (proc && proc.exitCode !== null) throw new Error(`process exited early (${proc.exitCode})`);
    try { if ((await fetch(url, { signal: AbortSignal.timeout(2000) })).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`${url} never became healthy`);
}

export interface Stack { port: number; url: string; ws: string; stop(): Promise<void>; restart(): Promise<void>; log(): string }

/** The real backend serving the BUILT UI from the same origin (what the Docker image does). */
export async function startStack(env: Record<string, string> = {}): Promise<Stack> {
  if (!existsSync(path.join(DIST, "index.html"))) throw new Error("frontend/dist missing: run `npm run build` first");
  const port = await freePort();
  let proc: ChildProcess;
  let out = "";
  const launch = async () => {
    proc = spawn("python", ["-m", "uvicorn", "main:app", "--port", String(port), "--log-level", "warning"], {
      cwd: path.join(ROOT, "server"),
      env: {
        ...process.env, SENTINEL_UI_DIR: DIST, SENTINEL_ALLOWED_ORIGINS: `http://127.0.0.1:${port},http://localhost:${port}`,
        SENTINEL_MONITOR: "rules", SENTINEL_EMBEDDER: "minilm", SENTINEL_HEALTH_DETAIL: "1", HF_HUB_OFFLINE: "1", SENTINEL_GATE_TIMEOUT_S: "120", ...env,
      },
    });
    proc.stdout?.on("data", (d) => { out += d; });
    proc.stderr?.on("data", (d) => { out += d; });
    await waitHealthy(`http://127.0.0.1:${port}/health`, proc);
    // a silent fallback to the hashing stub must FAIL a journey that asked for the real embedding model
    const want = (env.SENTINEL_EMBEDDER ?? "minilm");
    const got = (await (await fetch(`http://127.0.0.1:${port}/health`)).json()).embedder;
    if (want === "minilm" && got !== "minilm") throw new Error(`asked for the MiniLM embedder but /health says "${got}"`);
  };
  const stopProc = () => new Promise<void>((res) => {
    if (!proc || proc.exitCode !== null || proc.signalCode !== null) return res();
    proc.once("exit", () => res());
    proc.kill("SIGTERM");                                  // graceful: the event log writes its final checkpoint
    setTimeout(() => proc.kill("SIGKILL"), 8000);
  });
  await launch();
  return { port, url: `http://127.0.0.1:${port}`, ws: `ws://127.0.0.1:${port}`, stop: stopProc, restart: async () => { await stopProc(); await launch(); }, log: () => out };
}

export interface Agent { call(tool: string, args: unknown): Promise<{ is_error: boolean; text: string }>; stop(): void }

/** A scripted MCP agent behind the REAL stdio proxy (tests/proxy/agent_cli.py --serve). */
export function startAgent(opts: { wsBase: string; session: string; token?: string; servers?: Record<string, unknown>; dir: string; passthrough?: Record<string, string>; autoApprove?: string[] }): Agent {
  const cfg = path.join(opts.dir, `${opts.session}.json`);
  writeFileSync(cfg, JSON.stringify({
    session_id: opts.session, backend: `${opts.wsBase}/proxy/ws`,
    servers: opts.servers ?? { fs: { command: "python", args: [DOWNSTREAM] } }, ...(opts.autoApprove ? { auto_approve: opts.autoApprove } : {}),
  }));
  const p = spawn("python", [path.join(ROOT, "tests/proxy/agent_cli.py"), "--serve", cfg], {
    cwd: ROOT, env: { ...process.env, ...(opts.token ? { SENTINEL_AGENT_TOKEN: opts.token } : {}), ...(opts.passthrough ?? {}), SENTINEL_AGENT_PASSTHROUGH: ["SENTINEL_AGENT_TOKEN", ...Object.keys(opts.passthrough ?? {})].join(",") },
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
    call: (tool, args) => new Promise((resolve) => { waiters.push(resolve); p.stdin.write(JSON.stringify({ tool, args }) + "\n"); }),
    stop: () => { p.stdin.end(); },
  };
}

export async function signIn(page: Page, token: string) {
  await page.locator('[data-testid="inbox-signin-input"]').fill(token);
  await page.locator('[data-testid="inbox-signin-submit"]').click();
}

export function sh(cmd: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv; input?: string } = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return { code: r.status ?? -1, out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "" };
}
