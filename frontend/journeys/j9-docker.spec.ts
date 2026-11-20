import { randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { freePort, sh, shooter } from "./lib";

// W9: the Docker user. The REAL image (hardened: read-only rootfs, non-root, cap_drop ALL) serves the UI; sign in with the bootstrap token; the demo agent
// runs in a SECOND container on the same network, its call is held, the operator decides in the browser. Needs Docker and the images (see docs/DOCKER.md).
const IMAGE = process.env.JOURNEY_DOCKER_IMAGE ?? "sentinel:local";
const DEMO = process.env.JOURNEY_DOCKER_DEMO_IMAGE ?? "sentinel:demo";
const have = (i: string) => sh("docker", ["image", "inspect", i]).code === 0;
test.skip(!have(IMAGE) || !have(DEMO), `docker images ${IMAGE} / ${DEMO} not built (docs/DOCKER.md)`);

const ADMIN = randomBytes(24).toString("base64url");
const AGENT = randomBytes(24).toString("base64url");
const NET = `journey-net-${randomBytes(4).toString("hex")}`;
const HUB = `journey-hub-${randomBytes(4).toString("hex")}`;
const created: string[] = [];
test.afterAll(() => { for (const c of created) sh("docker", ["rm", "-f", c]); sh("docker", ["network", "rm", NET]); });

test("W9 docker: the container serves the UI, the operator signs in, a demo agent in another container is held and decided", async ({ page }) => {
  const shot = shooter("W9-docker");
  const port = await freePort();
  expect(sh("docker", ["network", "create", NET]).code).toBe(0);
  const run = sh("docker", ["run", "-d", "--name", HUB, "--network", NET, "--network-alias", "sentinel", "-p", `127.0.0.1:${port}:8080`,
    "--read-only", "--tmpfs", "/tmp:size=64m,mode=1777", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "-e", `SENTINEL_BOOTSTRAP_ADMIN_TOKEN=${ADMIN}`, "-e", `SENTINEL_BOOTSTRAP_AGENT_TOKEN=${AGENT}`, "-e", `SENTINEL_ALLOWED_ORIGINS=http://127.0.0.1:${port}`,
    "-e", "SENTINEL_EVENT_LOG=/var/lib/sentinel/events.db", "-e", `SENTINEL_LOG_KEY=${randomBytes(18).toString("base64url")}`,
    "-v", `${HUB}-data:/var/lib/sentinel`, IMAGE]);
  expect(run.code, run.out).toBe(0);
  created.push(HUB);
  for (let i = 0; i < 120; i++) {
    if (sh("docker", ["inspect", "-f", "{{.State.Health.Status}}", HUB]).out.trim() === "healthy") break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  expect(sh("docker", ["inspect", "-f", "{{.State.Health.Status}}", HUB]).out.trim()).toBe("healthy");
  // evidence that this is the hardened image, as a real user could check it
  expect(sh("docker", ["exec", HUB, "id", "-u"]).out.trim()).toBe("10001");

  await page.goto(`http://127.0.0.1:${port}/`);
  await shot(page, "ui-served-by-the-container");
  await page.click('[data-testid="tab-inbox"]');
  await expect(page.locator('[data-testid="inbox-signin"]')).toBeVisible();
  await shot(page, "sign-in-required");
  await page.locator('[data-testid="inbox-signin-input"]').fill("wrong-token-wrong-token");
  await page.locator('[data-testid="inbox-signin-submit"]').click();
  await expect(page.locator('[data-testid="inbox-signin-error"]')).toBeVisible({ timeout: 15_000 });
  await shot(page, "wrong-token-refused");
  await page.locator('[data-testid="inbox-signin-input"]').fill(ADMIN);
  await page.locator('[data-testid="inbox-signin-submit"]').click();
  await expect(page.locator('[data-testid="inbox-identity"]')).toHaveText(/admin/, { timeout: 20_000 });
  await shot(page, "signed-in-with-the-bootstrap-token");

  const demo = `journey-demo-${randomBytes(4).toString("hex")}`;
  const d = sh("docker", ["run", "-d", "--name", demo, "--network", NET, "--read-only", "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL",
    "-e", `SENTINEL_AGENT_TOKEN=${AGENT}`, "-e", "SENTINEL_AGENT_PASSTHROUGH=SENTINEL_AGENT_TOKEN", "--entrypoint", "python", DEMO,
    "/app/tests/proxy/agent_cli.py", "/etc/sentinel/demo-proxy.json", "write_file", '{"path": "/tmp/report.txt", "content": "quarterly numbers"}']);
  expect(d.code, d.out).toBe(0);
  created.push(demo);
  const card = page.locator('[data-testid="inbox-pending"]').first();
  await expect(card).toBeVisible({ timeout: 90_000 });
  await expect(card).toContainText("write_file");
  await shot(page, "demo-agent-in-another-container-held-for-you");
  await card.locator('[data-testid="inbox-approve"]').click();
  await expect(page.locator('[data-testid="inbox-resolved"]').first()).toBeVisible({ timeout: 20_000 });
  await shot(page, "approved-in-the-browser");
  expect(sh("docker", ["wait", demo]).out.trim()).toBe("0");
  expect(sh("docker", ["logs", demo]).out).toContain('"is_error": false');
  // the audit log lives on the volume and verifies
  const verify = sh("docker", ["exec", "-w", "/app/server", HUB, "python", "-m", "eventlog_cli", "verify", "/var/lib/sentinel/events.db"]);
  expect(verify.out).toMatch(/OK|checkpoints/);
});
