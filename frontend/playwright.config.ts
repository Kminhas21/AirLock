import { defineConfig } from "@playwright/test";

// Real stack: Vite UI <-> real WebSocket <-> real FastAPI backend <-> HTTP LLM endpoint (scripted).
// Chromium comes from the pre-installed browser (no download).
// Ports are overridable: LLM_PORT / API_PORT (e2e/helpers/traces.ts reads the same variables).
const LLM_PORT = Number(process.env.LLM_PORT ?? 9101);
const API_PORT = Number(process.env.API_PORT ?? 8081);
// Optional second backend WITHOUT SENTINEL_REGISTRY (registry-ui.spec.ts: the loud fallback). Off unless this is set.
const FALLBACK_API_PORT = process.env.FALLBACK_API_PORT ? Number(process.env.FALLBACK_API_PORT) : 0;
const UI_PORT = 5173; // the backend's default Origin allow-list is http://localhost:5173

/** The real FastAPI backend. `registry` = SENTINEL_REGISTRY for this process (undefined: variable not set at all). */
function backend(port: number, registry: string | undefined) {
  return {
    command: `python -m uvicorn main:app --port ${port} --log-level warning`,
    cwd: "../server",
    url: `http://127.0.0.1:${port}/health`,
    reuseExistingServer: false,
    env: {
      OPENROUTER_API_KEY: "test-key",
      OPENROUTER_BASE_URL: `http://127.0.0.1:${LLM_PORT}/v1`,
      SENTINEL_GATE_TIMEOUT_S: "30",
      // The real MiniLM model (cached locally, never downloaded) is the default so a stub fallback is visible:
      // replay-traces asserts /health reports the embedder in EXPECT_EMBEDDER (default minilm).
      SENTINEL_EMBEDDER: process.env.SENTINEL_EMBEDDER ?? "minilm",
      HF_HUB_OFFLINE: "1",
      // Pinned explicitly: the server default is action_sim, but live.spec.ts and the default replay expectations
      // (REPLAY_DETECTOR=D1) are about the RULES monitor. The action_sim / learned / registry runs are separate gate stages.
      SENTINEL_MONITOR: process.env.SENTINEL_MONITOR ?? "rules",
      ...(process.env.SENTINEL_MONITOR_MODEL ? { SENTINEL_MONITOR_MODEL: process.env.SENTINEL_MONITOR_MODEL } : {}),
      // registry / registry_learned: the destination registry (same file the offline expectations were made with)
      // (always set, "" = not set, so a SENTINEL_REGISTRY in the caller's shell cannot leak into the fallback backend)
      SENTINEL_REGISTRY: registry ?? "",
      ...(process.env.SENTINEL_REGISTRY_MODEL ? { SENTINEL_REGISTRY_MODEL: process.env.SENTINEL_REGISTRY_MODEL } : {}),
    },
  };
}

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  workers: 1,
  reporter: [["list"]],
  outputDir: "./e2e/.results",
  use: {
    baseURL: `http://localhost:${UI_PORT}`,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    launchOptions: { executablePath: process.env.CHROMIUM_PATH ?? "/opt/pw-browsers/chromium" },
  },
  webServer: [
    {
      command: `python ../tests/browser/fake_llm.py ${LLM_PORT}`,
      url: `http://127.0.0.1:${LLM_PORT}/_calls`,
      reuseExistingServer: false,
      env: process.env.FAKE_LLM_TRACES ? { FAKE_LLM_TRACES: process.env.FAKE_LLM_TRACES } : {},
    },
    backend(API_PORT, process.env.REPLAY_REGISTRY),
    ...(FALLBACK_API_PORT ? [backend(FALLBACK_API_PORT, undefined)] : []),
    {
      command: `npx vite --port ${UI_PORT} --strictPort`,
      url: `http://localhost:${UI_PORT}`,
      reuseExistingServer: false,
      env: { VITE_SENTINEL_WS_URL: `ws://127.0.0.1:${API_PORT}/ws` },
    },
  ],
});
