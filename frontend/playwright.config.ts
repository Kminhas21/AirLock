import { defineConfig } from "@playwright/test";

// Real stack: Vite UI <-> real WebSocket <-> real FastAPI backend <-> HTTP LLM endpoint (scripted).
// Chromium comes from the pre-installed browser (no download).
// Ports are overridable: LLM_PORT / API_PORT (e2e/helpers/traces.ts reads the same variables).
const LLM_PORT = Number(process.env.LLM_PORT ?? 9101);
const API_PORT = Number(process.env.API_PORT ?? 8081);
const UI_PORT = 5173; // the backend's default Origin allow-list is http://localhost:5173

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
    {
      command: `python -m uvicorn main:app --port ${API_PORT} --log-level warning`,
      cwd: "../server",
      url: `http://127.0.0.1:${API_PORT}/health`,
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
        // (REPLAY_DETECTOR=D1) are about the RULES monitor. The action_sim / learned runs are separate gate stages.
        SENTINEL_MONITOR: process.env.SENTINEL_MONITOR ?? "rules",
        ...(process.env.SENTINEL_MONITOR_MODEL ? { SENTINEL_MONITOR_MODEL: process.env.SENTINEL_MONITOR_MODEL } : {}),
      },
    },
    {
      command: `npx vite --port ${UI_PORT} --strictPort`,
      url: `http://localhost:${UI_PORT}`,
      reuseExistingServer: false,
      env: { VITE_SENTINEL_WS_URL: `ws://127.0.0.1:${API_PORT}/ws` },
    },
  ],
});
