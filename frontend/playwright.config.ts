import { defineConfig } from "@playwright/test";

// Real stack: Vite UI <-> real WebSocket <-> real FastAPI backend <-> HTTP LLM endpoint (scripted).
// Chromium comes from the pre-installed browser (no download).
const LLM_PORT = 9101;
const API_PORT = 8081;
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
        SENTINEL_EMBEDDER: process.env.SENTINEL_EMBEDDER ?? "stub",
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
