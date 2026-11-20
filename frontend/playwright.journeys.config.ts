import { defineConfig } from "@playwright/test";

// User-journey suite (docs/JOURNEYS.md): each journey starts its OWN real stack (backend serving the built UI, real proxy, scripted agent) and
// writes named screenshots to journeys/.shots/<journey>/ (untracked). Run: npm run build && npx playwright test -c playwright.journeys.config.ts
export default defineConfig({
  testDir: "./journeys",
  timeout: 240_000,
  workers: 1,
  reporter: [["list"]],
  outputDir: "./journeys/.results",
  use: {
    viewport: { width: 1280, height: 860 },
    screenshot: "only-on-failure",
    launchOptions: { executablePath: process.env.CHROMIUM_PATH ?? "/opt/pw-browsers/chromium" },
  },
});
