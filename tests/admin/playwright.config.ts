import { defineConfig } from "@playwright/test";
const output =
  process.env.FLAGON_E2E_OUTPUT || "../../artifacts/glory-migration/current";
export default defineConfig({
  testDir: ".",
  testMatch: "admin.spec.ts",
  workers: 1,
  retries: 0,
  timeout: 30000,
  expect: { timeout: 10000 },
  outputDir: output + "/results",
  reporter: [["list"], ["json", { outputFile: output + "/results.json" }]],
  use: {
    baseURL: process.env.FLAGON_E2E_BASE_URL || "http://127.0.0.1:4183",
    browserName: "chromium",
    channel: process.env.FLAGON_E2E_CHANNEL || "msedge",
    viewport: { width: 1440, height: 900 },
    trace: "off",
    screenshot: "only-on-failure",
  },
});
