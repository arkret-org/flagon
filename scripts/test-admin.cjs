const { spawn, spawnSync } = require("node:child_process");
const { mkdirSync, openSync } = require("node:fs");
const { join, resolve } = require("node:path");
const http = require("node:http");
const env = { ...process.env };
const root = resolve(__dirname, "..");
if (process.platform === "win32") {
  env.TEMP = env.TMP = "D:/BuildCache/flagon-glory/tmp";
  env.PWTEST_CACHE_DIR = "D:/BuildCache/flagon-glory/playwright-cache";
  for (const path of [env.TEMP, env.PWTEST_CACHE_DIR])
    mkdirSync(path, { recursive: true });
}
const output =
  env.FLAGON_E2E_OUTPUT || join(root, "artifacts/glory-migration/current");
mkdirSync(output, { recursive: true });
const base = env.FLAGON_E2E_BASE_URL || "http://127.0.0.1:4183";
let server;
async function ready() {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (server.exitCode !== null)
      throw Error("Audit-console server exited before readiness");
    const ok = await new Promise((resolve) => {
      const request = http.get(base, (response) => {
        response.resume();
        resolve(response.statusCode === 200);
      });
      request.on("error", () => resolve(false));
      request.setTimeout(250, () => request.destroy());
    });
    if (ok) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error("Audit-console server did not become ready");
}
(async () => {
  try {
    if (env.FLAGON_E2E_WEB_DIR) {
      const log = openSync(join(output, "server.log"), "w");
      server = spawn(
        env.PYTHON || "python",
        [
          join(root, "scripts/serve-admin.py"),
          "--dir",
          env.FLAGON_E2E_WEB_DIR,
          "--port",
          new URL(base).port || "80",
        ],
        { cwd: root, env, stdio: ["ignore", log, log] },
      );
      await ready();
    }
    const run = spawnSync(
      process.execPath,
      [
        join(root, "node_modules/@playwright/test/cli.js"),
        "test",
        "-c",
        "tests/admin/playwright.config.ts",
        ...process.argv.slice(2),
      ],
      { cwd: root, env, stdio: "inherit" },
    );
    if (run.error) console.error(run.error);
    process.exitCode = run.status ?? 1;
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  } finally {
    server?.kill();
  }
})();
