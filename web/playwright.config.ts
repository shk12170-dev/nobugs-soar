import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";

const port = process.env.E2E_PORT ?? "5199";
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
// 로컬(Windows)은 저장소의 .venv, CI는 PATH의 python
const venvPython = resolve(root, ".venv", "Scripts", "python.exe");
const python = process.env.E2E_PYTHON ?? (existsSync(venvPython) ? venvPython : "python");

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    // 로컬은 설치된 Edge를 쓰고, CI는 playwright가 설치한 chromium을 쓴다
    ...(process.env.CI ? {} : { channel: "msedge" }),
    trace: "retain-on-failure",
  },
  webServer: {
    command: `"${python}" scripts/e2e_server.py`,
    cwd: root,
    url: `http://127.0.0.1:${port}/api/v1/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: { E2E_PORT: port },
  },
});
