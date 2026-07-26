import { defineConfig } from "vitest/config";

import { groth16VerifyGlobalSetupFile, poseidonSetupFile } from "./setup-files.js";

const DEFAULT_TIMEOUT_MS = 300_000;

function timeoutFromEnvironment(name) {
  const value = process.env[name];
  if (value === undefined) {
    return DEFAULT_TIMEOUT_MS;
  }

  const timeout = Number(value);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }

  return timeout;
}

export function defineE2eConfig(include) {
  return defineConfig({
    test: {
      fileParallelism: false,
      // prove-to-chain (and hybrid P5) shell out to the Rust groth16-verify
      // oracle; build it once before any e2e file runs.
      globalSetup: [groth16VerifyGlobalSetupFile],
      hookTimeout: timeoutFromEnvironment("ZOLANA_E2E_HOOK_TIMEOUT_MS"),
      include: [include],
      pool: "forks",
      setupFiles: [poseidonSetupFile],
      testTimeout: timeoutFromEnvironment("ZOLANA_E2E_TEST_TIMEOUT_MS"),
    },
  });
}
