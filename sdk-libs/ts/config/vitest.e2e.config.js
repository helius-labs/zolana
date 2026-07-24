import { defineConfig } from "vitest/config";

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
      hookTimeout: timeoutFromEnvironment("ZOLANA_E2E_HOOK_TIMEOUT_MS"),
      include: [include],
      pool: "forks",
      testTimeout: timeoutFromEnvironment("ZOLANA_E2E_TEST_TIMEOUT_MS"),
    },
  });
}
