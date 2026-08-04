import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: [
      "test/**/*.test.ts",
      "api/test/**/*.test.ts",
      "transaction/test/**/*.test.ts",
      "wallet/test/**/*.test.ts",
    ],
    setupFiles: ["./test/setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
