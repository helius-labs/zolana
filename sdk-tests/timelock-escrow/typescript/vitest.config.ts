import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["sdk-tests/timelock-escrow/typescript/*.test.ts"],
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
