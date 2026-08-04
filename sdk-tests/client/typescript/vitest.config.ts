import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["sdk-tests/client/typescript/deposit-transfer-withdraw.test.ts"],
    testTimeout: 600_000,
  },
});
