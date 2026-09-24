import { defineConfig } from "vitest/config";

const example = process.env["ZOLANA_TS_EXAMPLE"] ?? "deposit-transfer-withdraw";

export default defineConfig({
  test: {
    environment: "node",
    include: [`sdk-tests/client/typescript/${example}.test.ts`],
    testTimeout: 600_000,
  },
});
