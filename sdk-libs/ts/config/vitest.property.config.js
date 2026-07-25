import { defineConfig } from "vitest/config";

import { poseidonSetupFile, propertySetupFile } from "./setup-files.js";

export default defineConfig({
  test: {
    include: ["test/property/**/*.test.ts", "test/**/*property*.test.ts"],
    pool: "forks",
    sequence: {
      seed: 1_515_146_305,
    },
    setupFiles: [poseidonSetupFile, propertySetupFile],
  },
});
