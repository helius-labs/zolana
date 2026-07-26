import { defineConfig } from "vitest/config";

import { groth16VerifyGlobalSetupFile, poseidonSetupFile } from "./setup-files.js";

export default defineConfig({
  test: {
    globalSetup: [groth16VerifyGlobalSetupFile],
    include: ["test/vectors/**/*.test.ts", "test/**/*vector*.test.ts"],
    pool: "forks",
    setupFiles: [poseidonSetupFile],
  },
});
