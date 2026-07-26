import { defineConfig } from "vitest/config";

import { poseidonSetupFile } from "./setup-files.js";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    passWithNoTests: true,
    pool: "forks",
    setupFiles: [poseidonSetupFile],
  },
});
