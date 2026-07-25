import { defineConfig } from "vitest/config";

import { poseidonSetupFile } from "./setup-files.js";

export default defineConfig({
  test: {
    include: ["test/vectors/**/*.test.ts", "test/**/*vector*.test.ts"],
    pool: "forks",
    setupFiles: [poseidonSetupFile],
  },
});
