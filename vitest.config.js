import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["sdk-libs/ts/**/test/**/*.test.ts"],
    passWithNoTests: true,
    pool: "forks",
  },
});
