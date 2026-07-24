import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/vectors/**/*.test.ts", "test/**/*vector*.test.ts"],
    pool: "forks",
  },
});
