import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/vectors.test.ts", "test/responses.test.ts"],
    pool: "forks",
  },
});
