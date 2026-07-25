import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["sdk-libs/ts/**/test/**/*.test.ts"],
    passWithNoTests: true,
    pool: "forks",
    // The vector suites walk hundreds of cases through AES-CTR, Poseidon, and
    // Groth16 assembly. They finish in well under a second on an idle machine,
    // but forked transform work serializes under load and pushes the slowest
    // past the 5s default, which reports a timeout where there is no defect.
    testTimeout: 30_000,
  },
});
