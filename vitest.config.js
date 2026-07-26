import { defineConfig } from "vitest/config";

import {
  groth16VerifyGlobalSetupFile,
  poseidonSetupFile,
} from "./sdk-libs/ts/config/setup-files.js";

export default defineConfig({
  test: {
    // Root `test:unit` includes client vector suites that call the Rust
    // groth16-verify oracle; build it once before any test executes.
    globalSetup: [groth16VerifyGlobalSetupFile],
    include: ["sdk-libs/ts/**/test/**/*.test.ts"],
    passWithNoTests: true,
    pool: "forks",
    setupFiles: [poseidonSetupFile],
    // The vector suites walk hundreds of cases through AES-CTR, Poseidon, and
    // Groth16 assembly. They finish in well under a second on an idle machine,
    // but forked transform work serializes under load and pushes the slowest
    // past the 5s default, which reports a timeout where there is no defect.
    testTimeout: 30_000,
  },
});
