// Loads the compiled Poseidon before any suite runs.
//
// The packages require an explicit `initializePoseidon()` because a module-scope
// await cannot be expressed in a CommonJS build. A consumer makes that call
// once at startup; for the suites this file is that call, so a test reads like
// the synchronous code it is testing. The uninitialized path is not skipped by
// this: `hasher/test/initialization.test.ts` resets the module and asserts the
// refusal.
import { initializePoseidon } from "@zolana/hasher";

await initializePoseidon();
