// Held against the built entry point rather than the source. What this package
// is for is how the artifact loads, so the thing worth testing is the module a
// consumer resolves, and the singleton has to be the one the suite setup
// initialized for a reset here to mean anything.
import { afterEach, describe, expect, it } from "vitest";

import {
  HasherWasmError,
  initializePoseidon,
  isPoseidonInitialized,
  MAX_POSEIDON_INPUTS,
  poseidon,
  resetPoseidonForTests,
} from "@zolana/hasher";

const ONE = Uint8Array.from([1]);
const TWO = Uint8Array.from([2]);

// The suites are initialized by `config/poseidon.setup.mjs`, so every test here
// that resets the module has to put it back.
afterEach(async () => {
  await initializePoseidon();
});

describe("initializePoseidon", () => {
  it("refuses to hash before it is called, naming the missing call", () => {
    resetPoseidonForTests();
    expect(isPoseidonInitialized()).toBe(false);
    expect(() => poseidon([ONE, TWO])).toThrow(HasherWasmError);
    expect(() => poseidon([ONE, TWO])).toThrow(/initializePoseidon/);
  });

  // The uninitialized check comes before the arity check, so a caller who
  // forgot the initializer is told that rather than being told about arity.
  it("reports the missing load rather than the arity for a bad call", () => {
    resetPoseidonForTests();
    expect(() => poseidon([])).toThrow(/initializePoseidon/);
  });

  it("is safe to call twice", async () => {
    resetPoseidonForTests();
    await initializePoseidon();
    const first = poseidon([ONE, TWO]);
    await initializePoseidon();
    expect(poseidon([ONE, TWO])).toStrictEqual(first);
  });

  // Concurrent callers must share one instantiation rather than race two, and
  // must all be able to hash once any of them resolves.
  it("is safe to call concurrently", async () => {
    resetPoseidonForTests();
    await Promise.all(Array.from({ length: 8 }, () => initializePoseidon()));
    expect(isPoseidonInitialized()).toBe(true);
    expect(poseidon([ONE, TWO])).toHaveLength(32);
  });

  it("hashes the same digest before and after a reload", async () => {
    const before = poseidon([ONE, TWO]);
    resetPoseidonForTests();
    await initializePoseidon();
    expect(poseidon([ONE, TWO])).toStrictEqual(before);
  });

  // The arity ceiling is stated in TypeScript because callers need it before
  // the module loads, and checked against the module at every load.
  it("agrees with the compiled module on the arity ceiling", () => {
    expect(MAX_POSEIDON_INPUTS).toBe(12);
    expect(() => poseidon(Array.from({ length: 13 }, () => ONE))).toThrow(/1 to 12/);
  });
});
