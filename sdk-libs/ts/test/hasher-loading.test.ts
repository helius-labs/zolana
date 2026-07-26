import { readFile } from "node:fs/promises";

import { expect, it } from "vitest";

import { isPoseidonInitialized, resetPoseidonForTests } from "../src/hasher/core.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { initializePoseidonLazy } from "../src/hasher/slim/index.js";

it("does not resolve a losing Poseidon artifact loader", async () => {
  const bytes = await readFile(new URL("../src/hasher/poseidon.wasm", import.meta.url));
  resetPoseidonForTests();
  let losingLoaderCalled = false;

  try {
    const winner = initializePoseidonLazy(async () => bytes);
    const loser = initializePoseidonLazy(async () => {
      losingLoaderCalled = true;
      throw new Error("a losing loader must remain lazy");
    });

    await Promise.all([winner, loser]);
    expect(losingLoaderCalled).toBe(false);
    expect(isPoseidonInitialized()).toBe(true);
  } finally {
    resetPoseidonForTests();
    await initializePoseidon();
  }
});
