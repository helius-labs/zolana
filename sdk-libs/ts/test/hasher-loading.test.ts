import { WasmFactory } from "@lightprotocol/hasher.rs";
import { expect, it, vi } from "vitest";

import {
  initializePoseidon,
  isPoseidonInitialized,
  resetPoseidonForTests,
} from "../src/hasher/index.js";

it("initializes the Poseidon runtime once", async () => {
  resetPoseidonForTests();
  const loadHasher = vi.spyOn(WasmFactory, "loadHasher");

  try {
    await Promise.all([initializePoseidon(), initializePoseidon(), initializePoseidon()]);
    expect(loadHasher).toHaveBeenCalledTimes(1);
    expect(isPoseidonInitialized()).toBe(true);
  } finally {
    loadHasher.mockRestore();
    resetPoseidonForTests();
    await initializePoseidon();
  }
});
