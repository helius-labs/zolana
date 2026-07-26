import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";
import * as slim from "../src/slim/index.js";

describe("public exports", () => {
  it("pins the default entry point", () => {
    expect(Object.keys(root).sort()).toEqual([
      "HasherWasmError",
      "MAX_POSEIDON_INPUTS",
      "POSEIDON_ARTIFACT_BYTES",
      "initializePoseidon",
      "isPoseidonInitialized",
      "poseidon",
      "resetPoseidonForTests",
    ]);
  });

  it("pins the slim entry point", () => {
    expect(Object.keys(slim).sort()).toEqual([
      "HasherWasmError",
      "MAX_POSEIDON_INPUTS",
      "initializePoseidon",
      "isPoseidonInitialized",
      "poseidon",
      "resetPoseidonForTests",
    ]);
  });
});
