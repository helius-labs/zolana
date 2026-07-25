// Holds the two builds to one another. `pack:check` proves a published tarball
// resolves under both conditions; this proves the builds agree on every digest
// the fixture covers, which is the property that matters and the one a
// resolution check cannot see.
import { createRequire } from "node:module";

import { beforeAll, describe, expect, it } from "vitest";

import fixture from "../../vectors/poseidon-parity-v1.json" with { type: "json" };
import * as esm from "@zolana/hasher";

interface HasherModule {
  readonly initializePoseidon: () => Promise<void>;
  readonly poseidon: (inputs: readonly Uint8Array[]) => Uint8Array;
  readonly MAX_POSEIDON_INPUTS: number;
  readonly POSEIDON_ARTIFACT_BYTES: number;
}

const require = createRequire(import.meta.url);
const commonJs = require("@zolana/hasher") as HasherModule;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

beforeAll(async () => {
  await commonJs.initializePoseidon();
});

describe("the CommonJS and ESM builds", () => {
  // Two module instances of one artifact. They are separate singletons, so
  // this also says that initializing one does not initialize the other and
  // that each is usable on its own.
  it("are distinct module instances", () => {
    expect(commonJs).not.toBe(esm);
  });

  it("agree on the arity ceiling and the artifact size", () => {
    expect(commonJs.MAX_POSEIDON_INPUTS).toBe(esm.MAX_POSEIDON_INPUTS);
    expect(commonJs.POSEIDON_ARTIFACT_BYTES).toBe(esm.POSEIDON_ARTIFACT_BYTES);
  });

  it("produce identical digests across every Poseidon vector", () => {
    expect(fixture.vectors.length).toBeGreaterThan(0);
    for (const vector of fixture.vectors) {
      const inputs = vector.inputsBytes.map(hexToBytes);
      expect(bytesToHex(commonJs.poseidon(inputs))).toBe(vector.expectedBytes);
      expect(bytesToHex(esm.poseidon(inputs))).toBe(vector.expectedBytes);
    }
  });

  // Right-alignment happens on the TypeScript side of the boundary, so it is
  // the one behaviour the two builds could differ on without the artifact
  // differing.
  it("right-align a short input the same way", () => {
    for (const vector of fixture.shortInputs) {
      const inputs = [hexToBytes(vector.shortBytes)];
      expect(bytesToHex(commonJs.poseidon(inputs))).toBe(vector.expectedBytes);
      expect(bytesToHex(esm.poseidon(inputs))).toBe(vector.expectedBytes);
    }
  });
});
