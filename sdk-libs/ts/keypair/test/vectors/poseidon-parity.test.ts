import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants } from "@noble/curves/abstract/poseidon.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { KeypairError } from "../../src/error.js";
import { poseidon } from "../../src/poseidon.js";

const MODULUS = BigInt(fixture.field.modulus);
const Fp = Field(MODULUS);

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

function fieldToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function digest(values: readonly bigint[]): string {
  const bytes = new Uint8Array(values.length * 32);
  values.forEach((value, index) => {
    bytes.set(fieldToBytes(value), index * 32);
  });
  return bytesToHex(sha256(bytes));
}

// `poseidon.ts` never exposes the tables it generates, so the parameters are
// compared by rebuilding them from the same Grain LFSR options the module uses
// and digesting every constant. `arkSha256` and `mdsSha256` come from the
// arkworks tables inside `light-poseidon`, which is what `zolana-hasher` runs.
describe("Poseidon parameters against zolana-hasher", () => {
  it("uses the BN254 scalar field", () => {
    expect(Fp.ORDER).toBe(MODULUS);
    expect(bytesToHex(fieldToBytes(MODULUS))).toBe(fixture.field.modulusBytes);
    expect(bytesToHex(fieldToBytes(MODULUS - 1n))).toBe(fixture.field.modulusMinusOneBytes);
  });

  it("stops at the arity the Rust hasher supports", () => {
    expect(fixture.parameters.maxInputs).toBe(12);
    expect(fixture.parameters.perArity).toHaveLength(fixture.parameters.maxInputs);
  });

  for (const arity of fixture.parameters.perArity) {
    it(`generates the Rust round constants and MDS matrix for ${String(arity.inputs)} inputs`, () => {
      const options = {
        Fp,
        t: arity.width,
        roundsFull: fixture.parameters.roundsFull,
        roundsPartial: arity.roundsPartial,
        sboxPower: fixture.parameters.alpha,
      };
      expect(options.t).toBe(arity.inputs + 1);

      const { roundConstants, mds } = grainGenConstants(options);
      const flatConstants = roundConstants.flat();
      const flatMds = mds.flat();

      expect(flatConstants).toHaveLength(arity.arkCount);
      expect(flatMds).toHaveLength(arity.mdsCount);
      expect(digest(flatConstants)).toBe(arity.arkSha256);
      expect(digest(flatMds)).toBe(arity.mdsSha256);
    });
  }
});

describe("Poseidon vectors against zolana-hasher", () => {
  for (const vector of fixture.vectors) {
    it(vector.id, () => {
      const inputs = vector.inputsBytes.map(hexToBytes);
      expect(bytesToHex(poseidon(inputs))).toBe(vector.expectedBytes);
    });
  }

  it("covers every supported arity", () => {
    const arities = new Set(fixture.vectors.map((vector) => vector.inputsBytes.length));
    for (let arity = 1; arity <= fixture.parameters.maxInputs; arity += 1) {
      expect(arities).toContain(arity);
    }
  });
});

describe("Poseidon inputs the Rust hasher refuses", () => {
  for (const reject of fixture.rejects.filter((entry) => entry.kind !== "shorterThan32")) {
    it(reject.id, () => {
      const inputs = reject.inputsBytes.map(hexToBytes);
      expect(() => poseidon(inputs)).toThrow(KeypairError);
    });
  }
});

// Shorter inputs are a wider domain than the Rust hasher accepts, not a
// different digest: each one has to land on the Rust hash of the same value
// right-aligned into 32 bytes.
describe("Poseidon short inputs", () => {
  for (const short of fixture.shortInputs) {
    it(short.id, () => {
      expect(bytesToHex(poseidon([hexToBytes(short.shortBytes)]))).toBe(short.expectedBytes);
      expect(bytesToHex(poseidon([hexToBytes(short.alignedBytes)]))).toBe(short.expectedBytes);
    });
  }
});
