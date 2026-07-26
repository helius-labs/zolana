import { grainGenConstants } from "@noble/curves/abstract/poseidon.js";
import { bn254_Fr } from "@noble/curves/bn254.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import type { Bytes32 } from "../../src/bytes.js";
import { poseidonHasher } from "../../src/hashers.js";

// `hashers.ts` is the only port that takes its field from `bn254_Fr` instead of
// building one from the modulus literal, and it builds permutations for one and
// two inputs only, which is all a Merkle tree needs.
const SUPPORTED_ARITIES = [1, 2] as const;

function hexToBytes(hex: string): Bytes32 {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes as Bytes32;
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

function hash(inputs: readonly Bytes32[]): Bytes32 {
  const [left, right] = inputs;
  if (left === undefined) throw new Error("at least one input is required");
  return right === undefined ? poseidonHasher.hashBytes(left) : poseidonHasher.hash(left, right);
}

describe("Poseidon parameters against zolana-hasher", () => {
  it("takes the BN254 scalar field from @noble/curves", () => {
    expect(bn254_Fr.ORDER).toBe(BigInt(fixture.field.modulus));
  });

  for (const inputs of SUPPORTED_ARITIES) {
    it(`generates the Rust round constants and MDS matrix for ${String(inputs)} inputs`, () => {
      const arity = fixture.parameters.perArity.find((entry) => entry.inputs === inputs);
      expect(arity).toBeDefined();
      if (arity === undefined) return;

      const { roundConstants, mds } = grainGenConstants({
        Fp: bn254_Fr,
        t: arity.width,
        roundsFull: fixture.parameters.roundsFull,
        roundsPartial: arity.roundsPartial,
        sboxPower: fixture.parameters.alpha,
      });
      expect(digest(roundConstants.flat())).toBe(arity.arkSha256);
      expect(digest(mds.flat())).toBe(arity.mdsSha256);
    });
  }
});

describe("Poseidon vectors against zolana-hasher", () => {
  const vectors = fixture.vectors.filter((vector) =>
    (SUPPORTED_ARITIES as readonly number[]).includes(vector.inputsBytes.length),
  );

  it("covers both Merkle arities", () => {
    for (const arity of SUPPORTED_ARITIES) {
      expect(vectors.some((vector) => vector.inputsBytes.length === arity)).toBe(true);
    }
  });

  for (const vector of vectors) {
    it(vector.id, () => {
      expect(bytesToHex(hash(vector.inputsBytes.map(hexToBytes)))).toBe(vector.expectedBytes);
    });
  }
});

// This port checks input lengths strictly, so it refuses everything the Rust
// hasher refuses at one and two inputs, including the short inputs the other
// ports accept.
describe("Poseidon inputs the Rust hasher refuses", () => {
  const reachable = fixture.rejects.filter(
    (reject) => reject.inputsBytes.length >= 1 && reject.inputsBytes.length <= 2,
  );

  it("reaches the length and field rejections", () => {
    expect(reachable.map((reject) => reject.kind).sort()).toEqual([
      "longerThan32",
      "notCanonical",
      "notCanonical",
      "shorterThan32",
    ]);
  });

  for (const reject of reachable) {
    it(reject.id, () => {
      expect(() => hash(reject.inputsBytes.map(hexToBytes))).toThrow();
    });
  }
});
