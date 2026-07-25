import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { ClientError } from "../../src/error.js";
import { bigintToBytes, bytesToBigInt, hashChain, poseidon } from "../../src/internal.js";

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

function fieldsOf(inputsBytes: readonly string[]): readonly bigint[] {
  return inputsBytes.map((input) => bytesToBigInt(hexToBytes(input)));
}

// The client keeps its own Poseidon rather than importing `@zolana/keypair`'s,
// so the sibling parity suites in keypair, transaction, interface, and
// merkle-tree say nothing about this copy. It is the one that feeds the proof
// public inputs, so it is compared against the same `zolana-hasher` vectors.
describe("client Poseidon against zolana-hasher", () => {
  for (const vector of fixture.vectors) {
    it(`matches Poseidon::hashv for ${vector.id}`, () => {
      const result = poseidon(fieldsOf(vector.inputsBytes));
      expect(bytesToHex(bigintToBytes(result))).toBe(vector.expectedBytes);
    });
  }

  it("covers every supported arity", () => {
    const arities = new Set(fixture.vectors.map((vector) => vector.inputsBytes.length));
    for (let arity = 1; arity <= fixture.parameters.maxInputs; arity += 1) {
      expect(arities).toContain(arity);
    }
  });
});

describe("client Poseidon inputs the Rust hasher refuses", () => {
  // A digest over more inputs than `light_poseidon` and the `sol_poseidon`
  // syscall accept is one no on-chain verifier can reproduce, so producing one
  // is worse than refusing to.
  for (const reject of fixture.rejects.filter((entry) => entry.kind !== "shorterThan32")) {
    it(reject.id, () => {
      expect(() => poseidon(fieldsOf(reject.inputsBytes))).toThrow(ClientError);
    });
  }

  it("refuses the first arity above the supported maximum", () => {
    const supported = Array.from({ length: fixture.parameters.maxInputs }, () => 1n);
    expect(() => poseidon(supported)).not.toThrow();
    expect(() => poseidon([...supported, 1n])).toThrow(ClientError);
  });
});

// `hashChain` is `create_hash_chain_from_slice`: fold left with Poseidon, and
// return the sole element unhashed rather than hashing it against a seed.
describe("client hashChain against create_hash_chain_from_slice", () => {
  it("returns zero for an empty chain", () => {
    expect(hashChain([])).toBe(0n);
  });

  it("returns a single element unhashed", () => {
    expect(hashChain([7n])).toBe(7n);
  });

  it("is order sensitive", () => {
    expect(hashChain([1n, 2n])).not.toBe(hashChain([2n, 1n]));
  });

  it("folds left, pairwise", () => {
    expect(hashChain([1n, 2n, 3n])).toBe(poseidon([poseidon([1n, 2n]), 3n]));
  });
});
