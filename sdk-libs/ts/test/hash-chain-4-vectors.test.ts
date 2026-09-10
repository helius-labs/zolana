import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/hash_chain_4.json" with { type: "json" };
import { hashChain, hashChain4, poseidon } from "../src/client/internal.js";
import { hashChain4 as hashChain4Bytes } from "../src/transaction/internal.js";
import type { Bytes32 } from "../src/keypair/index.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function scalar(value: string): bigint {
  return BigInt(`0x${value}`);
}

describe("hashChain4 known-answer vectors", () => {
  const expectedNames = [
    ...[0, 1, 2, 3, 4, 5, 7, 8, 16, 36].map((length) => `len_${String(length)}`),
    "zero_element_in_the_middle",
  ];

  it("covers every length the contract pins", () => {
    expect(vectors.vectors.map((vector) => vector.name)).toEqual(expectedNames);
  });

  it.each(vectors.vectors)("$name folds the scalar chain", (vector) => {
    expect(hashChain4(vector.inputs.map(scalar))).toBe(scalar(vector.output));
  });

  it.each(vectors.vectors)("$name folds the byte chain", (vector) => {
    expect(hex(hashChain4Bytes(vector.inputs.map(bytes)))).toBe(vector.output);
  });

  it("matches the binary chain on zero and one element", () => {
    expect(hashChain4([])).toBe(hashChain([]));
    expect(hashChain4([7n])).toBe(hashChain([7n]));
  });

  it("uses one zero-padded 4-input Poseidon call for up to four elements", () => {
    expect(hashChain4([1n, 2n])).toBe(poseidon([1n, 2n, 0n, 0n]));
    expect(hashChain4([1n, 2n, 3n])).toBe(poseidon([1n, 2n, 3n, 0n]));
    expect(hashChain4([1n, 2n, 3n, 4n])).toBe(poseidon([1n, 2n, 3n, 4n]));
    expect(hashChain4([1n, 2n, 3n, 4n, 5n])).toBe(
      poseidon([poseidon([1n, 2n, 3n, 4n]), 5n, 0n, 0n]),
    );
  });
});
