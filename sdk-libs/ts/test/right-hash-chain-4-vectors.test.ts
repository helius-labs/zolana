import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/right_hash_chain_4.json" with { type: "json" };
import { hashChain4, poseidon, rightHashChain4 } from "../src/client/internal.js";

function scalar(value: string): bigint {
  return BigInt(`0x${value}`);
}

describe("rightHashChain4 known-answer vectors", () => {
  const expectedNames = [
    ...[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 36].map((length) => `len_${String(length)}`),
    "zero_element_in_the_middle",
    "trailing_zeros_8",
    "trailing_zeros_36",
    "all_zero_36",
  ];

  it("covers every length and shape the contract pins", () => {
    expect(vectors.vectors.map((vector) => vector.name)).toEqual(expectedNames);
  });

  it.each(vectors.vectors)("$name folds the scalar chain", (vector) => {
    expect(rightHashChain4(vector.inputs.map(scalar))).toBe(scalar(vector.output));
  });

  it("returns zero for an empty chain and the lone element unhashed", () => {
    expect(rightHashChain4([])).toBe(0n);
    expect(rightHashChain4([7n])).toBe(7n);
  });

  it("puts the short group leftmost with its elements left-aligned", () => {
    expect(rightHashChain4([1n, 2n])).toBe(poseidon([1n, 0n, 0n, 2n]));
    expect(rightHashChain4([1n, 2n, 3n])).toBe(poseidon([1n, 2n, 0n, 3n]));
    expect(rightHashChain4([1n, 2n, 3n, 4n])).toBe(poseidon([1n, 2n, 3n, 4n]));
    expect(rightHashChain4([1n, 2n, 3n, 4n, 5n])).toBe(
      poseidon([1n, 0n, 0n, poseidon([2n, 3n, 4n, 5n])]),
    );
  });

  it("agrees with the left fold only where the convention forces it to", () => {
    for (const length of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
      const values = Array.from({ length }, (_, index) => BigInt(index + 1));
      const same = rightHashChain4(values) === hashChain4(values);
      expect(same).toBe(length === 0 || length === 1 || length === 4);
    }
  });
});
