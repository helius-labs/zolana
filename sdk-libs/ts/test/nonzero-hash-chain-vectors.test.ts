import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/nonzero_hash_chain.json" with { type: "json" };
import { nonZeroHashChain } from "../src/transaction/internal.js";
import type { Bytes32 } from "../src/keypair/index.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function bytes(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function output(name: string): string {
  const vector = vectors.vectors.find((entry) => entry.name === name);
  if (vector === undefined) {
    throw new Error(`missing vector ${name}`);
  }
  return vector.output;
}

describe("nonZeroHashChain known-answer vectors", () => {
  const expectedNames = [
    "empty",
    "single_zero",
    "all_zero_4",
    "single",
    ...[2, 3, 4, 5, 8, 36].map((length) => `len_${String(length)}`),
    "leading_zero",
    "trailing_zero",
    "zeros_between",
    "padded_len_3",
    "reversed_len_3",
    "field_modulus_minus_one",
  ];

  it("covers every case the contract pins", () => {
    expect(vectors.vectors.map((vector) => vector.name)).toEqual(expectedNames);
  });

  it.each(vectors.vectors)("$name folds the chain", (vector) => {
    expect(hex(nonZeroHashChain(vector.inputs.map(bytes)))).toBe(vector.output);
  });

  it("skips padding and keeps the order of nonzero entries", () => {
    expect(output("padded_len_3")).toBe(output("len_3"));
    expect(output("reversed_len_3")).not.toBe(output("len_3"));
  });
});
