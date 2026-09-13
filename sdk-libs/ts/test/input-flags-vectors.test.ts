import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/input_flags.json" with { type: "json" };
import { ClientError } from "../src/client/error.js";
import { inputFlags } from "../src/client/internal.js";
import { INPUT_TREES } from "../src/interface/tree-slot.js";

function hex(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

describe("input flags packing vectors (test-vectors/input_flags.json)", () => {
  it("packs the same element the Rust and Go twins pack", () => {
    expect(vectors.input_trees).toBe(INPUT_TREES);
    for (const vector of vectors.vectors) {
      const packed = inputFlags(vector.allow_dummy_inputs, vector.tree_indexes);
      expect(`${vector.name}:${packed.toString()}`).toBe(
        `${vector.name}:${vector.input_flags_decimal}`,
      );
      expect(`${vector.name}:${hex(packed)}`).toBe(`${vector.name}:${vector.input_flags}`);
    }
  });

  it("places the policy in bit 0 and every tree index three bits above it", () => {
    expect(inputFlags(true, [])).toBe(1n);
    expect(inputFlags(false, [])).toBe(0n);
    expect(inputFlags(false, [0])).toBe(0n);
    expect(inputFlags(true, [0])).toBe(1n);
    expect(inputFlags(true, [0, 1])).toBe(17n);
    expect(inputFlags(false, [0, 1])).toBe(16n);
    expect(inputFlags(true, [0, 1, 1])).toBe(145n);
    expect(inputFlags(true, [0, 1, 2, 3, 4])).toBe(36113n);
    expect(inputFlags(true, [4])).toBe(9n);
    // A four-input shape occupies 13 bits, so the width is 1 + 3 * inputs.
    expect(inputFlags(true, [4, 4, 4, 4]).toString(2).length).toBe(13);
  });

  it("refuses a tree index no proof publishes a slot for", () => {
    expect(() => inputFlags(true, [0, INPUT_TREES])).toThrow(ClientError);
    try {
      inputFlags(true, [0, INPUT_TREES]);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ClientError);
      expect((error as ClientError).code).toBe("CLIENT_INPUT_TREE_INDEX_RANGE");
      expect((error as ClientError).details).toEqual({
        index: 1,
        treeIndex: INPUT_TREES,
        max: INPUT_TREES - 1,
      });
    }
    expect(() => inputFlags(true, [-1])).toThrow(ClientError);
    expect(() => inputFlags(true, [1.5])).toThrowError(
      expect.objectContaining({ code: "CLIENT_INVALID_INTEGER" }),
    );
  });
});
