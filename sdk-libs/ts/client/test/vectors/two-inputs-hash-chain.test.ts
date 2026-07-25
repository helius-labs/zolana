import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { bytesToBigInt, twoInputsHashChain } from "../../src/internal.js";

/// Replays the `createTwoInputsHashChain` vectors that
/// `xtask/src/bin/program-libs-parity.rs` already emits from
/// `program-libs/hasher`. The vectors were committed with nothing on the
/// TypeScript side reading them, which is the shape a missing port takes when it
/// is mistaken for a closed one.
///
/// The queue recorded this function as having seven callers on the proof path.
/// It has none: every reference in the workspace is its own test or this
/// oracle, so a divergence here could not have produced a bad proof today. The
/// port exists so it cannot start to.

function value(hex: string): bigint {
  return bytesToBigInt(
    Uint8Array.from(hex.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16)),
  );
}

describe("program-libs/hasher create_two_inputs_hash_chain", () => {
  for (const vector of fixture.hasher.hashChain.createTwoInputsHashChain) {
    it(`matches Rust for ${vector.name}`, () => {
      const first = vector.first.map(value);
      const second = vector.second.map(value);
      expect(twoInputsHashChain(first, second)).toBe(value(vector.output));
    });
  }

  /// Rust returns `InvalidInputLength` rather than hashing the shorter slice.
  it("rejects slices of different lengths, as Rust does", () => {
    expect(() => twoInputsHashChain([1n], [])).toThrow(/CLIENT_INVALID_LENGTH/u);
  });

  it("returns zero for two empty slices, as Rust does", () => {
    expect(twoInputsHashChain([], [])).toBe(0n);
  });
});
