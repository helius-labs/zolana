// The vector suite asks only that a refused input throws, which a TypeScript
// screen standing in front of the module satisfies just as well as the compiled
// hasher does. That is the divergence worth catching: a screen that reduces
// mod p, or that reads the modulus off by one, refuses almost the same set and
// hashes the rest to digests no verifier reproduces. So these assert the code
// the rejection carries, which says which side of the boundary refused.
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { HasherWasmError, poseidon } from "@zolana/hasher";

/** `HasherError::Poseidon` in `program-libs/hasher/src/errors.rs`. */
const RUST_POSEIDON = 7002;

/** The codes the wrapper raises without reaching the module. */
const WRAPPER_ARITY = 1;
const WRAPPER_TOO_LONG = 7005;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function codeFrom(inputs: readonly Uint8Array[]): number {
  try {
    poseidon(inputs);
  } catch (error) {
    if (error instanceof HasherWasmError) return error.code;
    throw error;
  }
  throw new Error("the hasher accepted an input the fixture records as refused");
}

function rejectsOfKind(kind: string): readonly { id: string; inputsBytes: string[] }[] {
  const entries = fixture.rejects.filter((entry) => entry.kind === kind);
  expect(entries.length).toBeGreaterThan(0);
  return entries;
}

describe("an input at or above the modulus", () => {
  for (const reject of rejectsOfKind("notCanonical")) {
    // The fixture records Rust's own reason, so the code pinned here stays tied
    // to the rejection Rust actually raises rather than to one asserted once.
    it(`${reject.id} is refused by the compiled hasher, not by the wrapper`, () => {
      expect(reject.reason).toContain("InputLargerThanModulus");
      expect(codeFrom(reject.inputsBytes.map(hexToBytes))).toBe(RUST_POSEIDON);
    });
  }

  // The whole boundary in two lines: the largest field element hashes, and the
  // modulus itself does not.
  it("puts the boundary at the modulus", () => {
    expect(poseidon([hexToBytes(fixture.field.modulusMinusOneBytes)])).toHaveLength(32);
    expect(codeFrom([hexToBytes(fixture.field.modulusBytes)])).toBe(RUST_POSEIDON);
  });
});

// Arity and over-length cannot reach the module: thirteen elements do not fit
// the twelve-slot buffer, and a longer input would overrun its neighbour. Rust
// answers 7002 for both, so the wrapper's codes are a divergence, and pinning
// them keeps it deliberate.
describe("an input the wrapper refuses before the module", () => {
  for (const reject of rejectsOfKind("arity")) {
    it(reject.id, () => {
      expect(codeFrom(reject.inputsBytes.map(hexToBytes))).toBe(WRAPPER_ARITY);
    });
  }

  for (const reject of rejectsOfKind("longerThan32")) {
    it(reject.id, () => {
      expect(codeFrom(reject.inputsBytes.map(hexToBytes))).toBe(WRAPPER_TOO_LONG);
    });
  }
});

// The one input Rust refuses that the wrapper takes. `shortInputs` pins the
// digest; this pins the acceptance, so narrowing the wrapper back to Rust's
// strict 32 bytes shows up here rather than in a caller.
describe("an input shorter than the field", () => {
  for (const reject of rejectsOfKind("shorterThan32")) {
    it(`${reject.id} is accepted right-aligned`, () => {
      expect(poseidon(reject.inputsBytes.map(hexToBytes))).toHaveLength(32);
    });
  }
});
