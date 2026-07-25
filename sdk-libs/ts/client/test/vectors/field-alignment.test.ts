import { describe, expect, it } from "vitest";

import oracleJson from "../oracles/field-alignment-v1.json" with { type: "json" };
import { BN254_MODULUS, bytesField, bytesToBigInt } from "../../src/internal.js";
import { ClientError } from "../../src/index.js";
import { bytes, hex } from "../helpers/prover-vectors.js";

type FieldCase = Readonly<{
  name: string;
  bytes: string;
  alignedBytes?: string;
  value?: string;
  error?: string;
}>;

const oracle = oracleJson as Readonly<{
  expected: Readonly<{ cases: readonly FieldCase[]; modulusBytes: string }>;
}>;

function align(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  out.set(input, 32 - input.length);
  return out;
}

function thrownCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    return (error as ClientError).code;
  }
  throw new Error("expected a ClientError");
}

/// C06. `prover::field` right-aligns into 32 bytes, rejects anything longer,
/// and reads the result big-endian; it never mentions the BN254 modulus. Each
/// expectation below is what the Rust functions returned, captured by
/// `ts_field_alignment_oracle_is_current` in
/// `sdk-libs/client/tests/ts_prover_oracle.rs`.
describe("Rust-generated field alignment", () => {
  it("pins the modulus the port checks against", () => {
    expect(bytesToBigInt(bytes(oracle.expected.modulusBytes))).toBe(BN254_MODULUS);
  });

  for (const expected of oracle.expected.cases) {
    it(`${expected.name} aligns and reads as Rust does`, () => {
      const input = expected.bytes === "" ? new Uint8Array() : bytes(expected.bytes);
      if (expected.error !== undefined) {
        expect(expected.error).toBe("FieldTooLong");
        expect(input.length).toBeGreaterThan(32);
        expect(thrownCode(() => bytesField(input, "case"))).toBe("CLIENT_FIELD_TOO_LONG");
        return;
      }
      const value = BigInt(expected.value ?? "");
      expect(hex(align(input))).toBe(expected.alignedBytes);
      expect(bytesToBigInt(align(input))).toBe(value);

      // The one difference: `be` hands back whatever the 32 bytes say, while
      // `bytesField` runs the result through the BN254 range check. It does not
      // reject an assembly Rust completes: the values reaching it are 31-byte
      // secrets, Poseidon outputs, or caller-supplied hashes, and a
      // caller-supplied hash at or above the modulus already fails inside
      // Poseidon when either language hashes the UTXO. Pin the asymmetry rather
      // than describe it.
      if (value >= BN254_MODULUS) {
        expect(thrownCode(() => bytesField(input, "case"))).toBe("CLIENT_INVALID_FIELD");
        return;
      }
      expect(bytesField(input, "case")).toBe(value);
    });
  }
});
