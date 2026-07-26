import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@zolana/interface";

import proverShapesJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import oracleJson from "../oracles/field-alignment-v1.json" with { type: "json" };
import { BN254_MODULUS, bytesField, bytesToBigInt } from "../../src/internal.js";
import { ClientError } from "../../src/index.js";
import { assemble } from "../../src/prover/index.js";
import {
  buildProofInputs,
  bytes,
  hex,
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";

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

      // Raw `be` still accepts these (it mirrors `bytesToBigInt`); production
      // assembly reads merkle witnesses through `checked_be`, which matches
      // `bytesField`. Pin both sides of that split.
      if (value >= BN254_MODULUS) {
        expect(thrownCode(() => bytesField(input, "case"))).toBe("CLIENT_INVALID_FIELD");
        return;
      }
      expect(bytesField(input, "case")).toBe(value);
    });
  }

  /**
   * Merkle witness bytes come off the indexer and are never hashed before they
   * become fields. Both languages refuse a root at the modulus at assembly:
   * TypeScript through `bytesField`, Rust through `checked_be`
   * (`p256_and_eddsa.rs` input assembly).
   */
  it("refuses a merkle root at the modulus at assembly", () => {
    const shapes = proverShapesJson as unknown as ProverShapesFixture;
    const source = buildProofInputs(shapes, "eddsa", { inputs: 1, outputs: 2 });
    const [spend, ...rest] = source.spendProofs;
    if (spend === undefined) throw new Error("expected one spend proof");
    const atModulus = {
      ...spend,
      state: { ...spend.state, root: bytes(oracle.expected.modulusBytes) as Bytes32 },
    };

    expect(() => assemble(source.proofInputs, [atModulus, ...rest])).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_FIELD" }),
    );
    expect(() => assemble(source.proofInputs, source.spendProofs)).not.toThrow();
  });
});
