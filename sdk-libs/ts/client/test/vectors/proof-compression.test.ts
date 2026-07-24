import type { Bytes64 } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import fixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { ClientError } from "../../src/index.js";
import { compressProof, parseProof } from "../../src/prover/proof.js";
import { bytes, hex } from "../helpers/prover-vectors.js";

function gnarkProof(commitment: boolean): Readonly<Record<string, unknown>> {
  const c = fixture.expected.vanilla.uncompressed.cBytes;
  const b = fixture.expected.vanilla.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return {
    ar: g1,
    bs: [
      [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
      [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
    ],
    krs: g1,
    ...(commitment ? { proof_commitment: g1, proof_commitment_pok: g1 } : {}),
  };
}

function expectCode(operation: () => unknown, code: string): void {
  expect(operation).toThrow(expect.objectContaining({ code }));
}

describe("frozen valid and malformed proof vectors", () => {
  for (const [name, expected] of [
    ["vanilla", fixture.expected.vanilla],
    ["bsb22", fixture.expected.bsb22],
  ] as const) {
    it(`converts and compresses the ${name} proof exactly`, () => {
      const proof = parseProof(gnarkProof(name === "bsb22"), name === "bsb22");
      expect(hex(proof.a)).toBe(expected.uncompressed.aBytes);
      expect(hex(proof.b)).toBe(expected.uncompressed.bBytes);
      expect(hex(proof.c)).toBe(expected.uncompressed.cBytes);
      expect(proof.commitment && hex(proof.commitment.commitment)).toBe(
        expected.uncompressed.commitment?.commitmentBytes,
      );
      expect(proof.commitment && hex(proof.commitment.commitmentPok)).toBe(
        expected.uncompressed.commitment?.commitmentPokBytes,
      );

      const compressed = compressProof(proof);
      expect(hex(compressed.a)).toBe(expected.compressed.aBytes);
      expect(hex(compressed.b)).toBe(expected.compressed.bBytes);
      expect(hex(compressed.c)).toBe(expected.compressed.cBytes);
      expect(compressed.commitment && hex(compressed.commitment.commitment)).toBe(
        expected.compressed.commitment?.commitmentBytes,
      );
      expect(compressed.commitment && hex(compressed.commitment.commitmentPok)).toBe(
        expected.compressed.commitment?.commitmentPokBytes,
      );
      expect(compressed.toTransactProof().rail).toBe(expected.rail);
    });
  }

  it("rejects every frozen malformed proof category", () => {
    expectCode(() => parseProof(fixture.inputs.malformedResponse, false), "CLIENT_PROOF_PARSE");
    expectCode(
      () => parseProof(fixture.inputs.partialCommitmentResponse, true),
      "CLIENT_PROOF_PARSE",
    );
    expectCode(() => parseProof(gnarkProof(false), true), "CLIENT_PROOF_RAIL_MISMATCH");
    expectCode(
      () =>
        compressProof({
          a: new Uint8Array(64).fill(0xff) as Bytes64,
          b: bytes(fixture.expected.bsb22.uncompressed.bBytes) as never,
          c: bytes(fixture.expected.bsb22.uncompressed.cBytes) as Bytes64,
        }),
      "CLIENT_PROOF_POINT",
    );
  });

  it("maps proof failures to stable client errors", () => {
    try {
      parseProof(fixture.inputs.malformedResponse, false);
    } catch (error) {
      expect(error).toBeInstanceOf(ClientError);
      expect((error as ClientError).code).toBe("CLIENT_PROOF_PARSE");
      expect(fixture.expected.errors.malformed.code).toBe("ProofParse");
      return;
    }
    throw new Error("expected malformed proof to fail");
  });
});
