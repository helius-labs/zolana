import type { Bytes64, Bytes128 } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/proof-response-parity-v1.json" with { type: "json" };
import { compressProof, parseProof } from "../../src/prover/proof.js";
import { bytes, hex } from "../helpers/prover-vectors.js";

/**
 * P3 residual coverage on top of the two suites already in-tree:
 * `proof-compression.test.ts` (vanilla / BSB22 generator points) and
 * `proof-canonical-oracle.test.ts` (coordinate spellings, rails, half
 * commitments). This file drives the Rust-generated
 * `proof-response-parity-v1.json` through the public parse and compress
 * entry points and compares bytes plus stable error categories.
 */

type ValidCase = Readonly<{
  id: string;
  clause: string;
  unavailable?: boolean;
  requireCommitment?: boolean;
  gnark?: Readonly<Record<string, unknown>>;
  uncompressed?: Readonly<{
    aBytes: string;
    bBytes: string;
    cBytes: string;
    commitment: null | Readonly<{ commitmentBytes: string; commitmentPokBytes: string }>;
  }>;
  compressed?: Readonly<{
    aBytes: string;
    bBytes: string;
    cBytes: string;
    commitment: null | Readonly<{ commitmentBytes: string; commitmentPokBytes: string }>;
  }>;
  rail?: string;
  hasCommitment?: boolean;
  compressedParity?: Readonly<{ a: boolean; b: boolean; c: boolean }>;
}>;

type RejectCase = Readonly<{
  id: string;
  clause: string;
  mutation?: string;
  gnark?: Readonly<Record<string, unknown>>;
  requireCommitment?: boolean;
  accepted?: boolean;
  divergence?: boolean;
  acceptedByRust?: boolean;
  acceptedByTypescript?: boolean;
  stage?: "parse" | "compress";
  typescriptCategory?: string | null;
  uncompressed?: Readonly<{
    aBytes: string;
    bBytes: string;
    cBytes: string;
  }>;
}>;

function expectCode(operation: () => unknown, code: string): void {
  expect(operation).toThrow(expect.objectContaining({ code }));
}

function expectAccept(operation: () => unknown): void {
  expect(operation).not.toThrow();
}

describe("P3 proof-response parity (Rust-generated)", () => {
  it("records the suites that already cover part of P3", () => {
    expect(fixture.existingCoverage.proofCanonicalOracle.test).toContain(
      "proof-canonical-oracle.test.ts",
    );
    expect(fixture.existingCoverage.proofValidity.test).toContain("proof-compression.test.ts");
  });

  for (const testCase of fixture.valid as ValidCase[]) {
    if (testCase.unavailable) {
      it.skip(
        `valid ${testCase.id} (${testCase.clause}) — ${String(
          (testCase as { reason?: string }).reason ?? "unavailable",
        )}`,
        () => {},
      );
      continue;
    }

    it(`parses and compresses ${testCase.id} (${testCase.clause})`, () => {
      const gnark = testCase.gnark;
      const expected = testCase.uncompressed;
      const compressedExpected = testCase.compressed;
      if (!gnark || !expected || !compressedExpected) {
        throw new Error(`valid case ${testCase.id} is missing gnark or expected bytes`);
      }

      const proof = parseProof(gnark, testCase.requireCommitment === true);
      expect(hex(proof.a)).toBe(expected.aBytes);
      expect(hex(proof.b)).toBe(expected.bBytes);
      expect(hex(proof.c)).toBe(expected.cBytes);
      expect(proof.commitment !== undefined).toBe(testCase.hasCommitment);
      if (expected.commitment && proof.commitment) {
        expect(hex(proof.commitment.commitment)).toBe(expected.commitment.commitmentBytes);
        expect(hex(proof.commitment.commitmentPok)).toBe(expected.commitment.commitmentPokBytes);
      }

      const compressed = compressProof(proof);
      expect(hex(compressed.a)).toBe(compressedExpected.aBytes);
      expect(hex(compressed.b)).toBe(compressedExpected.bBytes);
      expect(hex(compressed.c)).toBe(compressedExpected.cBytes);
      if (compressedExpected.commitment && compressed.commitment) {
        expect(hex(compressed.commitment.commitment)).toBe(
          compressedExpected.commitment.commitmentBytes,
        );
        expect(hex(compressed.commitment.commitmentPok)).toBe(
          compressedExpected.commitment.commitmentPokBytes,
        );
      }
      expect(compressed.toTransactProof().rail).toBe(testCase.rail);
      expect((compressed.a[0] ?? 0) & 0x80).toBe(testCase.compressedParity?.a ? 0x80 : 0);
      expect((compressed.b[0] ?? 0) & 0x80).toBe(testCase.compressedParity?.b ? 0x80 : 0);
      expect((compressed.c[0] ?? 0) & 0x80).toBe(testCase.compressedParity?.c ? 0x80 : 0);
    });
  }

  for (const testCase of fixture.rejects as RejectCase[]) {
    if (testCase.divergence) {
      it(`records the off-curve G2 compress divergence (${testCase.id})`, () => {
        const point = testCase.uncompressed;
        const code = testCase.typescriptCategory;
        if (!point || !code) throw new Error(`divergence case ${testCase.id} is incomplete`);
        expect(testCase.acceptedByRust).toBe(true);
        expect(testCase.acceptedByTypescript).toBe(false);
        expectCode(
          () =>
            compressProof({
              a: bytes(point.aBytes) as Bytes64,
              b: bytes(point.bBytes) as Bytes128,
              c: bytes(point.cBytes) as Bytes64,
            }),
          code,
        );
      });
      continue;
    }

    if (testCase.accepted === true) {
      it(`accepts ${testCase.id} on both sides (${testCase.clause})`, () => {
        const gnark = testCase.gnark;
        if (!gnark) throw new Error(`accept case ${testCase.id} lacks gnark`);
        // Unknown fields are ignored today; pinning the shared acceptance is
        // what makes a future one-sided rejector fail this suite.
        expectAccept(() => parseProof(gnark, testCase.requireCommitment === true));
      });
      continue;
    }

    if (testCase.stage === "compress") {
      it(`rejects ${testCase.id} at compress (${testCase.clause})`, () => {
        const point = testCase.uncompressed;
        const code = testCase.typescriptCategory;
        if (!point || !code) throw new Error(`compress reject ${testCase.id} is incomplete`);
        expectCode(
          () =>
            compressProof({
              a: bytes(point.aBytes) as Bytes64,
              b: bytes(point.bBytes) as Bytes128,
              c: bytes(point.cBytes) as Bytes64,
            }),
          code,
        );
      });
      continue;
    }

    it(`rejects ${testCase.id} at parse (${testCase.clause})`, () => {
      const gnark = testCase.gnark;
      const code = testCase.typescriptCategory;
      if (!gnark || !code) throw new Error(`parse reject ${testCase.id} is incomplete`);
      expectCode(() => parseProof(gnark, testCase.requireCommitment === true), code);
    });
  }
});
