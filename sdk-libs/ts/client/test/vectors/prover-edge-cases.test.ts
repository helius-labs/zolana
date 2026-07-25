import { transactInstructionDataCodec } from "@zolana/interface/codecs";
import { describe, expect, it } from "vitest";

import oracleJson from "../oracles/prover-edge-cases-v1.json" with { type: "json" };
import { bigintToBytes } from "../../src/internal.js";
import { assemble } from "../../src/prover/index.js";
import {
  PROVER_EDGE_CASES,
  buildEdgeCase,
  hex,
  proverInputsJson,
  type ProverEdgeCaseOracle,
} from "../helpers/prover-vectors.js";

const oracle = oracleJson as ProverEdgeCaseOracle;

/// `fixtures/client/prover-shapes-v1.json` covers twenty shapes, but every one
/// of them puts a single real input in slot 0, pads the tail, and settles in
/// SOL. These four cases are the ones the shape sweep cannot reach: the SPL
/// asset field, a dummy between two real inputs, and two real inputs on
/// different signature schemes. Each expected value comes from running the Rust
/// `assemble` in `sdk-libs/client/tests/ts_prover_oracle.rs`.
describe("Rust-generated prover assembly edge cases", () => {
  it("covers every case the Rust oracle emits", () => {
    expect(PROVER_EDGE_CASES).toHaveLength(oracle.expected.cases.length);
  });

  oracle.expected.cases.forEach((expected, index) => {
    it(`${expected.name} matches the Rust witness, signer slots, and wire bytes`, () => {
      const shape = PROVER_EDGE_CASES[index];
      if (!shape) throw new Error("missing TypeScript counterpart for an oracle case");
      const source = buildEdgeCase(oracle, shape);
      const assembled = assemble(source.proofInputs, source.spendProofs);

      expect(proverInputsJson(assembled.proverInputs)).toEqual(expected.proverInputs);
      expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
      expect(assembled.instructionData.inputs.map((input) => input.eddsaSignerIndex)).toEqual(
        expected.eddsaSignerIndexes,
      );
      expect(assembled.nullifiers.map(hex)).toEqual(expected.nullifierBytes);
      expect(assembled.inputRootIndexes.map((pair) => [...pair])).toEqual(
        expected.rootIndexes.map((pair) => [...pair]),
      );
      expect(hex(transactInstructionDataCodec.encode(assembled.instructionData))).toBe(
        expected.transactIxBytes,
      );
    });
  });

  /// The public SPL asset is the one witness field TypeScript re-derives instead
  /// of reading from `SppProofInputs.publicAmounts()`, which returns only the
  /// two amounts. The Rust oracle above pins the derived value; this pins that
  /// the SOL-only cases leave it at zero, so the re-derivation cannot leak into
  /// a transaction with no public SPL leg.
  it("leaves the SPL asset field at zero when the public leg is SOL", () => {
    oracle.expected.cases.forEach((expected, index) => {
      const shape = PROVER_EDGE_CASES[index];
      if (!shape) throw new Error("missing TypeScript counterpart for an oracle case");
      if (shape.splWithdrawal) return;
      expect(expected.proverInputs["publicSplAssetPubkey"]).toBe("0");
    });
  });
});

/// `bigintToBytes` is the boundary every witness field crosses on its way into
/// the oracle comparison above; a regression there would show up as twenty
/// failures with no obvious cause, so pin the boundary itself.
describe("witness field encoding", () => {
  it("renders a field element as 32 big-endian bytes", () => {
    expect(hex(bigintToBytes(1n))).toBe(`${"00".repeat(31)}01`);
  });
});
