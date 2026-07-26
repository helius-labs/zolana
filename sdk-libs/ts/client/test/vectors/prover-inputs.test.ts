import { transactInstructionDataCodec } from "@zolana/interface/codecs";
import { describe, expect, it } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { bigintToBytes } from "../../src/internal.js";
import { assemble } from "../../src/prover/index.js";
import { proverRequest } from "../../src/prover/client.js";
import { compressProof, parseProof } from "../../src/prover/proof.js";
import {
  buildProofInputs,
  hex,
  proverInputsJson,
  type ProverShapesFixture,
} from "../helpers/prover-vectors.js";

const fixture = proverFixtureJson as ProverShapesFixture;

function gnarkProof(commitment: boolean): Readonly<Record<string, unknown>> {
  const c = proofFixture.expected.vanilla.uncompressed.cBytes;
  const b = proofFixture.expected.vanilla.uncompressed.bBytes;
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

describe("frozen prover shape vectors", () => {
  for (const railFixture of fixture.expected.rails) {
    for (const shapeFixture of railFixture.shapes) {
      const inputs = Number(shapeFixture.shape.inputs);
      const outputs = Number(shapeFixture.shape.outputs);
      it(`${railFixture.rail} ${String(inputs)}x${String(outputs)} matches the complete witness and wire bytes`, () => {
        const source = buildProofInputs(fixture, railFixture.rail, { inputs, outputs });
        const assembled = assemble(source.proofInputs, source.spendProofs);

        expect(proverInputsJson(assembled.proverInputs)).toEqual(shapeFixture.proverInputs);
        expect(proverRequest(assembled.proverInputs)).toEqual(shapeFixture.proverJson);
        expect(hex(bigintToBytes(assembled.proverInputs.payload.publicInputHash))).toBe(
          shapeFixture.publicInputHashBytes,
        );
        expect(hex(transactInstructionDataCodec.encode(assembled.instructionData))).toBe(
          shapeFixture.transactIxData.beforeProofBytes,
        );

        const proof = compressProof(
          parseProof(gnarkProof(railFixture.rail === "p256"), railFixture.rail === "p256"),
        ).toTransactProof();
        expect(hex(transactInstructionDataCodec.encode(assembled.withProof(proof)))).toBe(
          shapeFixture.transactIxData.afterProofBytes,
        );
      });
    }
  }
});
