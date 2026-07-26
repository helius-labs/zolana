import type { Bytes33 } from "@zolana/interface";
import { P256PublicKey } from "@zolana/keypair";
import { SppProofInputs } from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { p256Coordinates } from "../../src/internal.js";
import { assemble, ProverClient } from "../../src/prover/index.js";
import { buildProofInputs, type ProverShapesFixture } from "../helpers/prover-vectors.js";

const proverFixture = proverFixtureJson as ProverShapesFixture;

function response(): Response {
  const c = proofFixture.expected.bsb22.uncompressed.cBytes;
  const b = proofFixture.expected.bsb22.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return Response.json({
    proof: {
      ar: g1,
      bs: [
        [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
        [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
      ],
      krs: g1,
      proof_commitment: g1,
      proof_commitment_pok: g1,
    },
  });
}

describe("P256 prover rail", () => {
  it("sends the frozen request and retains both commitment points", async () => {
    const rail = proverFixture.expected.rails.find((value) => value.rail === "p256");
    const shape = rail?.shapes[0];
    if (!shape) throw new Error("missing P256 fixture shape");
    const source = buildProofInputs(proverFixture, "p256", { inputs: 1, outputs: 1 });
    const assembled = assemble(source.proofInputs, source.spendProofs);
    const fetch = vi.fn((_request: URL | RequestInfo, init?: RequestInit) => {
      expect(JSON.parse(typeof init?.body === "string" ? init.body : "")).toEqual(shape.proverJson);
      return Promise.resolve(response());
    });

    const proof = await new ProverClient({
      url: "https://prover.example.test",
      fetch,
    }).prove(assembled.proverInputs);

    expect(proof.commitment).toBeDefined();
    expect(proofFixture.expected.bsb22.rail).toBe("p256");
  });

  it("rejects a signature whose key is not the P256 input owner", () => {
    const source = buildProofInputs(proverFixture, "p256", { inputs: 1, outputs: 1 });
    const signature = source.proofInputs.p256Signature();
    if (!signature) throw new Error("missing P256 fixture signature");
    // The negated owner key: same x, other y. The signing-time check compares x
    // only, so only the assembly-time owner check can reject it.
    const negated = signature.publicKey.toBytes();
    negated[0] = negated[0] === 2 ? 3 : 2;
    source.proofInputs.applyP256Signature({
      publicKey: P256PublicKey.fromBytes(negated),
      r: signature.r,
      s: signature.s,
    });

    expect(() => assemble(source.proofInputs, source.spendProofs)).toThrow(
      expect.objectContaining({
        code: "CLIENT_P256_SIGNATURE",
        details: { reason: "signature key is not the P256 input owner" },
      }),
    );
  });

  it("rejects an x that is off the P256 curve instead of recovering a y", () => {
    const source = buildProofInputs(proverFixture, "p256", { inputs: 1, outputs: 1 });
    const owner = source.proofInputs.inputUtxos[0]?.utxo.owner.p256();
    if (!owner) throw new Error("missing P256 fixture owner");
    const offCurve = new Uint8Array(33) as Bytes33;
    offCurve[0] = 2;
    offCurve[32] = 1;

    expect(p256Coordinates(owner.toBytes())[1]).not.toBe(0n);
    expect(() => p256Coordinates(offCurve)).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_P256_KEY" }),
    );
  });

  it("assembles the corrected mixed P256 and EdDSA input rail", () => {
    const p256 = buildProofInputs(proverFixture, "p256", { inputs: 2, outputs: 2 });
    const eddsa = buildProofInputs(proverFixture, "eddsa", { inputs: 1, outputs: 1 });
    const p256Input = p256.proofInputs.inputUtxos[0];
    const eddsaInput = eddsa.proofInputs.inputUtxos[0];
    const p256Proof = p256.spendProofs[0];
    const eddsaProof = eddsa.spendProofs[0];
    const signature = p256.proofInputs.p256Signature();
    if (!p256Input || !eddsaInput || !p256Proof || !eddsaProof || !signature) {
      throw new Error("missing mixed fixture input");
    }
    const mixed = new SppProofInputs({
      payerPublicKeyHash: p256.proofInputs.payerPublicKeyHash,
      inputUtxos: [p256Input, eddsaInput],
      outputs: p256.proofInputs.outputs,
      externalData: p256.proofInputs.externalData,
    });
    mixed.applyP256Signature(signature);
    const proofs = [
      p256Proof,
      {
        state: {
          ...eddsaProof.state,
          leaf: eddsaInput.hash(),
          leafIndex: 1n,
        },
        nullifier: {
          ...eddsaProof.nullifier,
          leaf: eddsaInput.nullifier(),
        },
      },
    ];

    const assembled = assemble(mixed, proofs);
    expect(assembled.proverInputs.circuit).toBe("transferP256");
    expect(assembled.instructionData.inputs.map((input) => input.eddsaSignerIndex)).toEqual([
      255, 0,
    ]);
  });
});
