import type { Bytes31 } from "@zolana/interface";
import { SppProofInputUtxo } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import fixture from "../../../fixtures/api/prover-request-v1.json" with { type: "json" };
import { bytesField } from "../../src/internal.js";
import { circuitUtxo, createDummyTransferInput } from "../../src/prover/assembly.js";
import { proverRequest } from "../../src/prover/client.js";
import type { Field, ProverInputs, TransferInput } from "../../src/prover/index.js";
import { bytes } from "../helpers/prover-vectors.js";

function field(value: bigint): Field {
  return value as Field;
}

describe("frozen prover request JSON", () => {
  it("serializes every field of the deterministic dummy witness", () => {
    const dummy = SppProofInputUtxo.dummy(bytes(fixture.inputs.dummyBlinding) as Bytes31);
    const input: TransferInput = createDummyTransferInput(
      dummy,
      BigInt(fixture.expected.request.inputs[0]?.utxoTreeRoot ?? "0"),
      BigInt(fixture.expected.request.inputs[0]?.nullifierTreeRoot ?? "0"),
      BigInt(fixture.expected.request.inputs[0]?.ownerPkHash ?? "0"),
    );
    expect(circuitUtxo(input)).toEqual(
      expect.objectContaining({
        blinding: bytesField(dummy.utxo.blinding, "dummy blinding"),
        amount: 0n,
      }),
    );
    const one = field(1n);
    const proverInputs: ProverInputs = {
      circuit: "transfer",
      payload: {
        inputs: [input],
        outputs: [],
        externalDataHash: one,
        privateTxHash: one,
        publicInputHash: one,
        publicSolAmount: one,
        publicSplAmount: one,
        publicSplAssetPublicKey: one,
        zoneProgramId: one,
        payerPublicKeyHash: one,
      },
    };

    expect(proverRequest(proverInputs)).toEqual(fixture.expected.request);
  });
});
