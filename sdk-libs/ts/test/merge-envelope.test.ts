import { describe, expect, it } from "vitest";

import { solInput } from "./helpers/utxos.js";
import { assembleMergeWithProofs, prepareMerge } from "../src/client/prover/merge.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../src/interface/tree-slot.js";
import type { Bytes32, Bytes128 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { MergeOutputEnvelope } from "../src/transaction/instructions/builders.js";
import { Merge, PreparedMerge, createProofOutput } from "../src/transaction/index.js";

describe("merge envelope guards", () => {
  const owner = ShieldedKeypair.generate();
  const submitTree = treeAddress(DEFAULT_TREE_ID);

  function rebuilt(
    prepared: PreparedMerge,
    change: Readonly<{ envelope?: MergeOutputEnvelope; blinding?: Bytes32 }>,
  ): PreparedMerge {
    return new PreparedMerge({
      inputs: prepared.inputs,
      output:
        change.blinding === undefined
          ? prepared.output
          : createProofOutput({
              ownerAddress: owner.shieldedAddress(),
              asset: prepared.output.asset,
              amount: prepared.output.amount,
              blinding: change.blinding,
            }),
      envelope: change.envelope,
      expiryUnixTs: prepared.expiryUnixTs,
      signingPublicKey: prepared.signingPublicKey,
      nullifierPublicKey: prepared.nullifierPublicKey,
      dummyNullifiers: prepared.dummyNullifiers(),
      privateTxBlinding: prepared.privateTxBlinding(),
      outputTreeId: prepared.outputTreeId,
    });
  }

  it("seals a default merge to the owner's viewing key and takes the sealed blinding", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const sealed = prepared.sealedEnvelope();
    expect(prepared.envelope?.recipient.equals(owner.viewingPublicKey())).toBe(true);
    expect(sealed?.outputBlinding).toEqual(prepared.output.blinding);
    expect(sealed?.ciphertext).toHaveLength(40);
  });

  it("refuses a default merge without its envelope", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    expect(() => assembleMergeWithProofs(rebuilt(prepared, {}), [], submitTree)).toThrow(
      expect.objectContaining({ code: "CLIENT_MERGE_ENVELOPE_RAIL_MISMATCH" }),
    );
  });

  it("refuses an envelope sealed to a key other than the output owner's", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const other = ShieldedKeypair.generate();
    try {
      const envelope = new MergeOutputEnvelope({ recipient: other.viewingPublicKey() });
      const blinding = envelope.seal(prepared.output.amount, prepared.output.asset).outputBlinding;
      expect(() =>
        assembleMergeWithProofs(rebuilt(prepared, { envelope, blinding }), [], submitTree),
      ).toThrow(expect.objectContaining({ code: "CLIENT_MERGE_OUTPUT_MISMATCH" }));
    } finally {
      other.destroy();
    }
  });

  it("refuses an output blinding the envelope does not derive", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const envelope = new MergeOutputEnvelope({ recipient: owner.viewingPublicKey() });
    expect(() => assembleMergeWithProofs(rebuilt(prepared, { envelope }), [], submitTree)).toThrow(
      expect.objectContaining({ code: "CLIENT_OUTPUT_BLINDING_MISMATCH", details: { index: 0 } }),
    );
  });

  it("requires the proof commitment the envelope carries", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const complete = prepareMerge(prepared, submitTree).finish({
      slot: {
        id: DEFAULT_TREE_ID,
        utxoRoot: new Uint8Array(32) as Bytes32,
        nullifierRoot: new Uint8Array(32) as Bytes32,
      },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    });
    const proof = {
      a: new Uint8Array(32),
      b: new Uint8Array(128) as Bytes128,
      c: new Uint8Array(32),
    };
    expect(() => complete.instructionData(proof)).toThrow(
      expect.objectContaining({
        code: "CLIENT_PROOF_PARSE",
        details: { path: "$.proof.proofCommitment", reason: "missing commitment" },
      }),
    );
    const commitment = new Uint8Array(32).fill(3);
    const commitmentPok = new Uint8Array(32).fill(4);
    const sealed = prepared.sealedEnvelope();
    expect(complete.instructionData({ ...proof, commitment, commitmentPok }).envelope).toEqual({
      commitment,
      commitmentPok,
      ephemeralPk: sealed?.ephemeralPublicKey.toBytes(),
      ciphertext: sealed?.ciphertext,
    });
  });

  it("refuses an output blinding source of the other rail", () => {
    const input = solInput(owner, 5n);
    const common = {
      address: owner.shieldedAddress(),
      inputs: [input],
      privateTxBlinding: new Uint8Array(32) as Bytes32,
      dummyNullifiers: PreparedMerge.dummySlots(1).map(() => new Uint8Array(32) as Bytes32),
    };
    expect(
      () =>
        new Merge({
          ...common,
          blinding: { kind: "derived", outputBlinding: new Uint8Array(32) as Bytes32 },
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_MERGE_BLINDING_RAIL_MISMATCH" }));
  });
});
