import { describe, expect, it } from "vitest";

import { ClientError } from "../src/client/error.js";
import { assembleMergeWithProofs } from "../src/client/prover/merge.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../src/interface/tree-slot.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import { Merge, PreparedMerge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";

function solInput(keypair: ShieldedKeypair, amount: bigint): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: randomBlinding(),
    }),
    keypair,
  );
}

function rejectedWith(run: () => unknown, code: ClientError["code"]): unknown {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    const clientError = error as ClientError;
    expect(clientError.code).toBe(code);
    return clientError.details;
  }
  throw new Error("assembleMergeWithProofs did not reject the tree mismatch");
}

// The merge instruction takes one tree for both spending and appending, so a
// proof over inputs of the submit tree but an output hashed under another tree
// would verify against a public output tree id the instruction cannot supply.
describe("merge tree guards", () => {
  const owner = ShieldedKeypair.generate();
  const submitTree = treeAddress(DEFAULT_TREE_ID);

  it("keeps prepared dummy nullifiers independent of returned buffers", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const expected = prepared.dummyNullifiers().map((value) => new Uint8Array(value));
    for (const value of prepared.dummyNullifiers()) value.fill(255);
    expect(prepared.dummyNullifiers()).toEqual(expected);
  });

  it.each(["signing", "nullifier"] as const)(
    "rejects inconsistent prepared %s ownership",
    (kind) => {
      const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
      const other = ShieldedKeypair.generate();
      try {
        const inconsistent = new PreparedMerge({
          inputs: prepared.inputs,
          output: prepared.output,
          expiryUnixTs: prepared.expiryUnixTs,
          signingPublicKey:
            kind === "signing" ? other.signingPublicKey() : prepared.signingPublicKey,
          nullifierPublicKey:
            kind === "nullifier" ? other.nullifierPublicKey() : prepared.nullifierPublicKey,
          dummyNullifiers: prepared.dummyNullifiers(),
          privateTxBlinding: prepared.privateTxBlinding(),
          outputTreeId: prepared.outputTreeId,
        });
        expect(() => assembleMergeWithProofs(inconsistent, [], submitTree)).toThrow(
          expect.objectContaining({
            code:
              kind === "signing"
                ? "CLIENT_MERGE_SIGNING_KEY_MISMATCH"
                : "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
          }),
        );
      } finally {
        other.destroy();
      }
    },
  );

  it("rejects an output tree that is not the input tree", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n), solInput(owner, 7n)])
      .withOutputTreeId(1)
      .prepare();
    expect(prepared.inputTreeId).toBe(DEFAULT_TREE_ID);
    expect(prepared.outputTreeId).toBe(1);

    const details = rejectedWith(
      () => assembleMergeWithProofs(prepared, [], submitTree),
      "CLIENT_TREE_ID_MISMATCH",
    );
    expect(details).toEqual({ expected: DEFAULT_TREE_ID, actual: 1 });
  });

  it("rejects an input tree that is not the submit tree", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const details = rejectedWith(
      () => assembleMergeWithProofs(prepared, [], treeAddress(1)),
      "CLIENT_MERGE_TREE_MISMATCH",
    );
    expect(details).toEqual({ proofTree: submitTree, submitTree: treeAddress(1) });
  });
});
