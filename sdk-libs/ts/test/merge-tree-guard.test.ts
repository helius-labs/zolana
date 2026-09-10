import { describe, expect, it } from "vitest";

import { ClientError } from "../src/client/error.js";
import { assembleMergeWithProofs } from "../src/client/prover/merge.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../src/interface/tree-slot.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import { Merge, ProofInputUtxo, SOL_MINT, Utxo } from "../src/transaction/index.js";

function solInput(keypair: ShieldedKeypair, amount: bigint): ProofInputUtxo {
  return new ProofInputUtxo({
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: randomBlinding(),
    }),
    nullifierKey: keypair.nullifierKey(),
  });
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
  const material = {
    signingPublicKey: owner.signingPublicKey(),
    nullifierKey: owner.nullifierKey(),
  };
  const submitTree = treeAddress(DEFAULT_TREE_ID);

  it("rejects an output tree that is not the input tree", () => {
    const prepared = new Merge(owner, [solInput(owner, 5n), solInput(owner, 7n)])
      .withOutputTreeId(1)
      .prepare();
    expect(prepared.inputTreeId).toBe(DEFAULT_TREE_ID);
    expect(prepared.outputTreeId).toBe(1);

    const details = rejectedWith(
      () => assembleMergeWithProofs(prepared, material, [], submitTree),
      "CLIENT_TREE_ID_MISMATCH",
    );
    expect(details).toEqual({ expected: DEFAULT_TREE_ID, actual: 1 });
  });

  it("rejects an input tree that is not the submit tree", () => {
    const prepared = new Merge(owner, [solInput(owner, 5n)]).prepare();
    const details = rejectedWith(
      () => assembleMergeWithProofs(prepared, material, [], treeAddress(1)),
      "CLIENT_MERGE_TREE_MISMATCH",
    );
    expect(details).toEqual({ proofTree: submitTree, submitTree: treeAddress(1) });
  });
});
