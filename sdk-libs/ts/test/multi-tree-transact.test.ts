import { describe, expect, it } from "vitest";

import { ClientError } from "../src/client/error.js";
import { inputFlags } from "../src/client/internal.js";
import { assemble } from "../src/client/prover/assembly.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import type { Bytes16, Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { INPUT_TREES, ZERO_TREE_SLOT, treeIdField } from "../src/interface/tree-slot.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { TransactionError } from "../src/transaction/error.js";
import { inputTreeIds, singleInputTreeId } from "../src/transaction/instructions/transact.js";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../src/transaction/index.js";

const OWNER_TAG = fill(8);

function fill(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A blinding is a field element, so its leading byte stays zero. */
function blinding(value: number): Bytes32 {
  const bytes = fill(value);
  bytes[0] = 0;
  return bytes;
}

type TreeRoots = Readonly<{
  treeId: number;
  utxoRoot: Bytes32;
  utxoRootIndex: number;
  nullifierRoot: Bytes32;
  nullifierRootIndex: number;
}>;

const TREE_0: TreeRoots = {
  treeId: 0,
  utxoRoot: fill(3),
  utxoRootIndex: 4,
  nullifierRoot: fill(6),
  nullifierRootIndex: 7,
};
const TREE_1: TreeRoots = {
  treeId: 1,
  utxoRoot: fill(13),
  utxoRootIndex: 5,
  nullifierRoot: fill(16),
  nullifierRootIndex: 8,
};

function spendProof(input: ProofInputUtxo, tree: TreeRoots): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: treeAddress(tree.treeId) },
      path: Array.from({ length: 32 }, () => fill(0)),
      leafIndex: 0n,
      root: tree.utxoRoot,
      rootSeq: 1n,
      rootIndex: tree.utxoRootIndex,
    },
    nullifier: {
      ...nonInclusionProof(input.nullifier(), tree),
      leaf: input.nullifier(),
    },
  };
}

function nonInclusionProof(leaf: Bytes32, tree: TreeRoots): NonInclusionProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree: treeAddress(tree.treeId) },
    path: Array.from({ length: 40 }, () => fill(0)),
    lowElement: fill(4),
    lowElementIndex: 0n,
    highElement: fill(5),
    highElementIndex: 1n,
    root: tree.nullifierRoot,
    rootSeq: 1n,
    rootIndex: tree.nullifierRootIndex,
  };
}

/**
 * Two real spends, one per tree, and a padding slot riding the second tree's
 * run: the smallest shape that exercises the grouping rule.
 */
function twoTreeFixture(): Readonly<{
  keypair: ShieldedKeypair;
  proofInputs: SppProofInputs;
  spendProofs: readonly SpendProof[];
  dummyProofs: readonly NonInclusionProof[];
}> {
  const keypair = ShieldedKeypair.generate();
  const spend = (amount: bigint, seedByte: number, treeId: number): ProofInputUtxo =>
    new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: blinding(seedByte),
      }),
      nullifierKey: keypair.nullifierKey(),
      treeId,
    });
  const first = spend(7n, 1, TREE_0.treeId);
  const second = spend(5n, 2, TREE_1.treeId);
  const dummy = ProofInputUtxo.dummy(blinding(10), TREE_1.treeId);
  const seed = blinding(9);
  const outputSeed = outputBlindingSeed(first.nullifier(), seed);
  const slotBlinding = (index: number): Bytes32 =>
    transactOutputBlinding(first.nullifier(), outputSeed, index);
  const outputs = [
    createProofOutput({
      ownerAddress: keypair.shieldedAddress(),
      asset: SOL_MINT,
      amount: 12n,
      blinding: slotBlinding(0),
    }),
    ...[1, 2].map((index) =>
      createProofOutput({
        asset: SOL_MINT,
        amount: 0n,
        blinding: slotBlinding(index),
        ownerTag: OWNER_TAG,
      }),
    ),
  ];
  const proofInputs = new SppProofInputs({
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: [first, second, dummy],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((entry) => ({
        utxoHash: entry.hash(TREE_0.treeId),
        ownerTag: { kind: "inline", value: OWNER_TAG },
      })),
      resolvedOwnerTags: outputs.map(() => OWNER_TAG),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId: TREE_0.treeId,
  });
  return {
    keypair,
    proofInputs,
    spendProofs: [spendProof(first, TREE_0), spendProof(second, TREE_1)],
    dummyProofs: [nonInclusionProof(dummy.nullifier(), TREE_1)],
  };
}

describe("a transact spending from two trees", () => {
  it("gives every input the index of the context it was proved against", () => {
    const fixture = twoTreeFixture();
    const assembled = assemble(fixture.proofInputs, fixture.spendProofs, fixture.dummyProofs);

    expect(assembled.instructionData.inputs.map((input) => input.treeIndex)).toEqual([0, 1, 1]);
    expect(assembled.instructionData.treeContexts).toEqual([
      {
        utxoTreeRootIndex: TREE_0.utxoRootIndex,
        nullifierTreeRootIndex: TREE_0.nullifierRootIndex,
      },
      {
        utxoTreeRootIndex: TREE_1.utxoRootIndex,
        nullifierTreeRootIndex: TREE_1.nullifierRootIndex,
      },
    ]);
  });

  it("publishes one slot per tree and the packed flags the slots agree with", () => {
    const fixture = twoTreeFixture();
    const { payload } = assemble(
      fixture.proofInputs,
      fixture.spendProofs,
      fixture.dummyProofs,
    ).proverInputs;

    expect(payload.inputs.map((input) => input.treeSlot)).toEqual([0n, 1n, 1n]);
    expect(payload.inputFlags).toBe(inputFlags(true, [0, 1, 1]));
    expect(payload.inputFlags).toBe(145n);
    expect(payload.treeSlots).toHaveLength(INPUT_TREES);
    expect(payload.treeSlots.slice(0, 2)).toEqual([
      {
        id: BigInt(`0x${Buffer.from(treeIdField(TREE_0.treeId)).toString("hex")}`),
        utxoRoot: BigInt(`0x${Buffer.from(TREE_0.utxoRoot).toString("hex")}`),
        nullifierRoot: BigInt(`0x${Buffer.from(TREE_0.nullifierRoot).toString("hex")}`),
      },
      {
        id: BigInt(`0x${Buffer.from(treeIdField(TREE_1.treeId)).toString("hex")}`),
        utxoRoot: BigInt(`0x${Buffer.from(TREE_1.utxoRoot).toString("hex")}`),
        nullifierRoot: BigInt(`0x${Buffer.from(TREE_1.nullifierRoot).toString("hex")}`),
      },
    ]);
    expect(payload.treeSlots.slice(2).every((slot) => slot.utxoRoot === 0n)).toBe(true);
    expect(ZERO_TREE_SLOT.utxoRoot.every((byte) => byte === 0)).toBe(true);
  });

  it("binds the first tree's roots, the pair a ring statement reads", () => {
    const fixture = twoTreeFixture();
    const assembled = assemble(fixture.proofInputs, fixture.spendProofs, fixture.dummyProofs);

    expect(assembled.rootIndexes).toEqual({
      utxoTree: TREE_0.utxoRootIndex,
      nullifierTree: TREE_0.nullifierRootIndex,
    });
    expect(assembled.roots.stateRoot).toEqual(TREE_0.utxoRoot);
    expect(assembled.roots.nullifierRoot).toEqual(TREE_0.nullifierRoot);
  });

  it("refuses a spend proof taken from another tree than the input names", () => {
    const fixture = twoTreeFixture();
    const [first, second] = fixture.spendProofs;
    if (first === undefined || second === undefined) expect.unreachable();
    const swapped: SpendProof = {
      state: { ...second.state, merkleContext: first.state.merkleContext },
      nullifier: second.nullifier,
    };

    expect(() => assemble(fixture.proofInputs, [first, swapped], fixture.dummyProofs)).toThrow(
      expect.objectContaining({ code: "CLIENT_PROOF_TREE_MISMATCH" }),
    );
  });

  it("refuses a padding slot that does not ride the run it sits in", () => {
    const fixture = twoTreeFixture();
    const strayRoot = nonInclusionProof(fixture.dummyProofs[0]?.leaf ?? fill(0), TREE_0);

    expect(() => assemble(fixture.proofInputs, fixture.spendProofs, [strayRoot])).toThrow(
      ClientError,
    );
  });
});

describe("input tree grouping", () => {
  const utxos = (treeIds: readonly number[]): readonly ProofInputUtxo[] =>
    treeIds.map((treeId, index) => ProofInputUtxo.dummy(blinding(20 + index), treeId));

  it("lists the trees in the order the inputs first name them", () => {
    expect(inputTreeIds(utxos([0, 0, 1, 1, 2]))).toEqual([0, 1, 2]);
    expect(singleInputTreeId(utxos([3, 3]))).toBe(3);
  });

  it("refuses a run that reopens a tree an earlier run closed", () => {
    expect(() => inputTreeIds(utxos([0, 1, 0]))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INPUTS_NOT_GROUPED_BY_TREE" }),
    );
    expect(() => singleInputTreeId(utxos([0, 1]))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INPUT_TREE_MISMATCH" }),
    );
  });

  it("refuses more trees than a proof publishes slots for", () => {
    const overflowing = Array.from({ length: INPUT_TREES + 1 }, (_, index) => index);
    expect(() => inputTreeIds(utxos(overflowing))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_TOO_MANY_INPUT_TREES" }),
    );
    expect(inputTreeIds(utxos(overflowing.slice(0, INPUT_TREES)))).toHaveLength(INPUT_TREES);
  });

  it("refuses an empty input list", () => {
    expect(() => inputTreeIds([])).toThrow(TransactionError);
  });
});
