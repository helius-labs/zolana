import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { solInput } from "./helpers/utxos.js";
import { bytesToBigInt } from "../src/client/internal.js";
import { assemble, prepareTransfer } from "../src/client/prover/assembly.js";
import { assembleMergeWithProofs, prepareMerge } from "../src/client/prover/merge.js";
import type { NonInclusionProof, SpendProof } from "../src/client/rpc.js";
import type { Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { ShieldedKeypair, randomBlinding } from "../src/keypair/index.js";
import { mergeDummyNullifier } from "../src/keypair/merge/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Merge,
  PreparedMerge,
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  createProofOutput,
  transactOutputBlinding,
} from "../src/transaction/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

function fill(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A field element, so its leading byte stays zero. */
function field(value: number): Bytes32 {
  const bytes = fill(value);
  bytes[0] = 0;
  return bytes;
}

const UTXO_ROOT = field(1);
const NULLIFIER_ROOT = field(2);

function nonInclusionProof(leaf: Bytes32, treeId: number): NonInclusionProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree: treeAddress(treeId) },
    path: Array.from({ length: 40 }, () => field(0)),
    lowElement: field(4),
    lowElementIndex: 3n,
    highElement: field(5),
    highElementIndex: 1n,
    root: NULLIFIER_ROOT,
    rootSeq: 1n,
    rootIndex: 6,
  };
}

function spendProof(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: treeAddress(input.treeId) },
      path: Array.from({ length: 32 }, () => field(0)),
      leafIndex: 0n,
      root: UTXO_ROOT,
      rootSeq: 1n,
      rootIndex: 0,
    },
    nullifier: nonInclusionProof(input.nullifier(), input.treeId),
  };
}

function compactTransfer(
  sender: ShieldedKeypair,
  shape: Readonly<{ inputs: number; outputs: number }>,
): SppProofInputs {
  return ConfidentialTransfer.compact(sender.shieldedAddress(), [solInput(sender, 10n)], PAYER)
    .withShape(shape)
    .sign(sender, new AssetRegistry());
}

describe("compact padding", () => {
  it("pads a transfer with compact slots that stay out of the instruction", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const transfer = ConfidentialTransfer.compact(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      PAYER,
    ).withShape({ inputs: 2, outputs: 4 });
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);
    const prepared = transfer.prepare();
    const signed = transfer.sign(sender, new AssetRegistry());
    const [real, compactInput] = signed.inputUtxos;
    if (!real || !compactInput) expect.unreachable();

    expect(signed.inputUtxos.map((input) => input.isCompact())).toEqual([false, true]);
    // Compact padding names the first tree and publishes 0 in place of the
    // zero-key nullifier the circuit derives for its zero-blinding dummy.
    expect(compactInput.treeId).toBe(real.treeId);
    expect(compactInput.publishedNullifier()).toEqual(new Uint8Array(32));
    expect(compactInput.nullifier()).toEqual(
      ProofInputUtxo.dummy(new Uint8Array(32) as Bytes32, real.treeId).nullifier(),
    );
    expect(signed.dummyNullifiers()).toEqual([compactInput.nullifier()]);
    expect(signed.outputs.map((output) => output.isCompact())).toEqual([false, false, true, true]);
    expect(signed.outputs[2]?.hash(signed.outputTreeId)).toEqual(new Uint8Array(32));
    expect(signed.outputs[2]?.blinding).toEqual(
      transactOutputBlinding(prepared.firstNullifier, prepared.outputBlindingSeed(), 2),
    );
    expect([
      signed.externalData.outputs.length,
      signed.externalData.resolvedOwnerTags.length,
    ]).toEqual([2, 2]);
    expect(signed.checkShape()).toEqual({ inputs: 2, outputs: 4 });

    // The instruction carries only the sent slots; SPP fills the rest back in.
    // The statement publishes 0 for compact padding, and the lookup carries
    // the derived nullifier the prover fetches the non-inclusion proof for.
    const assembly = prepareTransfer(signed);
    expect(assembly.inputs.payload.inputs.map((input) => input.nullifier === 0n)).toEqual([
      false,
      true,
    ]);
    expect(assembly.inputs.lookups.map((lookup) => lookup.nullifier)).toEqual([
      null,
      compactInput.nullifier(),
    ]);
    const treeId = real.treeId;
    const { instructionData } = assembly.finish([
      {
        treeId,
        slot: {
          id: treeId,
          utxoRoot: new Uint8Array(32).fill(1) as Bytes32,
          nullifierRoot: new Uint8Array(32).fill(2) as Bytes32,
        },
        utxoRootIndex: 0,
        nullifierRootIndex: 0,
      },
    ]);
    expect([instructionData.inputs.length, instructionData.outputs.length]).toEqual([1, 2]);
  });

  it("proves non-inclusion of a compact slot's derived nullifier and publishes 0", () => {
    const sender = ShieldedKeypair.generate();
    const signed = compactTransfer(sender, { inputs: 2, outputs: 2 });
    const [real, compactInput] = signed.inputUtxos;
    if (!real || !compactInput) expect.unreachable();
    const proof = nonInclusionProof(compactInput.nullifier(), real.treeId);

    const assembled = assemble(signed, [spendProof(real)], [proof]);
    const witness = assembled.proverInputs.payload.inputs[1];
    if (!witness) expect.unreachable();
    expect({
      isDummy: witness.isDummy,
      treeSlot: witness.treeSlot,
      nullifier: witness.nullifier,
      ownerPublicKeyHash: witness.ownerPublicKeyHash,
      nullifierSecret: witness.nullifierSecret,
      nullifierLowValue: witness.nullifierLowValue,
      nullifierNextValue: witness.nullifierNextValue,
      nullifierLowPathIndex: witness.nullifierLowPathIndex,
    }).toEqual({
      isDummy: 1n,
      treeSlot: 0n,
      nullifier: 0n,
      ownerPublicKeyHash: 0n,
      nullifierSecret: 0n,
      nullifierLowValue: bytesToBigInt(proof.lowElement),
      nullifierNextValue: bytesToBigInt(proof.highElement),
      nullifierLowPathIndex: 3n,
    });
    expect(assembled.nullifiers[1]).toEqual(new Uint8Array(32));
    expect(assembled.instructionData.inputs).toHaveLength(1);
    expect(assembled.instructionData.treeContexts).toEqual([
      { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 6 },
    ]);
  });

  it("refuses a compact slot without a non-inclusion proof or with another leaf's", () => {
    const sender = ShieldedKeypair.generate();
    const signed = compactTransfer(sender, { inputs: 2, outputs: 2 });
    const real = signed.inputUtxos[0];
    if (!real) expect.unreachable();

    expect(() => assemble(signed, [spendProof(real)], [])).toThrow(
      expect.objectContaining({ code: "CLIENT_MISSING_INPUT_MERKLE_PROOF", details: { index: 1 } }),
    );
    expect(() =>
      assemble(signed, [spendProof(real)], [nonInclusionProof(field(9), real.treeId)]),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH",
        details: { index: 1 },
      }),
    );
  });

  it("keeps the compact flag through withTreeId and refuses it on a real input", () => {
    const moved = ProofInputUtxo.compact(0).withTreeId(3);
    expect(moved.isCompact()).toBe(true);
    expect(moved.treeId).toBe(3);
    expect(moved.nullifier()).toEqual(ProofInputUtxo.compact(3).nullifier());
    expect(ProofInputUtxo.dummy(undefined, 3).withTreeId(4).isCompact()).toBe(false);

    const real = solInput(ShieldedKeypair.generate(), 10n);
    expect(
      () =>
        new ProofInputUtxo({
          utxo: real.utxo,
          nullifierPublicKey: real.nullifierPublicKey,
          nullifier: real.nullifier(),
          treeId: real.treeId,
          compact: true,
        }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
        details: { field: "compact" },
      }),
    );
    expect(
      () =>
        new ProofInputUtxo({
          utxo: ProofInputUtxo.compact(0).utxo,
          nullifierPublicKey: new Uint8Array(32) as Bytes32,
          nullifier: new Uint8Array(32) as Bytes32,
          compact: true,
        }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
        details: { field: "nullifier" },
      }),
    );
  });

  it("refuses a slot after compact padding on either side", () => {
    const sender = ShieldedKeypair.generate();
    const signed = compactTransfer(sender, { inputs: 3, outputs: 4 });
    const [real, compactInput] = signed.inputUtxos;
    const [change, compactOutput] = signed.outputs;
    if (!real || !compactInput || !change || !compactOutput) expect.unreachable();
    const rebuilt = (
      slots: Readonly<{ inputUtxos?: readonly ProofInputUtxo[]; outputs?: typeof signed.outputs }>,
    ) =>
      new SppProofInputs({
        payer: signed.payer,
        inputUtxos: slots.inputUtxos ?? signed.inputUtxos,
        outputs: slots.outputs ?? signed.outputs,
        externalData: signed.externalData,
        blindingSeed: signed.blindingSeed,
        outputTreeId: signed.outputTreeId,
      });

    expect(() =>
      rebuilt({ inputUtxos: [real, compactInput, ProofInputUtxo.dummy(undefined, real.treeId)] }),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "input", index: 2 },
      }),
    );
    const randomDummy = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: randomBlinding(),
      ownerTag: new Uint8Array(32).fill(8) as Bytes32,
    });
    expect(() => rebuilt({ outputs: [change, compactOutput, randomDummy, compactOutput] })).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "output", index: 2 },
      }),
    );
  });

  it("refuses a prepared merge whose compact padding SPP would read differently", () => {
    const owner = ShieldedKeypair.generate();
    const inputs = [solInput(owner, 2n), solInput(owner, 3n), solInput(owner, 4n)];
    const prepared = Merge.fromKeypair(owner, inputs).prepare();
    const rebuilt = (padded: readonly ProofInputUtxo[], dummyNullifiers: readonly Bytes32[]) =>
      new PreparedMerge({
        inputs: padded,
        output: prepared.output,
        expiryUnixTs: prepared.expiryUnixTs,
        signingPublicKey: prepared.signingPublicKey,
        nullifierPublicKey: prepared.nullifierPublicKey,
        dummyNullifiers,
        privateTxBlinding: prepared.privateTxBlinding(),
        outputTreeId: prepared.outputTreeId,
      });
    const compact = () => ProofInputUtxo.compact(prepared.inputTreeId);

    // A dummy after compact padding: SPP moves the zero past it.
    const reordered = [
      ...inputs,
      compact(),
      ProofInputUtxo.dummy(undefined, prepared.inputTreeId),
      ...Array.from({ length: prepared.inputs.length - inputs.length - 2 }, compact),
    ];
    expect(() => rebuilt(reordered, prepared.dummyNullifiers())).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_SLOT_AFTER_COMPACT_PADDING",
        details: { side: "input", index: 4 },
      }),
    );
    // Three sent nullifiers select the 8-input circuit, not the 54-input one.
    const tooWide = [...inputs, ...Array.from({ length: 51 }, compact)];
    expect(() => rebuilt(tooWide, prepared.dummyNullifiers())).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_UNSUPPORTED_SHAPE",
        details: { inputs: 54, sent: 3 },
      }),
    );
    // Compact padding still takes one dummy nullifier per padded slot.
    expect(() => rebuilt(prepared.inputs, [])).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_INVALID_LENGTH",
        details: { field: "dummyNullifiers", expected: 5, actual: 0 },
      }),
    );
  });

  it("pads a merge with compact slots that take the dummy nullifiers of padded slots", () => {
    const owner = ShieldedKeypair.generate();
    const inputs = [solInput(owner, 2n), solInput(owner, 3n), solInput(owner, 4n)];
    const prepared = Merge.fromKeypair(owner, inputs).prepare();
    const first = inputs[0];
    if (!first) expect.unreachable();
    const key = owner.nullifierKey();
    const derived = PreparedMerge.dummySlots(inputs.length).map((slot) =>
      mergeDummyNullifier(key, first.nullifier(), slot),
    );
    key.destroy();

    expect(prepared.inputs).toHaveLength(8);
    expect(prepared.inputs.slice(inputs.length).every((input) => input.isCompact())).toBe(true);
    expect(prepared.dummyNullifiers()).toEqual(derived);
    expect(prepared.output.amount).toBe(9n);
  });

  it("proves non-inclusion of each compact merge slot's dummy nullifier and publishes 0", () => {
    const owner = ShieldedKeypair.generate();
    const inputs = [solInput(owner, 2n), solInput(owner, 3n), solInput(owner, 4n)];
    const prepared = Merge.fromKeypair(owner, inputs).prepare();
    const tree = treeAddress(prepared.inputTreeId);
    const dummyNullifiers = prepared.dummyNullifiers();
    const dummyProofs = dummyNullifiers.map((nullifier) =>
      nonInclusionProof(nullifier, prepared.inputTreeId),
    );

    const assembly = assembleMergeWithProofs(prepared, inputs.map(spendProof), tree, dummyProofs);
    expect(assembly.nullifiers.slice(3)).toEqual(dummyNullifiers.map(() => new Uint8Array(32)));
    expect(
      assembly.proverInputs.inputs.slice(3).map((input) => ({
        isDummy: input.isDummy,
        nullifier: input.nullifier,
        nullifierLowPathIndex: input.nullifierLowPathIndex,
      })),
    ).toEqual(
      dummyNullifiers.map(() => ({ isDummy: 1n, nullifier: 0n, nullifierLowPathIndex: 3n })),
    );
    const proof = {
      a: field(1),
      b: new Uint8Array(128) as never,
      c: field(2),
      commitment: field(3),
      commitmentPok: field(4),
    };
    expect(assembly.instructionData(proof).nullifiers).toEqual(
      inputs.map((input) => input.nullifier()),
    );
    expect(() => assembleMergeWithProofs(prepared, inputs.map(spendProof), tree, [])).toThrow(
      expect.objectContaining({
        code: "CLIENT_INCOMPLETE_INPUT_PROOFS",
        details: { expected: 5, state: 0, nullifier: 0 },
      }),
    );

    // The prover-resolved path publishes 0 and carries the dummy nullifier in
    // the lookup for the prover to fetch.
    const local = prepareMerge(prepared, tree);
    expect(local.inputs.payload.inputs.slice(3).map((input) => input.nullifier)).toEqual(
      dummyNullifiers.map(() => 0n),
    );
    expect(local.inputs.lookups.map((lookup) => lookup.nullifier)).toEqual([
      null,
      null,
      null,
      ...dummyNullifiers,
    ]);
  });
});
