import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/dummy_owner_tags.json" with { type: "json" };
import type { Address, Bytes16, Bytes32, OwnerTag } from "../src/interface/index.js";
import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  poseidon,
  randomBlinding,
  sha256Bytes,
} from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  LocalShieldedKeys,
  ProofInputUtxo,
  SOL_MINT,
  TransactionError,
  Utxo,
  Wallet,
  WithdrawalTarget,
  createProofOutput,
  decryptTransactions,
  encodeConfidentialSlots,
  privateTxBlinding,
  privateTxHash,
  transactOutputBlinding,
  type IndexedShieldedTransaction,
  type PreparedTransfer,
  type SppProofInputs,
} from "../src/transaction/index.js";
import { encodeAddress, nonZeroHashChain } from "../src/transaction/internal.js";
import {
  confidentialPadding,
  isConfidentialPadding,
  readOutputData,
} from "../src/transaction/serialization/codecs.js";
import { concatBytes, equalBytes } from "../src/interface/bytes.js";

// A fee sponsor that owns nothing in the transfer. The tag rule must never let
// a padding slot attribute the transaction to it.
const FOREIGN_PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");

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

function inlineTag(value: Bytes32): OwnerTag {
  return { kind: "inline", value };
}

/**
 * Published owner tags at the positions of `signed`'s dummy outputs. The prover
 * reads a dummy's tag from the output itself and folds it into the owner hash
 * chain the program recomputes from the published tags, so the two must agree
 * on every dummy, the ones `prepare` emitted included.
 */
function dummyTags(signed: SppProofInputs): readonly OwnerTag[] {
  const tags = signed.outputs.flatMap((output, index) =>
    output.isDummy()
      ? [{ published: signed.externalData.outputs[index]?.ownerTag, output, index }]
      : [],
  );
  return tags.map(({ published, output, index }) => {
    if (published === undefined) throw new Error("dummy output without a published slot");
    expect(output.ownerTag).toEqual(signed.externalData.resolvedOwnerTags[index]);
    if (published.kind === "inline") expect(output.ownerTag).toEqual(published.value);
    return published;
  });
}

/**
 * Every output slot, padding included, is blinded by
 * `transactOutputBlinding(firstNullifier, outputBlindingSeed, index)`; the
 * circuit recomputes exactly that, so any other blinding would fail to prove.
 */
function expectDerivedBlindings(prepared: PreparedTransfer, signed: SppProofInputs): void {
  const firstNullifier = signed.firstNullifier();
  expect(firstNullifier).toEqual(prepared.firstNullifier);
  expect(signed.outputBlindingSeed()).toEqual(prepared.outputBlindingSeed());
  expect(signed.outputs.length).toBe(signed.checkShape().outputs);
  signed.outputs.forEach((output, index) => {
    expect(output.blinding).toEqual(
      transactOutputBlinding(firstNullifier, prepared.outputBlindingSeed(), index),
    );
  });
}

function vectorKeypair(seed: number): ShieldedKeypair {
  const bytes = new Uint8Array(32).fill(seed);
  // The 32-byte array has the length `Bytes32` requires.
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes as Bytes32));
}

/**
 * Every slot of `signed`, real or dummy, opens with `frame` and the embedded
 * key's tag; every dummy embeds `participant`'s viewing key, whose tag it
 * carries, and decrypts for it to padding rather than to an output.
 */
function expectFramedPadding(
  signed: SppProofInputs,
  frame: string,
  participant: ShieldedKeypair,
  ringProgramId: Address | undefined,
): void {
  const external = signed.externalData;
  const viewingKey = participant.viewingKey();
  try {
    external.outputs.forEach((published, index) => {
      const data = published.data ?? new Uint8Array();
      expect(Buffer.from(data.subarray(0, frame.length / 2 + 1)).toString("hex")).toBe(
        `${frame}04`,
      );
      if (signed.outputs[index]?.isDummy() !== true) return;
      const { body } = readOutputData(data);
      expect(body.subarray(0, 33)).toEqual(participant.viewingPublicKey().toBytes());
      const plaintext = viewingKey.decryptUtxo(
        body.subarray(33),
        external.txViewingPublicKey,
        external.salt,
        index,
      );
      expect(isConfidentialPadding(plaintext)).toBe(true);
      expect(plaintext).toEqual(confidentialPadding(ringProgramId));
    });
  } finally {
    viewingKey.destroy();
  }
}

/** `signed` as the indexer returns it, every slot under its resolved owner tag. */
function indexed(signed: SppProofInputs): IndexedShieldedTransaction {
  const external = signed.externalData;
  return {
    slot: 1n,
    txSignature: "1".repeat(64) as Signature,
    txViewingPublicKey: external.txViewingPublicKey,
    salt: external.salt,
    outputSlots: external.outputs.map((output, index) => ({
      viewTag: external.resolvedOwnerTags[index] as Bytes32,
      outputContext: { hash: output.utxoHash, tree: TREE, leafIndex: BigInt(index) },
      payload: output.data ?? new Uint8Array(),
    })),
    messages: [],
    nullifiers: signed.inputContexts().map((input) => input.nullifier),
    proofless: false,
  };
}

describe("dummy output owner tags", () => {
  it.each(vectors.cases)("matches real output encoding: $name", (vector) => {
    const keypair = vectorKeypair;
    const sender = keypair(vectors.sender_seed);
    const recipient = keypair(vectors.recipient_seed);
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, BigInt(vectors.input_amount))],
      keypair(vector.payer_seed).shieldedAddress().solanaAddress(),
    ).withShape({ inputs: 1, outputs: vectors.outputs });
    transfer.send(recipient.shieldedAddress(), SOL_MINT, BigInt(vector.send_amount));
    const prepared = transfer.prepare();
    const signed = transfer.sign(sender, new AssetRegistry());
    const resolved = Uint8Array.from(Buffer.from(vector.resolved, "hex"));
    expect(resolved).toHaveLength(32);
    const expected: OwnerTag =
      vector.owner_tag_kind === "account"
        ? { kind: "account", index: 0 }
        : inlineTag(resolved as Bytes32);
    const tags = dummyTags(signed);
    const real = vector.send_amount < vectors.input_amount ? 2 : 1;
    expect(tags).toHaveLength(vectors.outputs - real);
    for (const tag of tags) expect(tag).toEqual(expected);
    const participantIndex = signed.outputs.findIndex(
      (output) =>
        output.ownerAddress !== undefined &&
        Buffer.from(output.ownerAddress.signingPublicKey.confidentialViewTag()).toString("hex") ===
          vector.resolved,
    );
    expect(participantIndex).toBeGreaterThanOrEqual(0);
    expect(signed.externalData.outputs[participantIndex]?.ownerTag).toEqual(expected);
    const participantData = signed.externalData.outputs[participantIndex]?.data;
    signed.outputs.forEach((output, index) => {
      if (!output.isDummy()) return;
      expect(signed.externalData.outputs[index]?.data).toHaveLength(participantData?.length ?? 0);
    });
    const participant = equalBytes(sender.signingPublicKey().confidentialViewTag(), resolved)
      ? sender
      : recipient;
    expectFramedPadding(signed, vectors.frame, participant, undefined);
    expectDerivedBlindings(prepared, signed);
  });

  it("pads every slot to the shared vector ciphertext length, ring transfers included", () => {
    const sender = vectorKeypair(vectors.sender_seed);
    const recipient = vectorKeypair(vectors.recipient_seed);
    const ring = encodeAddress(new Uint8Array(32).fill(vectors.ring_seed));
    for (const [ringProgramId, expected, frame] of [
      [undefined, vectors.slot_len, vectors.frame],
      [ring, vectors.ring_slot_len, vectors.ring_frame],
    ] as const) {
      const transfer = new ConfidentialTransfer(
        sender.shieldedAddress(),
        [solInput(sender, BigInt(vectors.input_amount))],
        FOREIGN_PAYER,
      ).withShape({ inputs: 1, outputs: vectors.outputs });
      if (ringProgramId !== undefined) transfer.withRingProgramId(ringProgramId);
      transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);
      const signed = transfer.sign(sender, new AssetRegistry());
      expect(signed.outputs.filter((output) => output.isDummy())).toHaveLength(vectors.outputs - 2);
      expect(signed.externalData.outputs.map((output) => output.data?.length)).toEqual(
        Array.from({ length: vectors.outputs }, () => expected),
      );
      expectFramedPadding(signed, frame, sender, ringProgramId);
    }
  });

  it("seals padding byte for byte as the shared vector", () => {
    const recipient = vectorKeypair(vectors.recipient_seed).shieldedAddress();
    const ring = encodeAddress(new Uint8Array(32).fill(vectors.ring_seed));
    const tx = ViewingKey.fromBytes(
      new Uint8Array(32).fill(vectors.padding.tx_key_seed) as Bytes32,
    );
    const salt = new Uint8Array(16).fill(vectors.padding.salt_seed) as Bytes16;
    try {
      for (const [ringProgramId, expected] of [
        [undefined, vectors.padding.slot],
        [ring, vectors.padding.ring_slot],
      ] as const) {
        // Compact padding publishes no slot, which puts the dummy at the vector's slot index.
        const outputs = Array.from({ length: vectors.padding.slot_index }, () =>
          createProofOutput({
            asset: SOL_MINT,
            amount: 0n,
            blinding: randomBlinding(),
            compact: true,
          }),
        );
        outputs.push(
          createProofOutput({
            asset: SOL_MINT,
            amount: 0n,
            blinding: randomBlinding(),
            ownerTag: recipient.confidentialViewTag(),
            ...(ringProgramId === undefined ? {} : { ringProgramId }),
          }),
        );
        const slots = encodeConfidentialSlots(outputs, undefined, tx, salt, recipient);
        expect(slots.slice(0, vectors.padding.slot_index)).toEqual(
          Array.from({ length: vectors.padding.slot_index }, () => undefined),
        );
        const slot = slots[vectors.padding.slot_index];
        expect(slot?.viewTag).toEqual(recipient.confidentialViewTag());
        expect(Buffer.from(slot?.data ?? new Uint8Array()).toString("hex")).toBe(expected);
      }
    } finally {
      tx.destroy();
    }
  });

  it("syncs each wallet's own output from a padded transfer and reads no dummy as undecryptable", async () => {
    const sender = vectorKeypair(vectors.sender_seed);
    const recipient = vectorKeypair(vectors.recipient_seed);
    // Sponsored with change pads under the sender's tag; self-paid without
    // change under the recipient's.
    for (const [payer, amount, kept] of [
      [FOREIGN_PAYER, 4n, [6n, 4n]],
      [sender.shieldedAddress().solanaAddress(), 10n, [0n, 10n]],
    ] as const) {
      const transfer = new ConfidentialTransfer(
        sender.shieldedAddress(),
        [solInput(sender, 10n)],
        payer,
      ).withShape({ inputs: 1, outputs: vectors.outputs });
      transfer.send(recipient.shieldedAddress(), SOL_MINT, amount);
      const transaction = indexed(transfer.sign(sender, new AssetRegistry()));
      for (const [index, keypair] of [sender, recipient].entries()) {
        const wallet = new Wallet({ identity: keypair.shieldedAddress() });
        const keys = LocalShieldedKeys.fromKeypair(keypair);
        try {
          const report = await decryptTransactions({ wallet, keys, transactions: [transaction] });
          expect(report).toMatchObject({ undecryptableCandidates: 0, unknownAssetIds: [] });
          expect(wallet.balance(SOL_MINT).amount).toBe(kept[index]);
        } finally {
          keys.destroy();
        }
      }
    }
  });

  it("refuses a slot encoded for someone other than the owner its tag names", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const stranger = ShieldedKeypair.generate();
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      FOREIGN_PAYER,
    );
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);
    const prepared = transfer.prepare();
    const viewingKey = sender.viewingKey();
    const tx = viewingKey.transactionViewingKey(prepared.firstNullifier);
    const salt = new Uint8Array(16).fill(5) as Parameters<PreparedTransfer["finalize"]>[0]["salt"];
    const payload = encodeConfidentialSlots(prepared.outputs, new AssetRegistry(), tx, salt);
    const strangerTag = stranger.signingPublicKey().confidentialViewTag();
    for (const slotIndex of [0, 1]) {
      const forged = payload.map((slot, index) =>
        slot !== undefined && index === slotIndex ? { ...slot, viewTag: strangerTag } : slot,
      );
      let caught: unknown;
      try {
        prepared.finalize({ txViewingPublicKey: tx.publicKey(), salt, payload: forged });
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(TransactionError);
      expect(caught).toMatchObject({
        code: "TRANSACTION_OWNER_TAG_MISMATCH",
        details: { slotIndex },
      });
    }
    tx.destroy();
    viewingKey.destroy();
  });

  it("names the sender, not a foreign fee payer, on every padding slot", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const senderTag = sender.signingPublicKey().confidentialViewTag();
    // The 1x8 shape appends six padding slots after the two prepared ones.
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      FOREIGN_PAYER,
    ).withShape({ inputs: 1, outputs: 8 });
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);

    const prepared = transfer.prepare();
    const signed = transfer.sign(sender, new AssetRegistry());

    expect(prepared.senderOutputCount).toBe(1);
    expect(prepared.outputs.map((output) => output.isDummy())).toEqual([false, false]);
    expect(prepared.outputs.map((output) => output.amount)).toEqual([6n, 4n]);
    expect(signed.outputs.map((output) => output.isDummy())).toEqual([
      false,
      false,
      true,
      true,
      true,
      true,
      true,
      true,
    ]);

    const tags = dummyTags(signed);
    expect(tags).toHaveLength(6);
    for (const tag of tags) expect(tag).toEqual(inlineTag(senderTag));
    expect(tags.some((tag) => tag.kind === "account")).toBe(false);
    expect(signed.externalData.outputs[0]?.ownerTag).toEqual(inlineTag(senderTag));
    // A foreign payer is not the sender, so no slot at all publishes Account(0).
    expect(
      signed.externalData.outputs.every(
        (output) => !(output.ownerTag.kind === "account" && output.ownerTag.index === 0),
      ),
    ).toBe(true);
    expectDerivedBlindings(prepared, signed);
  });

  it("falls back to the recipient's tag when the self-paying sender keeps no change", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const recipientTag = recipient.signingPublicKey().confidentialViewTag();
    const payer = sender.shieldedAddress().solanaAddress();

    // The only real output is the recipient; the declared shape forces one
    // padding slot after it.
    const compact = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      payer,
    ).withShape({ inputs: 1, outputs: 2 });
    compact.send(recipient.shieldedAddress(), SOL_MINT, 10n);
    const preparedCompact = compact.prepare();
    expect(preparedCompact.outputs.map((output) => output.isDummy())).toEqual([false]);
    const signedCompact = compact.sign(sender, new AssetRegistry());
    expect(signedCompact.outputs.map((output) => output.isDummy())).toEqual([false, true]);
    expect(dummyTags(signedCompact)).toEqual([inlineTag(recipientTag)]);
    expect(signedCompact.externalData.outputs[0]?.ownerTag).toEqual(inlineTag(recipientTag));
    expectDerivedBlindings(preparedCompact, signedCompact);
  });

  it("keeps a real zero-amount SOL change output for a self-paid full withdrawal", () => {
    const sender = ShieldedKeypair.generate();
    const senderTag = sender.signingPublicKey().confidentialViewTag();
    const payer = sender.shieldedAddress().solanaAddress();
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      payer,
    ).withShape({ inputs: 1, outputs: 2 });
    transfer.withdraw(SOL_MINT, 10n, WithdrawalTarget.sol({ recipient: payer }));

    // No recipient, no change, payer owns every input: nothing else could
    // name a participant, so the change slot stays real instead of throwing.
    const prepared = transfer.prepare();
    expect(prepared.outputs).toHaveLength(1);
    const change = prepared.outputs[0];
    expect(change?.isDummy()).toBe(false);
    expect(change?.amount).toBe(0n);
    expect(change?.asset).toBe(SOL_MINT);
    expect(change?.ownerAddress?.signingPublicKey.toBytes()).toEqual(
      sender.signingPublicKey().toBytes(),
    );
    expect(prepared.senderOutputCount).toBe(1);

    const signed = transfer.sign(sender, new AssetRegistry());
    expect(signed.outputs.map((output) => output.isDummy())).toEqual([false, true]);
    // The sender's own change names it, so the pad does too.
    expect(dummyTags(signed)).toEqual([{ kind: "account", index: 0 }]);
    // Sender and payer coincide, so the real change slot publishes Account(0);
    // the pad uses the same encoding.
    expect(signed.externalData.outputs[0]?.ownerTag).toEqual({ kind: "account", index: 0 });
    expect(signed.externalData.outputs[1]?.ownerTag).toEqual({ kind: "account", index: 0 });
    expect(signed.externalData.resolvedOwnerTags[1]).toEqual(senderTag);
    expect(signed.externalData.interfaceTransfers).toMatchObject([
      { kind: "sol", isDeposit: false, amount: 10n, userSolAccount: payer },
    ]);
    expectDerivedBlindings(prepared, signed);
  });

  it("binds the message hash to the private tx blinding derived from the random seed", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const input = solInput(sender, 10n);
    const build = (): { prepared: PreparedTransfer; signed: SppProofInputs } => {
      const transfer = new ConfidentialTransfer(sender.shieldedAddress(), [input], FOREIGN_PAYER);
      transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);
      return { prepared: transfer.prepare(), signed: transfer.sign(sender, new AssetRegistry()) };
    };
    const first = build();
    const second = build();

    // Same inputs, same first nullifier, but every transfer draws its own
    // root seed, so the private blindings, output blindings and hashes differ.
    expect(second.signed.firstNullifier()).toEqual(first.signed.firstNullifier());
    expect(second.prepared.blindingSeed).not.toEqual(first.prepared.blindingSeed);
    expect(second.signed.privateTxBlinding()).not.toEqual(first.signed.privateTxBlinding());
    expect(second.signed.outputBlindingSeed()).not.toEqual(first.signed.outputBlindingSeed());
    expect(second.signed.privateTxHash()).not.toEqual(first.signed.privateTxHash());
    expect(second.signed.messageHash()).not.toEqual(first.signed.messageHash());

    for (const { prepared, signed } of [first, second]) {
      const firstNullifier = signed.firstNullifier();
      const blinding = privateTxBlinding(firstNullifier, prepared.blindingSeed);
      expect(signed.privateTxBlinding()).toEqual(blinding);

      const zero = new Uint8Array(32) as Bytes32;
      const inputHashes = signed.inputUtxos.map((utxo) => (utxo.isDummy() ? zero : utxo.hash()));
      const outputHashes = signed.outputs.map((output) =>
        output.isDummy() ? zero : output.hash(signed.outputTreeId),
      );
      const externalDataHash = signed.externalData.hash();
      const byHand = poseidon([
        nonZeroHashChain(inputHashes),
        nonZeroHashChain(outputHashes),
        zero,
        blinding,
      ]);
      expect(signed.privateTxHash()).toEqual(byHand);
      expect(
        privateTxHash({
          inputHashes,
          outputHashes,
          addressNullifiers: inputHashes.map(() => zero),
          blinding,
        }),
      ).toEqual(byHand);
      expect(signed.messageHash()).toEqual(sha256Bytes(concatBytes(byHand, externalDataHash)));
      expectDerivedBlindings(prepared, signed);
    }
  });
});
