import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/dummy_owner_tags.json" with { type: "json" };
import type { Bytes32, OwnerTag } from "../src/interface/index.js";
import {
  ShieldedKeypair,
  SigningKey,
  poseidon,
  randomBlinding,
  sha256Bytes,
} from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  WithdrawalTarget,
  privateTxBlinding,
  privateTxHash,
  transactOutputBlinding,
  type PreparedTransfer,
  type SppProofInputs,
} from "../src/transaction/index.js";
import { concat, nonZeroHashChain } from "../src/transaction/internal.js";

// A fee sponsor that owns nothing in the transfer. The tag rule must never let
// a padding slot attribute the transaction to it.
const FOREIGN_PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

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

describe("dummy output owner tags", () => {
  it.each(vectors.cases)("matches real output encoding: $name", (vector) => {
    const keypair = (seed: number): ShieldedKeypair => {
      const bytes = new Uint8Array(32).fill(seed);
      // The fixed-size seed satisfies the signing key's byte-length invariant.
      return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes as Bytes32));
    };
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
    expectDerivedBlindings(prepared, signed);
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
      expect(signed.messageHash()).toEqual(sha256Bytes(concat(byHand, externalDataHash)));
      expectDerivedBlindings(prepared, signed);
    }
  });
});
