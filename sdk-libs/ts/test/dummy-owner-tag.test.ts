import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32, OwnerTag } from "../src/interface/index.js";
import { ShieldedKeypair, poseidon, randomBlinding, sha256Bytes } from "../src/keypair/index.js";
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
import { hashChain4 } from "../src/transaction/internal.js";

// A fee sponsor that owns nothing in the transfer. The tag rule must never let
// a padding slot attribute the transaction to it.
const FOREIGN_PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");

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
    output.isDummy() ? [{ published: signed.externalData.outputs[index]?.ownerTag, output }] : [],
  );
  return tags.map(({ published, output }) => {
    if (published === undefined) throw new Error("dummy output without a published slot");
    expect(published.kind).toBe("inline");
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
  it("names the sender, not a foreign fee payer, on every padding slot", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const senderTag = sender.signingPublicKey().confidentialViewTag();
    // The 1x8 shape appends five padding slots after the three prepared ones.
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      FOREIGN_PAYER,
    ).withShape({ inputs: 1, outputs: 8 });
    transfer.send(recipient.shieldedAddress(), SOL_MINT, 4n);

    const prepared = transfer.prepare();
    const signed = transfer.sign(sender, new AssetRegistry());

    // Padded layout: the SPL change slot below `senderOutputCount` holds no
    // value and is a dummy, the SOL change and the recipient are real.
    expect(prepared.changeLayout).toBe("padded");
    expect(prepared.senderOutputCount).toBe(2);
    expect(prepared.outputs.map((output) => output.isDummy())).toEqual([true, false, false]);
    expect(signed.outputs.map((output) => output.isDummy())).toEqual([
      true,
      false,
      false,
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
    // The zero-value change slot below `senderOutputCount` is published as a
    // pad under the dummy tag rather than as the sender's compact tag.
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

    // Compact: the only real output is the recipient; the declared shape
    // forces one padding slot after it.
    const compact = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      payer,
    )
      .withCompactChange()
      .withShape({ inputs: 1, outputs: 2 });
    compact.send(recipient.shieldedAddress(), SOL_MINT, 10n);
    const preparedCompact = compact.prepare();
    expect(preparedCompact.outputs.map((output) => output.isDummy())).toEqual([false]);
    const signedCompact = compact.sign(sender, new AssetRegistry());
    expect(signedCompact.outputs.map((output) => output.isDummy())).toEqual([false, true]);
    expect(dummyTags(signedCompact)).toEqual([inlineTag(recipientTag)]);
    expect(signedCompact.externalData.outputs[0]?.ownerTag).toEqual(inlineTag(recipientTag));
    expectDerivedBlindings(preparedCompact, signedCompact);

    // Padded: both change slots hold no value and are dummies from `prepare`
    // on; they, too, take the recipient's tag.
    const padded = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      payer,
    );
    padded.send(recipient.shieldedAddress(), SOL_MINT, 10n);
    const preparedPadded = padded.prepare();
    expect(preparedPadded.outputs.map((output) => output.isDummy())).toEqual([true, true, false]);
    const signedPadded = padded.sign(sender, new AssetRegistry());
    // `prepare` tagged both change slots with the sender, who is the payer
    // here; a pad may not name the payer, so the proof-side outputs must be
    // retagged to the recipient exactly like the published slots.
    expect(signedPadded.outputs.slice(0, 2).map((output) => output.ownerTag)).toEqual([
      recipientTag,
      recipientTag,
    ]);
    const tags = dummyTags(signedPadded);
    expect(tags.length).toBeGreaterThanOrEqual(2);
    for (const tag of tags) expect(tag).toEqual(inlineTag(recipientTag));
    expect(tags.some((tag) => tag.kind === "account")).toBe(false);
    expectDerivedBlindings(preparedPadded, signedPadded);
  });

  it("keeps a real zero-amount SOL change output for a self-paid full withdrawal", () => {
    const sender = ShieldedKeypair.generate();
    const senderTag = sender.signingPublicKey().confidentialViewTag();
    const payer = sender.shieldedAddress().solanaAddress();
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [solInput(sender, 10n)],
      payer,
    )
      .withCompactChange()
      .withShape({ inputs: 1, outputs: 2 });
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
    expect(dummyTags(signed)).toEqual([inlineTag(senderTag)]);
    // Sender and payer coincide, so the real change slot publishes Account(0);
    // the pad never does.
    expect(signed.externalData.outputs[0]?.ownerTag).toEqual({ kind: "account", index: 0 });
    expect(signed.externalData.outputs[1]?.ownerTag).toEqual(inlineTag(senderTag));
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
      // The five Poseidon elements the circuit hashes, folded by hand.
      const byHand = poseidon([
        hashChain4(inputHashes),
        hashChain4(outputHashes),
        hashChain4(inputHashes.map(() => zero)),
        externalDataHash,
        blinding,
      ]);
      expect(signed.privateTxHash()).toEqual(byHand);
      expect(
        privateTxHash({
          inputHashes,
          outputHashes,
          addressNullifiers: inputHashes.map(() => zero),
          externalDataHash,
          blinding,
        }),
      ).toEqual(byHand);
      expect(signed.messageHash()).toEqual(sha256Bytes(byHand));
      expectDerivedBlindings(prepared, signed);
    }
  });
});
