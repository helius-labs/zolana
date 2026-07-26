import type { Address, Bytes32, Signature } from "@zolana/interface";
import { ShieldedKeypair, randomBlinding } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  LocalWalletAuthority,
  SOL_ASSET_ID,
  SOL_MINT,
  Utxo,
  Wallet,
  syncWalletWithAuthority,
  deriveBlinding,
  type EncryptedTransfer,
} from "../src/index.js";
import type { IndexedShieldedTransaction } from "../src/instructions/transact.js";
import { createProofOutput } from "../src/utxo.js";

const OWNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const TREE = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const SIGNATURE = "1".repeat(64) as Signature;
const bytes32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

function wallet(keypair: ShieldedKeypair): Wallet {
  return new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() });
}

/** One transaction carrying the envelope's slots in the order it produced them. */
function transaction(
  envelope: EncryptedTransfer,
  hashes: readonly Bytes32[],
): IndexedShieldedTransaction {
  return {
    slot: 1n,
    txSignature: SIGNATURE,
    txViewingPublicKey: envelope.txViewingPublicKey,
    salt: envelope.salt,
    outputSlots: envelope.payload.flatMap((message, index) =>
      message === undefined
        ? []
        : [
            {
              viewTag: message.viewTag,
              outputContext: {
                hash: hashes[index] ?? bytes32(index),
                tree: TREE,
                leafIndex: BigInt(index),
              },
              payload: message.data,
            },
          ],
    ),
    messages: [],
    nullifiers: [bytes32(1)],
    proofless: false,
  };
}

describe("viewing-key history", () => {
  it("seeds the identity viewing key at the start of every tag family", () => {
    const keypair = ShieldedKeypair.generate();
    const history = wallet(keypair).viewingKeyHistory;

    expect(history).toHaveLength(1);
    expect(hex(history[0]?.viewingPublicKey.toBytes() ?? new Uint8Array())).toBe(
      hex(keypair.viewingKey().publicKey().toBytes()),
    );
    expect(history[0]).toMatchObject({
      txCount: 0n,
      requestCount: 0n,
      knownSenders: [],
      knownRecipients: [],
    });
  });

  it("advances the sender counter and records the recipient of its own bundle", async () => {
    const keypair = ShieldedKeypair.generate();
    const counterparty = ShieldedKeypair.generate();
    const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });
    const recipientViewingPublicKey = counterparty.viewingKey().publicKey();
    const envelope = await authority.encryptAnonymousTransfer({
      firstNullifier: bytes32(1),
      senderViewTag: keypair.viewingKey().senderViewTag(0n),
      sender: {
        ownerPublicKey: keypair.signingPublicKey(),
        splAssetId: SOL_ASSET_ID,
        splAmount: 0n,
        solAmount: 5n,
        blindingSeed: randomBlinding(),
        recipientViewingPublicKeys: [recipientViewingPublicKey],
        splData: new Data(),
        solData: new Data(),
      },
      recipients: [
        {
          viewTag: bytes32(9),
          recipientPublicKey: recipientViewingPublicKey,
          plaintext: {
            ownerPublicKey: counterparty.signingPublicKey(),
            senderPublicKey: keypair.viewingKey().publicKey(),
            assetId: SOL_ASSET_ID,
            amount: 5n,
            blinding: randomBlinding(),
            data: new Data(),
          },
        },
      ],
    });
    const target = wallet(keypair);

    await syncWalletWithAuthority({
      wallet: target,
      authority,
      transactions: [transaction(envelope, [])],
    });

    const entry = target.viewingKeyHistory[0];
    expect(entry?.txCount).toBe(1n);
    expect(entry?.knownRecipients.map((counter) => hex(counter.counterparty.toBytes()))).toEqual([
      hex(recipientViewingPublicKey.toBytes()),
    ]);
    expect(entry?.knownRecipients.map((counter) => counter.count)).toEqual([0n]);
  });

  // `scan_stream` extends a window as long as the step it just walked hit a
  // tag, so a counterparty that ran ahead of the stored counter is still
  // reachable. Tags at 1 and 3 with a window of 2 need two extensions; only a
  // scan that stops at the first miss settles on 4.
  it("keeps extending the window while each step still hits a tag", async () => {
    const keypair = ShieldedKeypair.generate();
    const counterparty = ShieldedKeypair.generate();
    const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });
    const bundle = async (tagIndex: bigint) =>
      transaction(
        await authority.encryptAnonymousTransfer({
          firstNullifier: bytes32(1),
          senderViewTag: keypair.viewingKey().senderViewTag(tagIndex),
          sender: {
            ownerPublicKey: keypair.signingPublicKey(),
            splAssetId: SOL_ASSET_ID,
            splAmount: 0n,
            solAmount: 5n,
            blindingSeed: randomBlinding(),
            recipientViewingPublicKeys: [counterparty.viewingKey().publicKey()],
            splData: new Data(),
            solData: new Data(),
          },
          recipients: [],
        }),
        [],
      );
    const target = wallet(keypair);

    await syncWalletWithAuthority({
      wallet: target,
      authority,
      transactions: [await bundle(1n), await bundle(3n)],
      config: { tagWindow: 2n },
    });

    expect(target.viewingKeyHistory[0]?.txCount).toBe(4n);
  });

  it("advances the request counter and records the sender of a stored note", async () => {
    const keypair = ShieldedKeypair.generate();
    const sender = ShieldedKeypair.generate();
    const blinding = randomBlinding();
    const note = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding,
      data: new Data(),
    });
    const envelope = await new LocalWalletAuthority({
      solanaPublicKey: OWNER,
      keypair: sender,
    }).encryptAnonymousTransfer({
      firstNullifier: bytes32(1),
      senderViewTag: bytes32(3),
      sender: {
        ownerPublicKey: sender.signingPublicKey(),
        splAssetId: SOL_ASSET_ID,
        splAmount: 0n,
        solAmount: 1n,
        blindingSeed: randomBlinding(),
        recipientViewingPublicKeys: [keypair.viewingKey().publicKey()],
        splData: new Data(),
        solData: new Data(),
      },
      recipients: [
        {
          viewTag: keypair.viewingKey().recipientRequestViewTag(0n),
          recipientPublicKey: keypair.viewingKey().publicKey(),
          plaintext: {
            ownerPublicKey: keypair.signingPublicKey(),
            senderPublicKey: sender.viewingKey().publicKey(),
            assetId: SOL_ASSET_ID,
            amount: 7n,
            blinding,
            data: new Data(),
          },
        },
      ],
    });
    const target = wallet(keypair);

    const report = await syncWalletWithAuthority({
      wallet: target,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      transactions: [
        transaction(envelope, [bytes32(0), note.hash(keypair.nullifierKey().publicKey())]),
      ],
    });

    expect(report.storedUtxos).toBe(1);
    const entry = target.viewingKeyHistory[0];
    expect(entry?.requestCount).toBe(1n);
    expect(entry?.knownSenders.map((counter) => hex(counter.counterparty.toBytes()))).toEqual([
      hex(sender.viewingKey().publicKey().toBytes()),
    ]);
  });

  it("records the recipient of a confidential transfer it sent", async () => {
    const keypair = ShieldedKeypair.generate();
    const counterparty = ShieldedKeypair.generate();
    const registry = new AssetRegistry();
    const change = (amount: bigint, index: number) =>
      createProofOutput({
        ownerAddress: keypair.shieldedAddress(),
        asset: SOL_MINT,
        amount,
        blinding: deriveBlinding(randomBlinding(), index),
      });
    const envelope = await new LocalWalletAuthority({
      solanaPublicKey: OWNER,
      keypair,
    }).encryptConfidentialTransfer({
      firstNullifier: bytes32(1),
      outputs: [
        change(0n, 0),
        change(3n, 1),
        createProofOutput({
          ownerAddress: counterparty.shieldedAddress(),
          asset: SOL_MINT,
          amount: 4n,
          blinding: deriveBlinding(randomBlinding(), 2),
        }),
      ],
      assets: registry,
    });
    const target = wallet(keypair);

    await syncWalletWithAuthority({
      wallet: target,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      transactions: [transaction(envelope, [])],
    });

    // The recipient slot is sealed to the recipient; the sender reads its
    // counterparty back out of the viewing key prefixed to the ciphertext.
    expect(
      target.viewingKeyHistory[0]?.knownRecipients.map((counter) =>
        hex(counter.counterparty.toBytes()),
      ),
    ).toEqual([hex(counterparty.shieldedAddress().viewingPublicKey.toBytes())]);
  });
});
