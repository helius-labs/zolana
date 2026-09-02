import type { Bytes32, MessageData } from "../../interface/types.js";
import { auditorMessageData, encryptTransactionViewingSecret } from "../../keypair/audit.js";
import { randomSalt } from "../../keypair/bytes.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { encodeConfidentialSlots } from "../instructions/transact.js";
import {
  EncryptedScheme,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeOutputData,
  encodeSplitBundle,
  encryptAnonymous,
  encryptSplit,
  type AnonymousSenderPlaintext,
  type SplitBundlePlaintext,
} from "../serialization/codecs.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "../asset.js";
import type {
  AnonymousRecipientSlot,
  EncryptedCustomRingTransfer,
  EncryptedSplit,
  EncryptedTransfer,
  SpendSession,
  SyncWalletAuthority,
  WalletSyncMaterial,
} from "./authority.js";

/** @internal Owns both keys, wipes them when `run` settles. */
export async function runSpendSession<T>(
  viewingKey: ViewingKey,
  nullifierKey: NullifierKey,
  run: (session: SpendSession) => Promise<T>,
): Promise<T> {
  try {
    return await run({
      nullifierKey: () => nullifierKey,
      encryptConfidentialTransfer: (input) =>
        Promise.resolve(encryptConfidentialTransferWith(viewingKey, input)),
      encryptCustomRingTransfer: (input) =>
        Promise.resolve(encryptCustomRingTransferWith(viewingKey, input)),
      encryptAnonymousTransfer: (input) =>
        Promise.resolve(encryptAnonymousTransferWith(viewingKey, input)),
      encryptSplit: (input) => Promise.resolve(encryptSplitWith(viewingKey, input)),
    });
  } finally {
    viewingKey.destroy();
    nullifierKey.destroy();
  }
}

/** @internal Owns the material, wipes its keys when `run` settles. */
export async function runSyncSession<T>(
  material: WalletSyncMaterial,
  run: (session: SyncWalletAuthority) => Promise<T>,
): Promise<T> {
  try {
    return await run({ syncMaterial: () => Promise.resolve(material) });
  } finally {
    for (const key of material.viewingKeys) key.destroy();
    material.nullifierKey.destroy();
  }
}

/** @internal */
export function encryptConfidentialTransferWith(
  viewingKey: ViewingKey,
  input: Readonly<{
    firstNullifier: Bytes32;
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
  }>,
): EncryptedTransfer {
  const tx = viewingKey.transactionViewingKey(input.firstNullifier);
  try {
    const salt = randomSalt();
    return {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
    };
  } finally {
    tx.destroy();
  }
}

/** @internal The caller wipes the returned audit secrets after proving. */
export function encryptCustomRingTransferWith(
  viewingKey: ViewingKey,
  input: Readonly<{
    firstNullifier: Bytes32;
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
    auditorPublicKey: P256PublicKey;
  }>,
): EncryptedCustomRingTransfer {
  const tx = viewingKey.transactionViewingKey(input.firstNullifier);
  let txViewingSecret: Bytes32 | undefined;
  let ephemeralSecret: Bytes32 | undefined;
  try {
    const salt = randomSalt();
    txViewingSecret = tx.secretBytes();
    const encryption = encryptTransactionViewingSecret(txViewingSecret, input.auditorPublicKey);
    ephemeralSecret = encryption.ephemeralSecret;
    const encrypted = {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
      auditorMessage: auditorMessageData(encryption.message, input.auditorPublicKey),
      audit: Object.freeze({ txViewingSecret, ephemeralSecret }),
    };
    // The finally must not wipe the secrets the returned object owns.
    txViewingSecret = undefined;
    ephemeralSecret = undefined;
    return encrypted;
  } finally {
    tx.destroy();
    txViewingSecret?.fill(0);
    ephemeralSecret?.fill(0);
  }
}

/**
 * Slot 0 carries the sender bundle encrypted to the wallet's own viewing
 * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
 * indices are bound into each ciphertext, so they must match the layout the
 * transfer instruction publishes.
 * @internal
 */
export function encryptAnonymousTransferWith(
  viewingKey: ViewingKey,
  input: Readonly<{
    firstNullifier: Bytes32;
    senderViewTag: Bytes32;
    sender: AnonymousSenderPlaintext;
    recipients: readonly AnonymousRecipientSlot[];
  }>,
): EncryptedTransfer {
  const tx = viewingKey.transactionViewingKey(input.firstNullifier);
  try {
    const salt = randomSalt();
    const slot = (
      scheme: EncryptedScheme,
      recipient: P256PublicKey,
      plaintext: Uint8Array,
      slotIndex: number,
      viewTag: Bytes32,
    ): MessageData => ({
      viewTag,
      data: encodeOutputData(
        scheme,
        encryptAnonymous(tx, recipient, plaintext, salt, slotIndex),
        "encrypted",
      ),
    });
    return {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: [
        slot(
          EncryptedScheme.anonymousSender,
          viewingKey.publicKey(),
          encodeAnonymousSender(input.sender),
          0,
          input.senderViewTag,
        ),
        ...input.recipients.map((recipient, index) =>
          slot(
            EncryptedScheme.anonymousRecipient,
            recipient.recipientPublicKey,
            encodeAnonymousRecipient(recipient.plaintext),
            index + 1,
            recipient.viewTag,
          ),
        ),
      ],
    };
  } finally {
    tx.destroy();
  }
}

/** @internal */
export function encryptSplitWith(
  viewingKey: ViewingKey,
  input: Readonly<{
    firstNullifier: Bytes32;
    viewTag: Bytes32;
    bundle: SplitBundlePlaintext;
  }>,
): EncryptedSplit {
  const tx = viewingKey.transactionViewingKey(input.firstNullifier);
  try {
    const salt = randomSalt();
    return {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: {
        viewTag: input.viewTag,
        data: encodeOutputData(
          EncryptedScheme.split,
          encryptSplit(tx, viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0),
          "encrypted",
        ),
      },
    };
  } finally {
    tx.destroy();
  }
}
