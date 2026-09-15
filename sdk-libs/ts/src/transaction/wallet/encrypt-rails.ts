import type { Bytes16, Bytes32, MessageData } from "../../interface/types.js";
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
  encryptSplit as encryptSplitSlot,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
  type SplitBundlePlaintext,
} from "../serialization/codecs.js";
import type { ProofOutputUtxo } from "../utxo.js";
import type { AssetRegistry } from "../asset.js";

export type { SplitBundlePlaintext };

/**
 * Per-transaction encryption envelope: the ephemeral transaction viewing key
 * and salt every ciphertext in the transaction shares (published in the
 * clear), plus the sealed payload the operation produced.
 */
export interface EncryptedEnvelope<P> {
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly payload: P;
}

/**
 * Transfer payload: one ciphertext per output slot, keyed to that output's
 * owner. `undefined` marks a dummy slot the transfer builder pads with a
 * length-matched random ciphertext.
 */
export type EncryptedTransfer = EncryptedEnvelope<readonly (MessageData | undefined)[]>;

/**
 * Split payload: the single sealed slot-0 bundle covering every real output.
 * Unlike a transfer there is exactly one ciphertext; all other slots stay empty
 * on the wire.
 */
export type EncryptedSplit = EncryptedEnvelope<MessageData>;

/** `txViewingSecret` is what the auditor key opens. It exists for the ring's own prover and is wiped after it. */
export interface AuditWitness {
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
}

export interface EncryptedCustomRingTransfer extends EncryptedTransfer {
  readonly auditorMessage: MessageData;
  readonly audit: AuditWitness;
}

export interface AnonymousRecipientSlot {
  readonly viewTag: Bytes32;
  readonly recipientPublicKey: P256PublicKey;
  readonly plaintext: AnonymousRecipientPlaintext;
}

/**
 * Every sealing step of a transaction, over the per-transaction key
 * `ShieldedKeys.transactionKeys` returns for its first nullifier. The key is
 * the caller's to destroy once the proof inputs are finalized.
 */
export function encryptConfidentialTransfer(
  tx: ViewingKey,
  input: Readonly<{ outputs: readonly ProofOutputUtxo[]; assets: AssetRegistry }>,
): EncryptedTransfer {
  const salt = randomSalt();
  return {
    txViewingPublicKey: tx.publicKey(),
    salt,
    payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
  };
}

/** The caller wipes the returned audit secrets after proving. */
export function encryptCustomRingTransfer(
  tx: ViewingKey,
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
    auditorPublicKey: P256PublicKey;
  }>,
): EncryptedCustomRingTransfer {
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
    txViewingSecret?.fill(0);
    ephemeralSecret?.fill(0);
  }
}

/**
 * Slot 0 carries the sender bundle encrypted to the wallet's own viewing
 * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
 * indices are bound into each ciphertext, so they must match the layout the
 * transfer instruction publishes.
 */
export function encryptAnonymousTransfer(
  tx: ViewingKey,
  input: Readonly<{
    /** The wallet's own viewing public key, which opens the sender bundle. */
    viewingPublicKey: P256PublicKey;
    senderViewTag: Bytes32;
    sender: AnonymousSenderPlaintext;
    recipients: readonly AnonymousRecipientSlot[];
  }>,
): EncryptedTransfer {
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
        input.viewingPublicKey,
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
}

export function encryptSplit(
  tx: ViewingKey,
  input: Readonly<{
    /** The wallet's own viewing public key, which opens the bundle. */
    viewingPublicKey: P256PublicKey;
    viewTag: Bytes32;
    bundle: SplitBundlePlaintext;
  }>,
): EncryptedSplit {
  const salt = randomSalt();
  return {
    txViewingPublicKey: tx.publicKey(),
    salt,
    payload: {
      viewTag: input.viewTag,
      data: encodeOutputData(
        EncryptedScheme.split,
        encryptSplitSlot(tx, input.viewingPublicKey, encodeSplitBundle(input.bundle), salt, 0),
        "encrypted",
      ),
    },
  };
}
