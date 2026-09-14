import type { Bytes16, Bytes32, Bytes33, MessageData } from "../../interface/types.js";
import { TransactionError } from "../error.js";
import { auditorMessageData, encryptTransactionViewingSecret } from "../../keypair/audit.js";
import { randomSalt } from "../../keypair/bytes.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { P256_PUBLIC_KEY_LENGTH } from "../../keypair/constants.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";
import { ShieldedAddress } from "../../keypair/shielded.js";

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
import { createProofOutput, type ProofOutputUtxo } from "../utxo.js";
import { SOL_MINT, type AssetRegistry } from "../asset.js";
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
      openSealedMessage: (input) => Promise.resolve(openSealedMessageWith(viewingKey, input)),
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
    recordOutputIndex?: number;
    sealedMessages?: readonly Readonly<{
      viewTag: Bytes32;
      plaintext: Uint8Array;
      slotIndex: number;
    }>[];
    /** Protocol counter seal, never a caller message channel. */
    counterMessage?: Readonly<{
      viewTag: Bytes32;
      plaintext: Uint8Array;
      slotIndex: number;
    }>;
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
    const recipient = tx.publicKey();
    const outputs = recordCarrierOutputs(input.outputs, input.recordOutputIndex, recipient);
    const outbound = [
      ...(input.sealedMessages ?? []),
      ...(input.counterMessage === undefined ? [] : [input.counterMessage]),
    ];
    checkDistinctSlots(input.outputs.length, outbound);
    const sealedMessages: readonly MessageData[] = outbound.map((message) => {
      const ciphertext = tx.encryptSlot(recipient, message.plaintext, salt, message.slotIndex);
      const body = new Uint8Array(P256_PUBLIC_KEY_LENGTH + ciphertext.length);
      body.set(recipient.toBytes(), 0);
      body.set(ciphertext, P256_PUBLIC_KEY_LENGTH);
      return { viewTag: message.viewTag, data: body };
    });
    const encrypted = {
      txViewingPublicKey: tx.publicKey(),
      salt,
      payload: encodeConfidentialSlots(outputs, input.assets, tx, salt),
      auditorMessage: auditorMessageData(encryption.message, input.auditorPublicKey),
      sealedMessages,
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

/** The recipient viewing key does not affect the UTXO commitment. */
function recordCarrierOutputs(
  outputs: readonly ProofOutputUtxo[],
  index: number | undefined,
  recipient: P256PublicKey,
): readonly ProofOutputUtxo[] {
  if (index === undefined) return outputs;
  const output = outputs[index];
  const owner = output?.ownerAddress;
  if (
    !Number.isInteger(index) ||
    index < 0 ||
    index !== outputs.length - 1 ||
    output === undefined ||
    owner === undefined
  ) {
    throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", {
      index,
    });
  }
  if (
    owner.signingPublicKey.signatureType() !== "pda" ||
    output.asset !== SOL_MINT ||
    output.amount !== 0n ||
    output.ringProgramId !== undefined ||
    output.dataHash === undefined ||
    output.data.records().length !== 0
  )
    throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH");
  return outputs.map((candidate, position) =>
    position !== index
      ? candidate
      : createProofOutput({
          ...output,
          ownerAddress: ShieldedAddress.fromPublicKeys(
            owner.signingPublicKey,
            owner.nullifierPublicKey,
            recipient,
          ),
        }),
  );
}

/** One keystream per slot under a fixed key and salt, a repeat is a two-time pad. */
function checkDistinctSlots(
  outputCount: number,
  messages: readonly Readonly<{ slotIndex: number }>[],
): void {
  const slots = new Set<number>(Array.from({ length: outputCount }, (_, index) => index));
  for (const message of messages) {
    if (slots.has(message.slotIndex)) {
      throw new TransactionError("TRANSACTION_DUPLICATE_SLOT_INDEX", {
        slotIndex: message.slotIndex,
      });
    }
    slots.add(message.slotIndex);
  }
}

/** @internal Opens a sealed message under the transaction key of `firstNullifier`. */
export function openSealedMessageWith(
  viewingKey: ViewingKey,
  input: Readonly<{
    firstNullifier: Bytes32;
    salt: Bytes16;
    slotIndex: number;
    data: Uint8Array;
  }>,
): Uint8Array {
  const tx = viewingKey.transactionViewingKey(input.firstNullifier);
  try {
    const recipient = P256PublicKey.fromBytes(
      input.data.slice(0, P256_PUBLIC_KEY_LENGTH) as Bytes33,
    );
    const ciphertext = input.data.slice(P256_PUBLIC_KEY_LENGTH);
    return tx.decryptSlotEphemeral(recipient, ciphertext, input.salt, input.slotIndex);
  } finally {
    tx.destroy();
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
