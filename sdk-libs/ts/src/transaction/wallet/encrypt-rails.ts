import { RING_SPEND_COUNTERS_SLOT_INDEX } from "../../interface/constants.js";
import { addressBytes } from "../../interface/internal.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import { treeIdField } from "../../interface/tree-slot.js";
import type { Bytes16, Bytes32, Bytes33, MessageData } from "../../interface/types.js";
import { hashBytes } from "../../hasher/index.js";
import {
  auditorMessageData,
  encryptTransactionViewingSecret,
  type AuditOutputOpening,
} from "../../keypair/audit.js";
import { bigIntToBytes, randomSalt } from "../../keypair/bytes.js";
import { P256_PUBLIC_KEY_LENGTH } from "../../keypair/constants.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress } from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";
import { TransactionError } from "../error.js";
import { rightAlign, ZERO_32 } from "../internal.js";

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
import { createProofOutput, type ProofOutputUtxo, type TreeId } from "../utxo.js";
import { SOL_MINT, type AssetRegistry } from "../asset.js";

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
  readonly sealedMessages: readonly MessageData[];
  readonly audit: AuditWitness;
}

/** Plaintext sealed to the transaction viewing key under its own slot index. */
export interface SealedMessageInput {
  readonly viewTag: Bytes32;
  readonly plaintext: Uint8Array;
  readonly slotIndex: number;
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

/**
 * The caller wipes the returned audit secrets after proving. `recordOutputIndex`
 * names the last output as the spend record carrier, encrypted to the
 * transaction viewing key itself. `counterMessage` is the protocol counter seal,
 * never a caller message channel.
 */
export function encryptCustomRingTransfer(
  tx: ViewingKey,
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
    auditorPublicKey: P256PublicKey;
    outputTreeId: TreeId;
    recordOutputIndex?: number;
    sealedMessages?: readonly SealedMessageInput[];
    counterMessage?: Omit<SealedMessageInput, "slotIndex">;
  }>,
): EncryptedCustomRingTransfer {
  let txViewingSecret: Bytes32 | undefined;
  let ephemeralSecret: Bytes32 | undefined;
  try {
    const salt = randomSalt();
    txViewingSecret = tx.secretBytes();
    const recipient = tx.publicKey();
    const outputs = recordCarrierOutputs(
      input.outputs,
      input.recordOutputIndex === undefined
        ? undefined
        : { index: input.recordOutputIndex, recipient },
    );
    const encryption = encryptTransactionViewingSecret(txViewingSecret, input.auditorPublicKey, {
      salt,
      outputs: outputs.map((output) => auditOutputOpening(output, input.outputTreeId)),
    });
    ephemeralSecret = encryption.ephemeralSecret;
    const callerMessages = (input.sealedMessages ?? []).map((message) => ({
      slotIndex: message.slotIndex,
      plaintext: message.plaintext,
      viewTag: message.viewTag,
    }));
    checkDistinctSlots(outputs.length, callerMessages);
    const outbound = [
      ...callerMessages,
      ...(input.counterMessage === undefined
        ? []
        : [{ ...input.counterMessage, slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX }]),
    ];
    const sealedMessages: readonly MessageData[] = outbound.map((message) => {
      const ciphertext = tx.encryptSlot(recipient, message.plaintext, salt, message.slotIndex);
      const body = new Uint8Array(P256_PUBLIC_KEY_LENGTH + ciphertext.length);
      body.set(recipient.toBytes(), 0);
      body.set(ciphertext, P256_PUBLIC_KEY_LENGTH);
      return { viewTag: message.viewTag, data: body };
    });
    const encrypted = {
      txViewingPublicKey: recipient,
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
    txViewingSecret?.fill(0);
    ephemeralSecret?.fill(0);
  }
}

function auditOutputOpening(output: ProofOutputUtxo, outputTreeId: TreeId): AuditOutputOpening {
  const dummy = output.isDummy();
  return Object.freeze({
    domain: rightAlign(Uint8Array.of(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
    treeId: treeIdField(outputTreeId),
    ownerHash: dummy ? ZERO_32 : output.ownerHash(),
    asset: dummy ? ZERO_32 : (hashBytes(addressBytes(output.asset)) as Bytes32),
    amount: dummy ? ZERO_32 : (bigIntToBytes(output.amount) as Bytes32),
    blinding: output.blinding,
    dataHash: dummy ? ZERO_32 : (output.dataHash ?? ZERO_32),
    ringDataHash: dummy ? ZERO_32 : (output.ringDataHash ?? ZERO_32),
    ringProgramId:
      dummy || output.ringProgramId === undefined
        ? ZERO_32
        : (hashBytes(addressBytes(output.ringProgramId)) as Bytes32),
  });
}

/** The recipient viewing key does not affect the UTXO commitment. */
function recordCarrierOutputs(
  outputs: readonly ProofOutputUtxo[],
  carrier: Readonly<{ index: number; recipient: P256PublicKey }> | undefined,
): readonly ProofOutputUtxo[] {
  if (carrier === undefined) return outputs;
  const { index, recipient } = carrier;
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

/** One keystream per slot under a fixed key and salt. */
function checkDistinctSlots(
  outputCount: number,
  messages: readonly Readonly<{ slotIndex: number }>[],
): void {
  const slots = new Set<number>([
    RING_SPEND_COUNTERS_SLOT_INDEX,
    ...Array.from({ length: outputCount }, (_, index) => index),
  ]);
  for (const message of messages) {
    if (slots.has(message.slotIndex)) {
      throw new TransactionError("TRANSACTION_DUPLICATE_SLOT_INDEX", {
        slotIndex: message.slotIndex,
      });
    }
    slots.add(message.slotIndex);
  }
}

/** `data` is the recipient key followed by the slot ciphertext. */
export function openSealedMessage(
  tx: ViewingKey,
  input: Readonly<{ salt: Bytes16; slotIndex: number; data: Uint8Array }>,
): Uint8Array {
  const recipient = P256PublicKey.fromBytes(input.data.slice(0, P256_PUBLIC_KEY_LENGTH) as Bytes33);
  const ciphertext = input.data.slice(P256_PUBLIC_KEY_LENGTH);
  return tx.decryptSlotEphemeral(recipient, ciphertext, input.salt, input.slotIndex);
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
