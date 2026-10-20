import { addressBytes } from "../../interface/internal.js";
import type { Address, Bytes32, MessageData } from "../../interface/types.js";
import { SOLANA_OWNER_TAG } from "../../hasher/index.js";
import {
  auditorMessageData,
  encryptTransactionViewingSecret,
  type AnonymousOutputOpening,
  type AuditInputOpening,
} from "../../keypair/audit.js";
import { randomBytes, randomSalt } from "../../keypair/bytes.js";
import type { RingAddress } from "../../keypair/ring-address.js";
import type { X25519PublicKey } from "../../keypair/x25519.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";
import { TransactionError } from "../error.js";
import { ZERO_32, equal } from "../internal.js";
import {
  EncryptedScheme,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  encodeOutputData,
  encodeRingAnonymous,
  ringAnonymousBodyHash,
} from "../serialization/codecs.js";
import type { ProofOutputUtxo } from "../utxo.js";

import type { AuditWitness, EncryptedEnvelope } from "./encrypt-rails.js";
import { hex } from "./state.js";

/** A real output slot, the destination address and the tag the allocator assigned. */
export interface AnonymousRingSlot {
  readonly address: RingAddress;
  readonly tag: Bytes32;
}

/** One published slot of the prover's `delivery.outputs`, zero asset and pair key on padding. */
export interface AnonymousOutputDelivery {
  readonly assetAddress: Bytes32;
  readonly pairU: Bytes32;
  readonly ciphertext: Uint8Array;
}

export interface EncryptedAnonymousRingTransfer extends EncryptedEnvelope<readonly MessageData[]> {
  readonly auditorMessage: MessageData;
  readonly audit: AuditWitness;
  readonly delivery: readonly AnonymousOutputDelivery[];
  /** `hashBytes` of each 105-byte published body in slot order, the statement's body chain. */
  readonly outputBodyHashes: readonly Bytes32[];
}

export interface AnonymousRingTransferInput {
  /** The spender's long-lived viewing key, its pair key toward each recipient is the pseudonym. */
  readonly sender: ViewingKey;
  /** The hidden owner's 32-byte signing key, disclosed to the auditor. */
  readonly senderIdentity: Bytes32;
  readonly ringProgramId: Address;
  readonly auditorPublicKey: X25519PublicKey;
  /** Every slot of the shape, a padding slot is a dummy output with no entry in `slots`. */
  readonly outputs: readonly ProofOutputUtxo[];
  readonly slots: readonly (AnonymousRingSlot | undefined)[];
  readonly inputs: readonly AuditInputOpening[];
}

/** Seals every slot, a padding slot carries a random body and tag in the real framing, the caller wipes the returned audit secrets after proving. */
export function encryptAnonymousRingTransfer(
  tx: ViewingKey,
  input: AnonymousRingTransferInput,
): EncryptedAnonymousRingTransfer {
  if (input.slots.length !== input.outputs.length) {
    throw new TransactionError("TRANSACTION_ANONYMOUS_SLOT_MISMATCH", {
      reason: "slot count",
      outputs: input.outputs.length,
      slots: input.slots.length,
    });
  }
  let txViewingSecret: Bytes32 | undefined;
  let ephemeralSecret: Bytes32 | undefined;
  try {
    const salt = randomSalt();
    const txViewingPublicKey = tx.publicKey();
    const tags = new TagSet();
    for (const slot of input.slots) if (slot !== undefined) tags.add(slot.tag, "duplicate tag");
    const sealed = input.outputs.map((output, slotIndex) =>
      sealSlot(tx, input, output, input.slots[slotIndex], slotIndex, salt, tags),
    );
    txViewingSecret = tx.secretBytes();
    const encryption = encryptTransactionViewingSecret(txViewingSecret, input.auditorPublicKey, {
      salt,
      anonymous: {
        sender: input.senderIdentity,
        inputs: input.inputs,
        outputs: sealed.map((slot) => slot.disclosure),
      },
    });
    ephemeralSecret = encryption.ephemeralSecret;
    const encrypted: EncryptedAnonymousRingTransfer = Object.freeze({
      txViewingPublicKey,
      salt,
      payload: Object.freeze(sealed.map((slot) => slot.message)),
      auditorMessage: auditorMessageData(encryption.message, input.auditorPublicKey),
      audit: Object.freeze({ txViewingSecret, ephemeralSecret }),
      delivery: Object.freeze(sealed.map((slot) => slot.delivery)),
      outputBodyHashes: Object.freeze(sealed.map((slot) => slot.bodyHash)),
    });
    txViewingSecret = undefined;
    ephemeralSecret = undefined;
    return encrypted;
  } finally {
    txViewingSecret?.fill(0);
    ephemeralSecret?.fill(0);
  }
}

interface SealedSlot {
  readonly message: MessageData;
  readonly delivery: AnonymousOutputDelivery;
  readonly bodyHash: Bytes32;
  readonly disclosure: AnonymousOutputOpening;
}

const PADDING_DISCLOSURE: AnonymousOutputOpening = Object.freeze({
  identityTag: 0,
  identityKey: ZERO_32,
  nullifierPublicKey: ZERO_32,
  viewingPublicKey: new Uint8Array(33) as AnonymousOutputOpening["viewingPublicKey"],
});

function sealSlot(
  tx: ViewingKey,
  input: AnonymousRingTransferInput,
  output: ProofOutputUtxo,
  slot: AnonymousRingSlot | undefined,
  slotIndex: number,
  salt: ReturnType<typeof randomSalt>,
  tags: TagSet,
): SealedSlot {
  const mismatch = (reason: string): TransactionError =>
    new TransactionError("TRANSACTION_ANONYMOUS_SLOT_MISMATCH", { reason, slotIndex });
  if (output.isCompact()) {
    throw new TransactionError("TRANSACTION_ANONYMOUS_COMPACT_PADDING", { slotIndex });
  }
  if (output.isDummy() !== (slot === undefined)) throw mismatch("padding");
  if (slot === undefined) {
    const ciphertext = randomBytes(RING_ANONYMOUS_PLAINTEXT_LENGTH);
    return {
      message: { viewTag: tags.fresh(), data: framed(ciphertext) },
      delivery: { assetAddress: ZERO_32, pairU: ZERO_32, ciphertext },
      bodyHash: ringAnonymousBodyHash(ciphertext),
      disclosure: PADDING_DISCLOSURE,
    };
  }
  const { address, tag } = slot;
  const owner = output.ownerAddress;
  if (owner === undefined || !equal(owner.toBytes(), address.recipient.toBytes())) {
    throw mismatch("owner");
  }
  if (
    output.ringProgramId !== input.ringProgramId ||
    address.ringProgramId !== input.ringProgramId
  ) {
    throw mismatch("ring");
  }
  if (
    !output.data.isEmpty() ||
    (output.dataHash !== undefined && !equal(output.dataHash, ZERO_32)) ||
    (output.ringDataHash !== undefined && !equal(output.ringDataHash, ZERO_32))
  ) {
    throw new TransactionError("TRANSACTION_ANONYMOUS_OUTPUT_DATA", { slotIndex });
  }
  checkTagShape(tag);
  const recipient = address.recipient.viewingPublicKey;
  const pair = input.sender.pairKey(recipient);
  let pairU: Bytes32;
  try {
    pairU = pair.publicKey().u();
  } finally {
    pair.destroy();
  }
  const plaintext = encodeRingAnonymous({
    assetAddress: output.asset,
    amount: output.amount,
    blinding: output.blinding,
    pairU,
  });
  let ciphertext: Uint8Array;
  try {
    ciphertext = tx.sealAnonymousOutput(recipient, plaintext, salt, slotIndex);
  } finally {
    plaintext.fill(0);
  }
  return {
    message: { viewTag: tag, data: framed(ciphertext) },
    delivery: { assetAddress: addressBytes(output.asset) as Bytes32, pairU, ciphertext },
    bodyHash: ringAnonymousBodyHash(ciphertext),
    disclosure: Object.freeze({
      identityTag: SOLANA_OWNER_TAG,
      identityKey: address.recipient.signingPublicKey.confidentialViewTag(),
      nullifierPublicKey: address.recipient.nullifierPublicKey,
      viewingPublicKey: recipient.toBytes(),
    }),
  };
}

function framed(ciphertext: Uint8Array): Uint8Array {
  return encodeOutputData(EncryptedScheme.ringAnonymous, ciphertext, "encrypted");
}

/** The ring program refuses a tag outside `0x00 || 31 nonzero-somewhere bytes`. */
export function checkTagShape(tag: Bytes32): void {
  if (tag.length !== 32 || tag[0] !== 0 || tag.every((byte) => byte === 0)) {
    throw new TransactionError("TRANSACTION_ANONYMOUS_TAG");
  }
}

/** The tags of one transaction, a padding tag is resampled until it is unique. */
class TagSet {
  readonly #seen = new Set<string>();

  add(tag: Bytes32, reason: string): void {
    checkTagShape(tag);
    const key = hex(tag);
    if (this.#seen.has(key)) {
      throw new TransactionError("TRANSACTION_ANONYMOUS_SLOT_MISMATCH", { reason });
    }
    this.#seen.add(key);
  }

  fresh(): Bytes32 {
    for (;;) {
      const tag = randomBytes(32) as Bytes32;
      tag[0] = 0;
      if (this.#seen.has(hex(tag))) continue;
      this.add(tag, "padding tag");
      return tag;
    }
  }
}
