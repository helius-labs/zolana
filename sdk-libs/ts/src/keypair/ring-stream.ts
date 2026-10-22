import { getAddressEncoder, type Address } from "@solana/kit";

import { hashBytes, packBytesBe } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { rightAlign } from "../interface/merge-utils.js";

import { symmetricAuditApply } from "./audit.js";
import {
  type Bytes16,
  type Bytes32,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  u32Field,
  u64be,
} from "./bytes.js";
import { checkedCounter } from "./derivation.js";
import { KeypairError } from "./error.js";
import { RingDomain, domainHash } from "./ring-domain.js";
import type { X25519PublicKey } from "./x25519.js";

const addressEncoder = getAddressEncoder();

/** `epoch = slot / EPOCH_SLOTS`, the statement epoch the program derives. */
export const EPOCH_SLOTS = 1n << 18n;
/** A 6-bit index in the circuit. */
export const J_INBOX = 64;
/** One index range check serves both streams. */
export const J_PAIR = J_INBOX;
/** Epochs a pair stream lives after its anchor, a 5-bit difference in the circuit. */
export const K_PAIR_EPOCHS = 32n;
/** `low128` bytes, the owner tag is `0^16 ‖ tag`. */
export const TAG_LEN = 16;
/** `asset_address(32) ‖ u64be(amount)`, Rust `zolana_event::RING_DELIVERED_BODY_LEN`. */
export const BODY_LEN = 40;

/** Below `J_INBOX`, the only indexes a proof accepts. */
export type TagIndex = number & { readonly __tagIndex: true };

export function tagEpoch(slot: bigint): bigint {
  return checkedCounter(slot, "slot") / EPOCH_SLOTS;
}

export function tagIndex(index: number): TagIndex {
  if (!Number.isInteger(index) || index < 0 || index >= J_INBOX)
    throw new KeypairError("KEYPAIR_TAG_INDEX_OUT_OF_RANGE", { index, maximum: J_INBOX - 1 });
  return index as TagIndex;
}

export type PackedSlot = Readonly<{
  /** The clamped encoding the auditor envelope seals. */
  txViewingSecret: Bytes32;
  salt: Bytes16;
  outputIndex: number;
  firstNullifier: Bytes32;
}>;

/** `Poseidon(CRAS, pack_be(tx_sk), salt, i, n0)`, known only to the sender and the auditor of `tx_sk`. */
export function packedSlotSecret(slot: PackedSlot): Bytes32 {
  const tail = slotTail(slot);
  return domainHash(RingDomain.packedSlotSecret, [
    ...packedSecret(slot.txViewingSecret, "transaction viewing secret"),
    ...tail,
  ]);
}

export type DeliveredSlot = Readonly<{
  /** `X25519(tx_sk, u)`. */
  agreement: Bytes32;
  txViewingKey: X25519PublicKey;
  recipientViewingKey: X25519PublicKey;
  salt: Bytes16;
  outputIndex: number;
  firstNullifier: Bytes32;
}>;

/** `Poseidon(CRDS, pack_be(dh), pack_be(tx_viewing_pk), pack_be(recipient_viewing_pk), salt, i, n0)`, rebuilt by the recipient from `X25519(u_sk, tx_u)`. */
export function deliveredSlotSecret(slot: DeliveredSlot): Bytes32 {
  const keys = [
    ...packBytesBe(slot.txViewingKey.toBytes()),
    ...packBytesBe(slot.recipientViewingKey.toBytes()),
  ];
  const tail = slotTail(slot);
  return domainHash(RingDomain.deliveredSlotSecret, [
    ...packedSecret(slot.agreement, "agreement"),
    ...keys,
    ...tail,
  ]);
}

/** Rust `ring_id_field`, `hash_bytes` of the ring program address. */
export function ringIdField(ring: Address): Bytes32 {
  return hashBytes(new Uint8Array(addressEncoder.encode(ring))) as Bytes32;
}

/** `Poseidon(CRIK, ring_id, pack_be(viewing_pk))`, public to anyone holding the ring address. */
export function inboxKey(ringId: Bytes32, viewingKey: X25519PublicKey): Bytes32 {
  return domainHash(RingDomain.inboxKey, [
    checkedBytes<Bytes32>(ringId, 32, "ring id"),
    ...packBytesBe(viewingKey.toBytes()),
  ]);
}

/** `low128(Poseidon(CRIT, inbox_key, epoch, j))`. */
export function inboxTag(key: Bytes32, epoch: bigint, index: TagIndex): Bytes16 {
  return streamTag(RingDomain.inboxTag, key, epoch, index);
}

/** `Poseidon(CRPK, s1)`, a secret of the sender, the recipient and the auditor of the first contact. */
export function pairKey(firstContactSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.pairKey, [
    checkedBytes<Bytes32>(firstContactSecret, 32, "first contact secret"),
  ]);
}

/** `low128(Poseidon(CRPT, pair_key, epoch, j))`, live `K_PAIR_EPOCHS` after the anchor. */
export function pairTag(key: Bytes32, epoch: bigint, index: TagIndex): Bytes16 {
  return streamTag(RingDomain.pairTag, key, epoch, index);
}

/** The circuit reads `low128` of the reduced value, a non-canonical encoding is refused. */
export function ringTag(field: Bytes32): Bytes16 {
  const value = checkedBytes<Bytes32>(field, 32, "tag field");
  if (!isCanonicalField(value))
    throw new KeypairError("KEYPAIR_NONCANONICAL_FIELD", { name: "tag" });
  return low128(value);
}

/** `0^16 ‖ tag`, the expanded owner tag and the field the statement chains. */
export function ringTagField(tag: Bytes16): Bytes32 {
  return rightAlign(checkedBytes<Bytes16>(tag, TAG_LEN, "tag"));
}

/** `0^16 ‖ tag` is the one owner tag form of an anonymous slot, Rust `RingTag::from_owner_tag`. */
export function ringTagFromOwnerTag(ownerTag: Bytes32): Bytes16 | undefined {
  const value = checkedBytes<Bytes32>(ownerTag, 32, "owner tag");
  return value.subarray(0, 32 - TAG_LEN).every((byte) => byte === 0) ? low128(value) : undefined;
}

/** `Poseidon(CRRC, s)`, a confidential or delegate ring secret no anchor accepts. */
export function confidentialRingSecret(slotSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.confidentialRingSecret, [
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
  ]);
}

/** `Poseidon(CRRA, s, tag)`, the one form an anchor opens, binding the published tag. */
export function anonymousRingSecret(slotSecret: Bytes32, tag: Bytes16): Bytes32 {
  const tagField = ringTagField(tag);
  return domainHash(RingDomain.anonymousRingSecret, [
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    tagField,
  ]);
}

/** `Poseidon(CRSC, sender_pk_hash, private_tx_blinding)`, binding the audit and policy proofs to one hidden sender. */
export function senderCommitment(
  sender: Readonly<{ senderPkHash: Bytes32; privateTxBlinding: Bytes32 }>,
): Bytes32 {
  return domainHash(RingDomain.senderCommitment, [
    checkedBytes<Bytes32>(sender.senderPkHash, 32, "sender pk hash"),
    checkedBytes<Bytes32>(sender.privateTxBlinding, 32, "private tx blinding"),
  ]);
}

/** What a scheme 9 or 10 body opens to, the recipient rebuilds the rest of the UTXO. */
export interface DeliveredBodyOpening {
  /** The mint, all zero for SOL. */
  readonly assetAddress: Bytes32;
  readonly amount: bigint;
}

/** AES-256-CTR of `asset_address ‖ u64be(amount)` under the slot secret's audit stream. */
export function sealDeliveredBody(slotSecret: Bytes32, opening: DeliveredBodyOpening): Uint8Array {
  const plaintext = concatBytes(
    checkedBytes<Bytes32>(opening.assetAddress, 32, "asset address"),
    u64be(checkedCounter(opening.amount, "amount")),
  );
  try {
    return symmetricAuditApply(checkedBytes<Bytes32>(slotSecret, 32, "slot secret"), plaintext);
  } finally {
    plaintext.fill(0);
  }
}

export function openDeliveredBody(slotSecret: Bytes32, body: Uint8Array): DeliveredBodyOpening {
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    checkedBytes(body, BODY_LEN, "delivered body"),
  );
  try {
    return Object.freeze({
      assetAddress: checkedBytes<Bytes32>(plaintext.subarray(0, 32), 32, "asset address"),
      amount: bytesToBigInt(plaintext.subarray(32)),
    });
  } finally {
    plaintext.fill(0);
  }
}

function streamTag(domain: RingDomain, key: Bytes32, epoch: bigint, index: TagIndex): Bytes16 {
  const position = [
    rightAlign(u64be(checkedCounter(epoch, "epoch"))),
    rightAlign(Uint8Array.of(tagIndex(index))),
  ];
  return low128(domainHash(domain, [checkedBytes<Bytes32>(key, 32, "stream key"), ...position]));
}

/** Packs a validated copy, the copy wiped once packed. */
function packedSecret(secret: Bytes32, name: string): Uint8Array[] {
  const copy = checkedBytes<Bytes32>(secret, 32, name);
  try {
    return packBytesBe(copy);
  } finally {
    copy.fill(0);
  }
}

/** `salt, i, n0`, validated before any secret is copied. */
function slotTail(
  slot: Readonly<{ salt: Bytes16; outputIndex: number; firstNullifier: Bytes32 }>,
): Bytes32[] {
  return [
    rightAlign(checkedBytes<Bytes16>(slot.salt, 16, "salt")),
    u32Field(slot.outputIndex, "outputIndex"),
    checkedBytes<Bytes32>(slot.firstNullifier, 32, "first nullifier"),
  ];
}

function low128(value: Bytes32): Bytes16 {
  return checkedBytes<Bytes16>(value.subarray(32 - TAG_LEN), TAG_LEN, "tag");
}
