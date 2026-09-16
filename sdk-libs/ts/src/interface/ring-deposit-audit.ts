import { copyBytes, fail } from "./internal.js";
import type { Bytes33, Bytes64 } from "./types.js";

export const RING_DEPOSIT_AUDIT_SLOTS = 8;
export const AUDITED_RING_DEPOSIT_TAG = 32;
const MAGIC = new TextEncoder().encode("CRDEP001");
const HEADER_LENGTH = 106;

/** Carries one deposit opening and its original recipient ciphertext. */
export interface RingDepositCapsule {
  readonly slotIndex: number;
  readonly ephemeralPublicKey: Bytes33;
  readonly ciphertext: Bytes64;
  readonly recipientCiphertext: Uint8Array;
}

export function encodeRingDepositCapsule(input: RingDepositCapsule): Uint8Array {
  if (
    !Number.isInteger(input.slotIndex) ||
    input.slotIndex < 0 ||
    input.slotIndex >= RING_DEPOSIT_AUDIT_SLOTS
  )
    fail("INTERFACE_CODEC", { field: "deposit slot" });
  const recipient = copyBytes(input.recipientCiphertext);
  const bytes = new Uint8Array(HEADER_LENGTH + recipient.length);
  bytes.set(MAGIC);
  bytes[8] = input.slotIndex;
  bytes.set(copyBytes(input.ephemeralPublicKey, 33, "deposit ephemeral key"), 9);
  bytes.set(copyBytes(input.ciphertext, 64, "deposit opening ciphertext"), 42);
  bytes.set(recipient, HEADER_LENGTH);
  return bytes;
}

export function readRingDepositCapsule(input: Uint8Array): RingDepositCapsule | undefined {
  const bytes = copyBytes(input);
  if (!MAGIC.every((byte, index) => bytes[index] === byte)) return undefined;
  const slotIndex = bytes[8];
  if (
    bytes.length < HEADER_LENGTH ||
    slotIndex === undefined ||
    slotIndex >= RING_DEPOSIT_AUDIT_SLOTS
  )
    fail("INTERFACE_CODEC", { field: "deposit capsule" });
  return Object.freeze({
    slotIndex,
    ephemeralPublicKey: bytes.slice(9, 42) as Bytes33,
    ciphertext: bytes.slice(42, HEADER_LENGTH) as Bytes64,
    recipientCiphertext: bytes.slice(HEADER_LENGTH),
  });
}
