import { X25519PublicKey, X25519Secret } from "../keypair/x25519.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes, copyBytes } from "../interface/internal.js";
import { pack33 } from "../interface/merge-utils.js";
import {
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_LENGTH,
  RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET,
  type RingDepositCapsule,
} from "./deposit-capsule.js";
import type { Address, Bytes32, Bytes96 } from "../interface/types.js";
import { auditSharedSecret } from "../keypair/audit.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { symmetricApply } from "../keypair/merge/index.js";
import { bigIntBytes, equal, hashChain } from "../transaction/internal.js";
import { ownerUtxoHash } from "../transaction/utxo.js";
import { RingError } from "./error.js";
import { ConfirmedDeposit } from "./origin.js";

const INFO = new TextEncoder().encode("CRING/dep1");
const OPENING_LENGTH = RING_DEPOSIT_OPENING_LENGTH;
const OWNER_KEY_OFFSET = RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET;
const PAYLOAD_LENGTH = OPENING_LENGTH * RING_DEPOSIT_AUDIT_SLOTS;
const ZERO = new Uint8Array(32) as Bytes32;

/** Carries the owner commitment preimage and unchanged recipient ciphertext. */
export interface RingDepositOpening {
  readonly ownerHash: Bytes32;
  readonly blinding: Bytes32;
  /** The Ed25519 owner key an anonymous ring discloses, the proof binds it to `ownerHash`. */
  readonly ownerKey?: Bytes32;
  readonly recipientCiphertext: Uint8Array;
}

export function sealRingDepositOpenings(
  openings: readonly RingDepositOpening[],
  auditor: X25519PublicKey,
): Readonly<{
  capsules: readonly RingDepositCapsule[];
  payloads: readonly Uint8Array[];
  ephemeralSecret: Bytes32;
}> {
  if (openings.length < 1 || openings.length > RING_DEPOSIT_AUDIT_SLOTS)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  const ephemeral = X25519Secret.generate();
  const plaintext = new Uint8Array(PAYLOAD_LENGTH);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    for (const [index, opening] of openings.entries()) {
      if (!isCanonicalField(opening.ownerHash) || !isCanonicalField(opening.blinding))
        throw new RingError("RING_BUILD_DEPOSIT");
      plaintext.set(opening.ownerHash, index * OPENING_LENGTH);
      plaintext.set(opening.blinding, index * OPENING_LENGTH + 32);
      if (opening.ownerKey !== undefined)
        plaintext.set(
          copyBytes(opening.ownerKey, 32, "deposit owner key"),
          index * OPENING_LENGTH + OWNER_KEY_OFFSET,
        );
    }
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditor);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditor);
    ciphertext = symmetricApply(shared, INFO, plaintext);
    const encrypted = ciphertext;
    const capsules = openings.map((opening, index): RingDepositCapsule =>
      Object.freeze({
        slotIndex: index,
        ephemeralPublicKey: ephemeralPublicKey.toBytes(),
        ciphertext: encrypted.slice(
          index * OPENING_LENGTH,
          (index + 1) * OPENING_LENGTH,
        ) as Bytes96,
        recipientCiphertext: new Uint8Array(opening.recipientCiphertext),
      }),
    );
    return Object.freeze({
      capsules: Object.freeze(capsules),
      payloads: Object.freeze(capsules.map(encodeRingDepositCapsule)),
      ephemeralSecret: ephemeral.secretBytes(),
    });
  } finally {
    ephemeral.destroy();
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
    ciphertext?.fill(0);
  }
}

/** `ownerKey` is the Ed25519 owner key of an anonymous ring deposit, absent otherwise. */
export function openRingDepositOpening(
  capsule: RingDepositCapsule,
  auditor: X25519Secret,
  ownerCommitment: Bytes32,
  confirmed: ConfirmedDeposit,
): Readonly<{ ownerHash: Bytes32; blinding: Bytes32; ownerKey?: Bytes32 }> {
  if (!ConfirmedDeposit.is(confirmed)) throw new RingError("RING_AUDIT_MESSAGE");
  const snapshot = readRingDepositCapsule(encodeRingDepositCapsule(capsule));
  if (snapshot === undefined) throw new RingError("RING_AUDIT_MESSAGE");
  capsule = snapshot;
  confirmed.authenticate(capsule, ownerCommitment);
  const ciphertext = new Uint8Array(PAYLOAD_LENGTH);
  ciphertext.set(capsule.ciphertext, capsule.slotIndex * OPENING_LENGTH);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const ephemeral = X25519PublicKey.fromBytes(capsule.ephemeralPublicKey);
    dh = auditor.ecdh(ephemeral);
    shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
    plaintext = symmetricApply(shared, INFO, ciphertext);
    const start = capsule.slotIndex * OPENING_LENGTH;
    const ownerHash = plaintext.slice(start, start + 32) as Bytes32;
    const blinding = plaintext.slice(start + 32, start + OWNER_KEY_OFFSET) as Bytes32;
    const ownerKey = plaintext.slice(start + OWNER_KEY_OFFSET, start + OPENING_LENGTH) as Bytes32;
    try {
      if (
        !isCanonicalField(ownerHash) ||
        !isCanonicalField(blinding) ||
        !isCanonicalField(ownerCommitment) ||
        !equal(ownerUtxoHash(ownerHash, blinding), ownerCommitment)
      )
        throw new RingError("RING_AUDIT_MESSAGE");
    } catch (cause) {
      ownerHash.fill(0);
      blinding.fill(0);
      throw cause;
    }
    return Object.freeze(
      isZero(ownerKey) ? { ownerHash, blinding } : { ownerHash, blinding, ownerKey },
    );
  } finally {
    ciphertext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

export function ringDepositContextHash(ring: Address, tree: Address, sppWire: Uint8Array): Bytes32 {
  return hashChain([
    hashBytes(addressBytes(ring)) as Bytes32,
    hashBytes(addressBytes(tree)) as Bytes32,
    bigIntBytes(BigInt(sppWire.length)) as Bytes32,
    hashBytes(sppWire) as Bytes32,
  ]);
}

export function ringDepositPublicInputHash(
  input: Readonly<{
    contextHash: Bytes32;
    ownerCommitments: readonly Bytes32[];
    capsules: readonly RingDepositCapsule[];
    auditorPublicKey: X25519PublicKey;
    /** Present exactly when deposited nullifier keys must be enrolled under it. */
    memberRegistryRoot?: Bytes32;
  }>,
): Bytes32 {
  const count = input.capsules.length;
  const first = input.capsules[0];
  if (
    count < 1 ||
    count > RING_DEPOSIT_AUDIT_SLOTS ||
    input.ownerCommitments.length !== count ||
    first === undefined
  )
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  if (!isCanonicalField(input.contextHash)) throw new RingError("RING_BUILD_DEPOSIT");
  X25519PublicKey.fromBytes(first.ephemeralPublicKey);
  const elements = [
    bigIntBytes(0x43524450n) as Bytes32,
    input.contextHash,
    bigIntBytes(BigInt(count)) as Bytes32,
    // The TypeScript builder admits only non-anonymous ring deposits.
    ZERO,
  ];
  for (let index = 0; index < RING_DEPOSIT_AUDIT_SLOTS; index++) {
    const capsule = input.capsules[index];
    if (capsule === undefined) elements.push(ZERO, ZERO);
    else {
      encodeRingDepositCapsule(capsule);
      if (
        capsule.slotIndex !== index ||
        !capsule.ephemeralPublicKey.every(
          (byte, offset) => byte === first.ephemeralPublicKey[offset],
        )
      )
        throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit capsule" } });
      const commitment = input.ownerCommitments[index];
      if (commitment === undefined || !isCanonicalField(commitment))
        throw new RingError("RING_BUILD_DEPOSIT");
      elements.push(commitment, hashBytes(capsule.ciphertext) as Bytes32);
    }
  }
  elements.push(
    ...pack33(input.auditorPublicKey.toBytes()),
    ...pack33(first.ephemeralPublicKey),
    bigIntBytes(input.memberRegistryRoot === undefined ? 0n : 1n) as Bytes32,
    input.memberRegistryRoot ?? ZERO,
  );
  return hashChain(elements);
}
