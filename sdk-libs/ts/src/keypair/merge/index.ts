import { ctr } from "@noble/ciphers/aes.js";

import { MERGE_CIPHERTEXT_LENGTH } from "../../interface/constants.js";
import { pack32, pack33, rightAlign } from "../../interface/merge-utils.js";
import {
  type Bytes32,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
  u64be,
} from "../bytes.js";
import {
  DOMAIN_MERGE_DERIVED_BLINDING,
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOM_SEP_KEY,
  DOM_SEP_NONCE,
  DOM_SEP_SILO,
  MERGE_ENVELOPE_INFO,
  MERGE_INFO as MERGE_INFO_BYTES,
  MERGE_SECRET_TAG,
} from "../derivation.js";
import { KeypairError, invalidLength } from "../error.js";
import type { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";
import type { P256PublicKey } from "../public-key.js";
import { privateTxBlinding } from "../transact/index.js";
import type { ViewingKey } from "../viewing-key.js";

export const MERGE_INFO = copyBytes(MERGE_INFO_BYTES);

const MERGE_AMOUNT_LENGTH = 8;
const MERGE_MINT_LENGTH = 32;
export const OPENED_MERGE_ENVELOPE_LENGTH = MERGE_AMOUNT_LENGTH + MERGE_MINT_LENGTH + 32;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export interface SealedMergeEnvelope {
  readonly ephemeralPublicKey: P256PublicKey;
  readonly ciphertext: Uint8Array;
  readonly outputBlinding: Bytes32;
}

export interface OpenedMergeEnvelope {
  readonly amount: bigint;
  readonly mint: Bytes32;
  readonly outputBlinding: Bytes32;
}

export function keyAgreementSecret(
  tag: Uint8Array,
  sharedX: Bytes32,
  ephemeralPublicKey: P256PublicKey,
  recipient: P256PublicKey,
): Bytes32 {
  const packed = pack32(sharedX);
  try {
    return poseidon([
      rightAlign(tag),
      ...packed,
      ...pack33(ephemeralPublicKey.toBytes()),
      ...pack33(recipient.toBytes()),
    ]) as Bytes32;
  } finally {
    for (const field of packed) field.fill(0);
  }
}

export function mergeSharedSecret(
  sharedX: Bytes32,
  ephemeralPublicKey: P256PublicKey,
  recipient: P256PublicKey,
): Bytes32 {
  return keyAgreementSecret(MERGE_SECRET_TAG, sharedX, ephemeralPublicKey, recipient);
}

export function sealMergeEnvelope(
  input: Readonly<{
    recipient: P256PublicKey;
    ephemeral: ViewingKey;
    amount: bigint;
    mint: Bytes32;
  }>,
): SealedMergeEnvelope {
  if (typeof input.amount !== "bigint" || input.amount < 0n || input.amount > U64_MAX) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name: "merge amount",
      minimum: 0,
      maximum: U64_MAX.toString(),
    });
  }
  const plaintext = concatBytes(
    u64be(input.amount),
    checkedBytes<Bytes32>(input.mint, MERGE_MINT_LENGTH, "merge mint"),
  );
  let sharedX: Bytes32 | undefined;
  let secret: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = input.ephemeral.publicKey();
    sharedX = input.ephemeral.ecdh(input.recipient);
    secret = mergeSharedSecret(sharedX, ephemeralPublicKey, input.recipient);
    return Object.freeze({
      ephemeralPublicKey,
      ciphertext: symmetricApply(secret, MERGE_ENVELOPE_INFO, plaintext),
      outputBlinding: mergeDerivedBlinding(secret),
    });
  } finally {
    plaintext.fill(0);
    sharedX?.fill(0);
    secret?.fill(0);
  }
}

export function openMergeEnvelope(
  input: Readonly<{
    viewingKey: ViewingKey;
    ephemeralPublicKey: P256PublicKey;
    ciphertext: Uint8Array;
  }>,
): OpenedMergeEnvelope {
  const ciphertext = checkedBytes<Uint8Array>(
    input.ciphertext,
    MERGE_CIPHERTEXT_LENGTH,
    "merge envelope ciphertext",
  );
  let sharedX: Bytes32 | undefined;
  let secret: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const recipient = input.viewingKey.publicKey();
    sharedX = input.viewingKey.ecdh(input.ephemeralPublicKey);
    secret = mergeSharedSecret(sharedX, input.ephemeralPublicKey, recipient);
    plaintext = symmetricApply(secret, MERGE_ENVELOPE_INFO, ciphertext);
    return Object.freeze({
      amount: bytesToBigInt(plaintext.subarray(0, MERGE_AMOUNT_LENGTH)),
      mint: copyBytes(plaintext.subarray(MERGE_AMOUNT_LENGTH)) as Bytes32,
      outputBlinding: mergeDerivedBlinding(secret),
    });
  } finally {
    sharedX?.fill(0);
    secret?.fill(0);
    plaintext?.fill(0);
  }
}

export function encodeOpenedMergeEnvelope(opened: OpenedMergeEnvelope): Uint8Array {
  return concatBytes(
    u64be(opened.amount),
    checkedBytes<Bytes32>(opened.mint, MERGE_MINT_LENGTH, "merge mint"),
    checkedBytes<Bytes32>(opened.outputBlinding, 32, "merge output blinding"),
  );
}

export function decodeOpenedMergeEnvelope(bytes: Uint8Array): OpenedMergeEnvelope {
  const opened = checkedBytes<Uint8Array>(
    bytes,
    OPENED_MERGE_ENVELOPE_LENGTH,
    "opened merge envelope",
  );
  const mintEnd = MERGE_AMOUNT_LENGTH + MERGE_MINT_LENGTH;
  try {
    return Object.freeze({
      amount: bytesToBigInt(opened.subarray(0, MERGE_AMOUNT_LENGTH)),
      mint: copyBytes(opened.subarray(MERGE_AMOUNT_LENGTH, mintEnd)) as Bytes32,
      outputBlinding: copyBytes(opened.subarray(mintEnd)) as Bytes32,
    });
  } finally {
    opened.fill(0);
  }
}

function mergeDerivedBlinding(sharedSecret: Bytes32): Bytes32 {
  return poseidon([fieldU32(DOMAIN_MERGE_DERIVED_BLINDING), sharedSecret]) as Bytes32;
}

function keySchedule(
  sharedSecret: Uint8Array,
  info: Uint8Array,
): readonly [Uint8Array, Uint8Array] {
  const siloed = poseidon([bigIntToBytes(BigInt(DOM_SEP_SILO)), sharedSecret, rightAlign(info)]);
  let keyLow: Uint8Array | undefined;
  let keyHigh: Uint8Array | undefined;
  let nonceSource: Uint8Array | undefined;
  try {
    keyLow = poseidon([bigIntToBytes(BigInt(DOM_SEP_KEY)), siloed]);
    keyHigh = poseidon([bigIntToBytes(BigInt(DOM_SEP_KEY) + 1n), siloed]);
    const key = concatBytes(keyHigh.subarray(16), keyLow.subarray(16));
    nonceSource = poseidon([bigIntToBytes(BigInt(DOM_SEP_NONCE)), siloed]);
    return [key, nonceSource.slice(20)];
  } finally {
    siloed.fill(0);
    keyLow?.fill(0);
    keyHigh?.fill(0);
    nonceSource?.fill(0);
  }
}

/**
 * Mirrors `zolana_keypair::symmetric_apply`: the Poseidon key schedule over a
 * pre-shared secret, then AES-256-CTR. Encryption and decryption are the same
 * operation, so applying it twice returns the input.
 */
export function symmetricApply(
  sharedSecret: Uint8Array,
  info: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (info.length !== MERGE_INFO_BYTES.length) {
    throw invalidLength("key schedule info", MERGE_INFO_BYTES.length, info.length);
  }
  const secret = checkedBytes<Bytes32>(sharedSecret, 32, "shared secret");
  let key: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  const counter = new Uint8Array(16);
  try {
    [key, nonce] = keySchedule(secret, info);
    counter.set(nonce);
    counter[15] = 2;
    return ctr(key, counter).encrypt(copyBytes(data));
  } finally {
    secret.fill(0);
    key?.fill(0);
    nonce?.fill(0);
    counter.fill(0);
  }
}

export function mergeOutputBlinding(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_OUTPUT_BLINDING_V1),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

/**
 * The private transaction blinding of a merge, `Poseidon("TXPB",
 * first_nullifier, nullifier_secret)`: merge has no blinding seed, the owner's
 * nullifier secret takes its place. Mirrors Rust `merge_private_tx_blinding`.
 */
export function mergePrivateTxBlinding(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return privateTxBlinding(checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"), secret);
  } finally {
    secret.fill(0);
  }
}

export function mergeDummyNullifier(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff) {
    throw new RangeError("merge dummy slot index must fit in u8");
  }
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
      fieldU32(slotIndex),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

function alignedNullifierSecret(nullifierKey: NullifierKey): Bytes32 {
  const secret = nullifierKey.secretBytes();
  try {
    return rightAlign(secret);
  } finally {
    secret.fill(0);
  }
}

function fieldU32(value: number): Bytes32 {
  const field = new Uint8Array(32);
  new DataView(field.buffer).setUint32(28, value, false);
  return field as Bytes32;
}
