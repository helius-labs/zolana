import { ctr } from "@noble/ciphers/aes.js";

import { BN254_SCALAR_ORDER } from "../../hasher/index.js";
import {
  type Bytes32,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
} from "../bytes.js";
import {
  DOMAIN_MERGE_AMOUNT_MASK,
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_MINT_MASK,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOM_SEP_KEY,
  DOM_SEP_NONCE,
  DOM_SEP_SILO,
  MERGE_INFO as MERGE_INFO_BYTES,
} from "../derivation.js";
import { invalidLength } from "../error.js";
import type { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";
import { privateTxBlinding } from "../transact/index.js";

export const MERGE_INFO = copyBytes(MERGE_INFO_BYTES);

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
 * The pad over a merge's output amount under the amount nonce `mergeMaskNonces`
 * derives from the merge's fresh seed. Mirrors Rust `merge_amount_mask`.
 */
export function mergeAmountMask(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  nonce: Bytes32,
): Bytes32 {
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_AMOUNT_MASK),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
      checkedBytes<Bytes32>(nonce, 32, "amount mask nonce"),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

/**
 * The pad over chunk `chunkIndex` of a merge's output mint under the mint
 * nonce. Mirrors Rust `merge_mint_mask`.
 */
export function mergeMintMask(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  nonce: Bytes32,
  chunkIndex: number,
): Bytes32 {
  if (chunkIndex !== 0 && chunkIndex !== 1) {
    throw new RangeError("merge mint chunk index must be 0 or 1");
  }
  const secret = alignedNullifierSecret(nullifierKey);
  try {
    return poseidon([
      fieldU32(DOMAIN_MERGE_MINT_MASK),
      secret,
      checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
      checkedBytes<Bytes32>(nonce, 32, "mint mask nonce"),
      fieldU32(chunkIndex),
    ]) as Bytes32;
  } finally {
    secret.fill(0);
  }
}

/** `amount + mask` in the BN254 scalar field; mirrors Rust `merge_masked_amount`. */
export function mergeMaskedAmount(amount: bigint, mask: Bytes32): Bytes32 {
  return maskedField(amount, mask);
}

/**
 * Inverts `mergeMaskedAmount`; `undefined` when the published value does not
 * encode a u64 under this mask. Mirrors Rust `merge_unmasked_amount`.
 */
export function mergeUnmaskedAmount(maskedAmount: Bytes32, mask: Bytes32): bigint | undefined {
  const amount = unmaskedField(maskedAmount, mask);
  return amount !== undefined && amount <= 0xffff_ffff_ffff_ffffn ? amount : undefined;
}

/**
 * The two field elements `hash_bytes` packs a 32-byte mint into: its first 31
 * bytes, then its last byte. Mirrors Rust `merge_mint_chunks`.
 */
export function mergeMintChunks(mint: Bytes32): readonly [Bytes32, Bytes32] {
  const bytes = checkedBytes<Bytes32>(mint, 32, "mint");
  return Object.freeze([
    rightAlign(bytes.subarray(0, 31)),
    rightAlign(bytes.subarray(31)),
  ] as const);
}

/** Each mint chunk plus its mask; mirrors Rust `merge_masked_mint`. */
export function mergeMaskedMint(
  mint: Bytes32,
  masks: readonly [Bytes32, Bytes32],
): readonly [Bytes32, Bytes32] {
  const [prefix, last] = mergeMintChunks(mint);
  return Object.freeze([
    maskedField(bytesToBigInt(prefix), masks[0]),
    maskedField(bytesToBigInt(last), masks[1]),
  ] as const);
}

/**
 * Inverts `mergeMaskedMint`; `undefined` unless both chunks unmask to the
 * canonical packing of some mint. Mirrors Rust `merge_unmasked_mint`.
 */
export function mergeUnmaskedMint(
  maskedMint: readonly [Bytes32, Bytes32],
  masks: readonly [Bytes32, Bytes32],
): Bytes32 | undefined {
  const prefix = unmaskedField(maskedMint[0], masks[0]);
  const last = unmaskedField(maskedMint[1], masks[1]);
  if (prefix === undefined || last === undefined || prefix >= 1n << 248n || last >= 256n) {
    return undefined;
  }
  const mint = new Uint8Array(32);
  mint.set(bigIntToBytes(prefix).subarray(1));
  mint[31] = Number(last);
  return mint as Bytes32;
}

function maskedField(value: bigint, mask: Bytes32): Bytes32 {
  const pad = bytesToBigInt(checkedBytes<Bytes32>(mask, 32, "merge mask"));
  return bigIntToBytes((value + pad) % BN254_SCALAR_ORDER) as Bytes32;
}

function unmaskedField(masked: Bytes32, mask: Bytes32): bigint | undefined {
  const value = bytesToBigInt(checkedBytes<Bytes32>(masked, 32, "masked merge value"));
  if (value >= BN254_SCALAR_ORDER) return undefined;
  const pad = bytesToBigInt(checkedBytes<Bytes32>(mask, 32, "merge mask")) % BN254_SCALAR_ORDER;
  return (value + BN254_SCALAR_ORDER - pad) % BN254_SCALAR_ORDER;
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

function rightAlign(bytes: Uint8Array): Bytes32 {
  const field = new Uint8Array(32);
  field.set(bytes, 32 - bytes.length);
  return field as Bytes32;
}
