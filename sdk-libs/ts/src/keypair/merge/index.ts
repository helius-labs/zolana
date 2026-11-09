import { ctr } from "@noble/ciphers/aes.js";

import {
  type Bytes31,
  type Bytes32,
  bigIntToBytes,
  checkedBytes,
  copyBytes,
  fieldU32,
} from "../bytes.js";
import {
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOMAIN_MERGE_OUTPUT_CIPHERTEXT,
  DOMAIN_MERGE_OUTPUT_KEY,
  DOM_SEP_KEY,
  DOM_SEP_NONCE,
  DOM_SEP_SILO,
  MERGE_INFO as MERGE_INFO_BYTES,
} from "../derivation.js";
import { invalidLength } from "../error.js";
import { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";
import { privateTxBlinding } from "../transact/index.js";
import { bytesToBigInt, concatBytes, rightAlign } from "../../interface/bytes.js";

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
 * Mirrors `spr_keypair::symmetric_apply`: the Poseidon key schedule over a
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

/** A right-aligned nullifier secret, or a viewing-key seed under the zero key. */
export function mergeOutputBlindingFromSeed(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(DOMAIN_MERGE_OUTPUT_BLINDING_V1),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
  ]) as Bytes32;
}

export function mergeOutputBlinding(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  return withNullifierSeed(nullifierKey, (seed) =>
    mergeOutputBlindingFromSeed(seed, firstNullifier),
  );
}

/** Keyed per first nullifier. Mirrors Rust `MergeSeed::output_key`. */
export function mergeOutputKeyFromSeed(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(DOMAIN_MERGE_OUTPUT_KEY),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
  ]) as Bytes32;
}

export function mergeOutputKey(nullifierKey: NullifierKey, firstNullifier: Bytes32): Bytes32 {
  return withNullifierSeed(nullifierKey, (seed) => mergeOutputKeyFromSeed(seed, firstNullifier));
}

/** Field elements in a merge output ciphertext: the amount and two mint chunks. */
export const MERGE_OUTPUT_CIPHERTEXT_ELEMENTS = 3;

/**
 * The output ciphertext pads, `Poseidon("TMOC", key, salt, i)`: element `i`
 * of the plaintext is added to pad `i` in the BN254 scalar field. Mirrors Rust
 * `pads` in `instructions/merge/serialization.rs` and the circuit's `PoseidonCtr`.
 */
export function mergeOutputPads(key: Bytes32, salt: Uint8Array): readonly [bigint, bigint, bigint] {
  checkedBytes<Bytes32>(key, 32, "merge output key");
  if (salt.length !== 16) throw invalidLength("merge output salt", 16, salt.length);
  const alignedSalt = rightAlign(salt);
  const pad = (index: number): bigint =>
    bytesToBigInt(
      poseidon([fieldU32(DOMAIN_MERGE_OUTPUT_CIPHERTEXT), key, alignedSalt, fieldU32(index)]),
    );
  return [pad(0), pad(1), pad(2)];
}

/** Mirrors Rust `MergeSeed::private_tx_blinding`. */
export function mergePrivateTxBlindingFromSeed(seed: Bytes32, firstNullifier: Bytes32): Bytes32 {
  return privateTxBlinding(
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
  );
}

export function mergePrivateTxBlinding(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
): Bytes32 {
  return withNullifierSeed(nullifierKey, (seed) =>
    mergePrivateTxBlindingFromSeed(seed, firstNullifier),
  );
}

export function mergeDummyNullifierFromSeed(
  seed: Bytes32,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  if (!Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex > 0xff) {
    throw new RangeError("merge dummy slot index must fit in u8");
  }
  return poseidon([
    fieldU32(DOMAIN_MERGE_DUMMY_NULLIFIER),
    checkedBytes<Bytes32>(seed, 32, "merge seed"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    fieldU32(slotIndex),
  ]) as Bytes32;
}

export function mergeDummyNullifier(
  nullifierKey: NullifierKey,
  firstNullifier: Bytes32,
  slotIndex: number,
): Bytes32 {
  return withNullifierSeed(nullifierKey, (seed) =>
    mergeDummyNullifierFromSeed(seed, firstNullifier, slotIndex),
  );
}

/** Public key of the zero nullifier key. */
export function zeroNullifierPublicKey(): Bytes32 {
  const zeroKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
  try {
    return zeroKey.publicKey();
  } finally {
    zeroKey.destroy();
  }
}

function withNullifierSeed(nullifierKey: NullifierKey, use: (seed: Bytes32) => Bytes32): Bytes32 {
  const secret = nullifierKey.secretBytes();
  const seed = rightAlign(secret);
  secret.fill(0);
  try {
    return use(seed);
  } finally {
    seed.fill(0);
  }
}
