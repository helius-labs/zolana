import { ctr } from "@noble/ciphers/aes.js";

import { type Bytes32, bigIntToBytes, checkedBytes, concatBytes, copyBytes } from "../bytes.js";
import {
  DOMAIN_MERGE_DUMMY_NULLIFIER,
  DOMAIN_MERGE_OUTPUT_BLINDING_V1,
  DOM_SEP_KEY,
  DOM_SEP_NONCE,
  DOM_SEP_SILO,
  MERGE_INFO as MERGE_INFO_BYTES,
} from "../derivation.js";
import { invalidLength } from "../error.js";
import type { NullifierKey } from "../nullifier-key.js";
import { poseidon } from "../poseidon.js";

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
