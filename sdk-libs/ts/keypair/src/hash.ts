import { sha256 } from "@noble/hashes/sha2.js";
import { pack33 as interfacePack33 } from "@zolana/interface";

import { type Bytes32 } from "./bytes.js";
import { wrapKeypairError } from "./error.js";
import { poseidon } from "./poseidon.js";

export function splitBigEndian128(value: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const low = new Uint8Array(32);
  const high = new Uint8Array(32);
  high.set(value.subarray(0, 16), 16);
  low.set(value.subarray(16, 32), 16);
  return [low, high];
}

export function hashField(value: Uint8Array): Bytes32 {
  return poseidon(splitBigEndian128(value)) as Bytes32;
}

export function ownerHash(
  ownerPublicKeyField: Uint8Array,
  nullifierPublicKey: Uint8Array,
): Uint8Array {
  return poseidon([ownerPublicKeyField, nullifierPublicKey]);
}

/**
 * The one boundary a TypeScript-only code belongs at: Rust's `pack33` takes
 * `&[u8; 33]` and cannot fail, so a wrong-length input has no Rust variant to
 * mirror.
 */
export function pack33(bytes: Uint8Array): readonly [Uint8Array, Uint8Array] {
  try {
    return interfacePack33(bytes);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_HASH", error);
  }
}

export function sha256Bytes(bytes: Uint8Array): Bytes32 {
  return sha256(bytes) as Bytes32;
}

export function sha256Be(bytes: Uint8Array): Bytes32 {
  const digest = sha256(bytes);
  digest[0] = 0;
  return digest as Bytes32;
}

