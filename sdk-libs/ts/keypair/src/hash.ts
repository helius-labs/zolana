import { sha256 } from "@noble/hashes/sha2.js";

import { bigIntToBytes, bytesToBigInt } from "./bytes.js";
import { poseidon } from "./poseidon.js";

export function splitBigEndian128(value: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const low = new Uint8Array(32);
  const high = new Uint8Array(32);
  high.set(value.subarray(0, 16), 16);
  low.set(value.subarray(16, 32), 16);
  return [low, high];
}

export function hashField(value: Uint8Array): Uint8Array {
  return poseidon(splitBigEndian128(value));
}

export function hashPublicKeyX(x: Uint8Array, yIsOdd: boolean): Uint8Array {
  return poseidon([bigIntToBytes(yIsOdd ? 1n : 0n), hashField(x)]);
}

export function ownerHash(
  ownerPublicKeyField: Uint8Array,
  nullifierPublicKey: Uint8Array,
): Uint8Array {
  return poseidon([ownerPublicKeyField, nullifierPublicKey]);
}

export function pack33(bytes: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const low = new Uint8Array(32);
  low.set(bytes.subarray(0, 31), 1);
  const high = new Uint8Array(32);
  high.set(bytes.subarray(31), 30);
  return [low, high];
}

export function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return sha256(bytes);
}

export function fieldFromBytes(bytes: Uint8Array): Uint8Array {
  return bigIntToBytes(bytesToBigInt(bytes));
}
