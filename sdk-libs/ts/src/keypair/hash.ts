import { sha256 } from "@noble/hashes/sha2.js";

import { type Bytes32 } from "./bytes.js";
import { poseidon } from "./poseidon.js";

export function ownerHash(
  ownerProofInputHash: Uint8Array,
  nullifierPublicKey: Uint8Array,
): Uint8Array {
  return poseidon([ownerProofInputHash, nullifierPublicKey]);
}

export function sha256Bytes(bytes: Uint8Array): Bytes32 {
  return sha256(bytes) as Bytes32;
}

export function sha256Be(bytes: Uint8Array): Bytes32 {
  const digest = sha256(bytes);
  digest[0] = 0;
  return digest as Bytes32;
}
