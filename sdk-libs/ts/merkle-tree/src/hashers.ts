import { bn254_Fr } from "@noble/curves/bn254.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { poseidon } from "@zolana/hasher";

import { bytes32, type Bytes32 } from "./bytes.js";
import type { Hasher32 } from "./merkle-tree.js";

export interface Hasher32WithBytes extends Hasher32 {
  hashBytes(value: Bytes32): Bytes32;
}

// The tree checks the field bound itself rather than reading it off the
// rejection: a leaf at or above the modulus is a caller error worth naming,
// and the message is part of this package's surface.
function checkedField(value: Bytes32, name: string): Bytes32 {
  const checked = bytes32(value, name);
  let result = 0n;
  for (const byte of checked) {
    result = (result << 8n) | BigInt(byte);
  }
  if (result >= bn254_Fr.ORDER) {
    throw new Error("Poseidon input exceeds the BN254 scalar field");
  }
  return checked;
}

function createDigestAdapter(digest: typeof sha256 | typeof keccak_256): Hasher32WithBytes {
  return {
    hash(left, right) {
      const state = digest.create();
      state.update(bytes32(left, "left"));
      state.update(bytes32(right, "right"));
      return bytes32(state.digest(), "hash");
    },
    hashBytes(value) {
      return bytes32(digest(bytes32(value, "value")), "hash");
    },
  };
}

export const poseidonHasher: Hasher32WithBytes = {
  hash(left, right) {
    return poseidon([checkedField(left, "left"), checkedField(right, "right")]) as Bytes32;
  },
  hashBytes(value) {
    return poseidon([checkedField(value, "value")]) as Bytes32;
  },
};

export const sha256Hasher = createDigestAdapter(sha256);
export const keccakHasher = createDigestAdapter(keccak_256);
