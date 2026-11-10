import { MAX_POSEIDON_INPUTS, poseidonOr } from "../hasher/index.js";

import { InterfaceError } from "./errors.js";
import { copyBytes } from "./internal.js";
import type { Bytes32 } from "./types.js";
import { rightAlign } from "./bytes.js";

/** The hasher's `poseidon`, rejecting an input as the `INTERFACE_HASH` its callers catch. */
export function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  return poseidonOr(inputs, (failure) => {
    if (failure.code === "NotInitialized") return failure;
    const { inputCount, index, length } = failure.details;
    return new InterfaceError(
      "INTERFACE_HASH",
      inputCount === undefined
        ? { index, length }
        : { inputCount, minimum: 1, maximum: MAX_POSEIDON_INPUTS },
    );
  }) as Bytes32;
}

function checkedCompressedKey(compressed: Uint8Array): Uint8Array {
  const key = copyBytes(compressed, 33, "compressedPublicKey");
  if (key[0] !== 0x02 && key[0] !== 0x03) {
    throw new InterfaceError("INTERFACE_CODEC", {
      name: "compressedPublicKeyPrefix",
      actual: key[0],
    });
  }
  return key;
}

function xHash(compressed: Uint8Array): Bytes32 {
  const x = compressed.subarray(1);
  return poseidon([rightAlign(x.subarray(16)), rightAlign(x.subarray(0, 16))]);
}

export function pkFieldCompressed(compressed: Uint8Array): Bytes32 {
  const key = checkedCompressedKey(compressed);
  return poseidon([rightAlign(Uint8Array.of(key[0] === 0x03 ? 1 : 0)), xHash(key)]);
}

export function ownerPkFieldCompressed(compressed: Uint8Array): Bytes32 {
  return xHash(checkedCompressedKey(compressed));
}

export function pack33(bytes: Uint8Array): readonly [Bytes32, Bytes32] {
  const input = copyBytes(bytes, 33, "bytes");
  const low = new Uint8Array(32);
  low.set(input.subarray(0, 31), 1);
  const high = new Uint8Array(32);
  high.set(input.subarray(31), 30);
  return Object.freeze([low as Bytes32, high as Bytes32]);
}

export function ciphertextHash(ciphertext: Uint8Array): Bytes32 {
  const bytes = copyBytes(ciphertext);
  const chunks: Bytes32[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    chunks.push(rightAlign(bytes.subarray(offset, offset + 16)));
  }
  return poseidon(chunks);
}
