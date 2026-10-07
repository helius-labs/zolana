import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/index.js";

import { MERGE_CIPHERTEXT_LENGTH } from "./constants.js";
import { InterfaceError } from "./errors.js";
import { copyBytes } from "./internal.js";
import type { Bytes32 } from "./types.js";

const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

// The bounds are checked here rather than left to the module so a rejection
// still arrives as the `INTERFACE_HASH` its callers catch, with the detail that
// says which input was wrong.
export function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw new InterfaceError("INTERFACE_HASH", {
      inputCount: inputs.length,
      minimum: 1,
      maximum: MAX_POSEIDON_INPUTS,
    });
  }
  inputs.forEach((input, index) => {
    if (input.length > 32 || bytesToBigInt(input) >= BN254_MODULUS) {
      throw new InterfaceError("INTERFACE_HASH", { index, length: input.length });
    }
  });
  return hash(inputs) as Bytes32;
}

export function rightAlign(bytes: Uint8Array): Bytes32 {
  const result = new Uint8Array(32);
  result.set(bytes, 32 - bytes.length);
  return result as Bytes32;
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

const PACK_BE_CHUNK_BYTES = 31;

function packChunk(bytes: Uint8Array, index: number): Bytes32 {
  return rightAlign(bytes.subarray(index * PACK_BE_CHUNK_BYTES, (index + 1) * PACK_BE_CHUNK_BYTES));
}

export function pack32(bytes: Uint8Array): readonly [Bytes32, Bytes32] {
  const input = copyBytes(bytes, 32, "bytes");
  try {
    return Object.freeze([packChunk(input, 0), packChunk(input, 1)]);
  } finally {
    input.fill(0);
  }
}

export function pack33(bytes: Uint8Array): readonly [Bytes32, Bytes32] {
  const input = copyBytes(bytes, 33, "bytes");
  return Object.freeze([packChunk(input, 0), packChunk(input, 1)]);
}

export function mergeEnvelopePublicElements(
  recipient: Uint8Array,
  ephemeral: Uint8Array,
  ciphertext: Uint8Array,
): readonly [Bytes32, Bytes32, Bytes32, Bytes32] {
  const recipientKey = checkedCompressedKey(recipient);
  const ephemeralKey = checkedCompressedKey(ephemeral);
  const encrypted = copyBytes(ciphertext, MERGE_CIPHERTEXT_LENGTH, "ciphertext");
  const packed = Uint8Array.of(
    ...recipientKey.subarray(0, PACK_BE_CHUNK_BYTES),
    ...ephemeralKey.subarray(0, PACK_BE_CHUNK_BYTES),
    ...recipientKey.subarray(PACK_BE_CHUNK_BYTES),
    ...ephemeralKey.subarray(PACK_BE_CHUNK_BYTES),
    ...encrypted,
  );
  return Object.freeze([
    packChunk(packed, 0),
    packChunk(packed, 1),
    packChunk(packed, 2),
    packChunk(packed, 3),
  ]);
}

export function ciphertextHash(ciphertext: Uint8Array): Bytes32 {
  const bytes = copyBytes(ciphertext);
  const chunks: Bytes32[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    chunks.push(rightAlign(bytes.subarray(offset, offset + 16)));
  }
  return poseidon(chunks);
}
