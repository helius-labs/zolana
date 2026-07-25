import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants, poseidon as createPoseidon } from "@noble/curves/abstract/poseidon.js";

import { InterfaceError } from "./errors.js";
import { copyBytes } from "./internal.js";
import type { Bytes32 } from "./index.js";

const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65] as const;
const Fp = Field(BN254_MODULUS);
const permutations = new Map<number, ReturnType<typeof createPoseidon>>();

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value: bigint): Bytes32 {
  const bytes = new Uint8Array(32);
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes as Bytes32;
}

function permutation(inputCount: number): ReturnType<typeof createPoseidon> {
  const cached = permutations.get(inputCount);
  if (cached !== undefined) return cached;
  const roundsPartial = PARTIAL_ROUNDS[inputCount - 1];
  if (roundsPartial === undefined) {
    throw new InterfaceError("INTERFACE_HASH", {
      inputCount,
      minimum: 1,
      maximum: PARTIAL_ROUNDS.length,
    });
  }
  const options = {
    Fp,
    t: inputCount + 1,
    roundsFull: 8,
    roundsPartial,
    sboxPower: 5,
  } as const;
  const generated = createPoseidon({ ...options, ...grainGenConstants(options) });
  permutations.set(inputCount, generated);
  return generated;
}

function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  const values = inputs.map((input, index) => {
    const value = bytesToBigInt(input);
    if (input.length > 32 || value >= BN254_MODULUS) {
      throw new InterfaceError("INTERFACE_HASH", { index, length: input.length });
    }
    return value;
  });
  const result = permutation(values.length)([0n, ...values])[0];
  if (result === undefined) throw new InterfaceError("INTERFACE_HASH");
  return bigIntToBytes(result);
}

function rightAlign(bytes: Uint8Array): Bytes32 {
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
