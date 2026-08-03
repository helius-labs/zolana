import { sha256 } from "@noble/hashes/sha2.js";
import { getAddressDecoder, getAddressEncoder, getBase58Encoder } from "@solana/kit";
import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/index.js";

import type { Address, Bytes16, Bytes32, Bytes33 } from "../interface/types.js";
export { hashField, sha256Be } from "../keypair/hash.js";

import { TransactionError, type TransactionErrorCode } from "./error.js";

const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
const base58Encoder = getBase58Encoder();

export const ZERO_32 = new Uint8Array(32) as Bytes32;
export const U64_MAX = 0xffff_ffff_ffff_ffffn;

export function copy<T extends Uint8Array>(bytes: T): T {
  return new Uint8Array(bytes) as T;
}

export function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left.at(index) ?? 0) ^ (right.at(index) ?? 0);
  }
  return difference === 0;
}

export function checked<T extends Uint8Array>(
  bytes: Uint8Array | T,
  length: number,
  name: string,
): T {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      name,
      expected: length,
      actual: bytes instanceof Uint8Array ? bytes.length : -1,
    });
  }
  return new Uint8Array(bytes) as T;
}

export function checkU64(value: bigint, name: string): bigint {
  if (value < 0n || value > U64_MAX) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      name,
      minimum: "0",
      maximum: U64_MAX.toString(),
      actual: value.toString(),
    });
  }
  return value;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigIntBytes(value: bigint, length = 32): Uint8Array {
  const output = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index--) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

export function rightAlign(bytes: Uint8Array): Bytes32 {
  if (bytes.length > 32) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMaximum: 32,
      actual: bytes.length,
    });
  }
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}

function hashFields(inputs: readonly Uint8Array[], code: TransactionErrorCode): Bytes32 {
  if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
    throw new TransactionError(code, { inputCount: inputs.length });
  }
  inputs.forEach((input, index) => {
    if (input.length > 32 || bytesToBigInt(input) >= BN254_MODULUS) {
      throw new TransactionError(code, { index, reason: "invalidField" });
    }
  });
  return hash(inputs) as Bytes32;
}

export function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  return hashFields(inputs, "TRANSACTION_KEYPAIR");
}

export function commitmentPoseidon(inputs: readonly Uint8Array[]): Bytes32 {
  return hashFields(inputs, "TRANSACTION_POSEIDON");
}

export function hashChain(values: readonly Bytes32[]): Bytes32 {
  const [first, ...remaining] = values;
  if (!first) return copy(ZERO_32);
  let hash = copy(first);
  for (const value of remaining) hash = poseidon([hash, value]);
  return hash;
}

export function rightHashChain(values: readonly Bytes32[]): Bytes32 {
  const last = values.at(-1);
  if (!last) return copy(ZERO_32);
  let hash = copy(last);
  for (let index = values.length - 2; index >= 0; index -= 1) {
    hash = poseidon([values[index] as Bytes32, hash]);
  }
  return hash;
}

export function sha256Bytes(bytes: Uint8Array): Bytes32 {
  return sha256(bytes) as Bytes32;
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function random16(): Bytes16 {
  const output = new Uint8Array(16);
  globalThis.crypto.getRandomValues(output);
  return output as Bytes16;
}

export function decodeAddress(address: Address): Bytes32 {
  try {
    return new Uint8Array(addressEncoder.encode(address)) as Bytes32;
  } catch (cause) {
    try {
      return checked<Bytes32>(new Uint8Array(base58Encoder.encode(address)), 32, "address");
    } catch (fallbackCause) {
      if (fallbackCause instanceof TransactionError) throw fallbackCause;
      throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { address }, cause);
    }
  }
}

export function encodeAddress(bytes: Uint8Array): Address {
  const input = checked<Bytes32>(bytes, 32, "address");
  return addressDecoder.decode(input);
}

export function checked33(bytes: Uint8Array): Bytes33 {
  return checked<Bytes33>(bytes, 33, "public key");
}
