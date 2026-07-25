import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants, poseidon as createPoseidon } from "@noble/curves/abstract/poseidon.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
export { hashField, sha256Be } from "@zolana/keypair/hash";

import { TransactionError } from "./error.js";

const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
// Circom x5 partial-round counts for widths 2 through 13, stopping at twelve
// inputs to match the Rust hasher: `light_poseidon` caps the width at 13 and
// the `sol_poseidon` syscall takes at most twelve inputs.
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65] as const;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FIELD = Field(BN254_MODULUS);
const permutations = new Map<number, ReturnType<typeof createPoseidon>>();

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

function permutation(inputCount: number): ReturnType<typeof createPoseidon> {
  const cached = permutations.get(inputCount);
  if (cached) return cached;
  const roundsPartial = PARTIAL_ROUNDS[inputCount - 1];
  if (roundsPartial === undefined) {
    throw new TransactionError("TRANSACTION_HASH", { inputCount });
  }
  const options = {
    Fp: FIELD,
    t: inputCount + 1,
    roundsFull: 8,
    roundsPartial,
    sboxPower: 5,
  } as const;
  const generated = createPoseidon({ ...options, ...grainGenConstants(options) });
  permutations.set(inputCount, generated);
  return generated;
}

export function poseidon(inputs: readonly Uint8Array[]): Bytes32 {
  const values = inputs.map((input, index) => {
    const value = bytesToBigInt(input);
    if (input.length > 32 || value >= BN254_MODULUS) {
      throw new TransactionError("TRANSACTION_HASH", { index, reason: "invalidField" });
    }
    return value;
  });
  const result = permutation(values.length)([0n, ...values])[0];
  if (result === undefined) throw new TransactionError("TRANSACTION_HASH");
  return bigIntBytes(result) as Bytes32;
}

export function hashChain(values: readonly Bytes32[]): Bytes32 {
  const [first, ...remaining] = values;
  if (!first) return copy(ZERO_32);
  let hash = copy(first);
  for (const value of remaining) hash = poseidon([hash, value]);
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

export function random31(): Bytes31 {
  const output = new Uint8Array(31);
  globalThis.crypto.getRandomValues(output);
  return output as Bytes31;
}

export function random16(): Bytes16 {
  const output = new Uint8Array(16);
  globalThis.crypto.getRandomValues(output);
  return output as Bytes16;
}

export function decodeAddress(address: Address): Bytes32 {
  let value = 0n;
  for (const character of address) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { address });
    value = value * 58n + BigInt(digit);
  }
  const decoded: number[] = [];
  while (value > 0n) {
    decoded.push(Number(value & 0xffn));
    value >>= 8n;
  }
  for (const character of address) {
    if (character !== "1") break;
    decoded.push(0);
  }
  decoded.reverse();
  return checked<Bytes32>(Uint8Array.from(decoded), 32, "address");
}

export function encodeAddress(bytes: Uint8Array): Address {
  const input = checked<Bytes32>(bytes, 32, "address");
  let value = bytesToBigInt(input);
  let output = "";
  while (value > 0n) {
    output = BASE58.charAt(Number(value % 58n)) + output;
    value /= 58n;
  }
  for (const byte of input) {
    if (byte !== 0) break;
    output = `1${output}`;
  }
  return (output || "1") as Address;
}

export function checked33(bytes: Uint8Array): Bytes33 {
  return checked<Bytes33>(bytes, 33, "public key");
}
