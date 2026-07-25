import { InterfaceError } from "./errors.js";
import type { Address } from "./index.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map(Array.from(BASE58_ALPHABET, (character, index) => [character, index]));
const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

export function fail(
  code: InterfaceError["code"],
  details?: Readonly<Record<string, unknown>>,
  cause?: unknown,
): never {
  throw new InterfaceError(code, details, cause);
}

export function copyBytes(value: Uint8Array, length?: number, name = "bytes"): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: "non-bytes" });
  }
  if (length !== undefined && value.length !== length) {
    fail("INTERFACE_INVALID_LENGTH", { name, expected: length, actual: value.length });
  }
  return value.slice();
}

export function unsigned(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", { name, minimum: 0, maximum, actual: value });
  }
  return value;
}

export function unsignedBigint(value: bigint, maximum: bigint, name: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", {
      name,
      minimum: "0",
      maximum: maximum.toString(),
      actual: String(value),
    });
  }
  return value;
}

export function signedBigint(
  value: bigint,
  minimum: bigint,
  maximum: bigint,
  name: string,
): bigint {
  if (typeof value !== "bigint" || value < minimum || value > maximum) {
    fail("INTERFACE_INVALID_INTEGER", {
      name,
      minimum: minimum.toString(),
      maximum: maximum.toString(),
      actual: String(value),
    });
  }
  return value;
}

export function addressBytes(value: Address, name = "address"): Uint8Array {
  if (typeof value !== "string") {
    fail("INTERFACE_INVALID_ADDRESS", { name, actual: typeof value });
  }
  const bytes = decodeBase58(value);
  if (bytes.length !== 32 || encodeBase58(bytes) !== value) {
    fail("INTERFACE_INVALID_ADDRESS", { name, actual: value });
  }
  return bytes;
}

export function checkedAddress(value: string, name = "address"): Address {
  addressBytes(value as Address, name);
  return value as Address;
}

export function encodeBase58(bytes: Uint8Array): Address {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let encoded = "";
  while (value > 0n) {
    encoded = arrayValue(BASE58_ALPHABET, Number(value % 58n)) + encoded;
    value /= 58n;
  }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  return ("1".repeat(zeros) + encoded) as Address;
}

function decodeBase58(value: string): Uint8Array {
  if (value.length === 0 || value.length > 44) {
    fail("INTERFACE_INVALID_ADDRESS", { actual: value });
  }
  let decoded = 0n;
  for (const character of value) {
    const digit = BASE58_INDEX.get(character);
    if (digit === undefined) fail("INTERFACE_INVALID_ADDRESS", { actual: value });
    decoded = decoded * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.push(Number(decoded & 255n));
    decoded >>= 8n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}

export function findProgramAddress(
  seeds: readonly Uint8Array[],
  program: Address,
): readonly [Address, number] {
  for (let bump = 255; bump >= 0; bump -= 1) {
    const address = createProgramAddress([...seeds, Uint8Array.of(bump)], program);
    if (address !== undefined) return [address, bump];
  }
  fail("INTERFACE_INVALID_PDA", { reason: "no viable bump" });
}

function createProgramAddress(seeds: readonly Uint8Array[], program: Address): Address | undefined {
  if (seeds.length > 16 || seeds.some((seed) => seed.length > 32)) {
    fail("INTERFACE_INVALID_PDA", { reason: "seed bounds" });
  }
  const digest = sha256(concat([...seeds, addressBytes(program), PDA_MARKER]));
  return isEd25519Point(digest) ? undefined : encodeBase58(digest);
}

function isEd25519Point(bytes: Uint8Array): boolean {
  const p = (1n << 255n) - 19n;
  const d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
  const sign = arrayValue(bytes, 31) >>> 7;
  const yBytes = bytes.slice();
  yBytes[31] = arrayValue(yBytes, 31) & 0x7f;
  let y = 0n;
  for (let index = 31; index >= 0; index -= 1) {
    y = (y << 8n) | BigInt(arrayValue(yBytes, index));
  }
  if (y >= p) return false;
  const y2 = mod(y * y, p);
  const x2 = mod((y2 - 1n) * invert(mod(d * y2 + 1n, p), p), p);
  const x = modPow(x2, (p + 3n) / 8n, p);
  const root =
    mod(x * x, p) === x2
      ? x
      : mod(x * 19681161376707505956807079304988542015446066515923890162744021073123829784752n, p);
  return mod(root * root, p) === x2 && (root !== 0n || sign === 0);
}

function invert(value: bigint, modulus: bigint): bigint {
  return modPow(value, modulus - 2n, modulus);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let current = mod(base, modulus);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = mod(result * current, modulus);
    current = mod(current * current, modulus);
    remaining >>= 1n;
  }
  return result;
}

function mod(value: bigint, modulus: bigint): bigint {
  const reduced = value % modulus;
  return reduced < 0n ? reduced + modulus : reduced;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function arrayValue<T>(values: ArrayLike<T>, index: number): T {
  const value = values[index];
  if (value === undefined) {
    fail("INTERFACE_CODEC", { reason: "internal index out of bounds", index });
  }
  return value;
}

export function sha256(input: Uint8Array): Uint8Array {
  const constants = Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const bitLength = BigInt(input.length) * 8n;
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x80;
  for (let index = 0; index < 8; index += 1) {
    padded[padded.length - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 255n);
  }
  const hash = Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const words = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      const at = offset + index * 4;
      words[index] =
        (arrayValue(padded, at) << 24) |
        (arrayValue(padded, at + 1) << 16) |
        (arrayValue(padded, at + 2) << 8) |
        arrayValue(padded, at + 3);
    }
    for (let index = 16; index < 64; index += 1) {
      const x = arrayValue(words, index - 15);
      const y = arrayValue(words, index - 2);
      const s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3);
      const s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10);
      words[index] = (arrayValue(words, index - 16) + s0 + arrayValue(words, index - 7) + s1) >>> 0;
    }
    let a = arrayValue(hash, 0);
    let b = arrayValue(hash, 1);
    let c = arrayValue(hash, 2);
    let d0 = arrayValue(hash, 3);
    let e = arrayValue(hash, 4);
    let f = arrayValue(hash, 5);
    let g = arrayValue(hash, 6);
    let h = arrayValue(hash, 7);
    for (let index = 0; index < 64; index += 1) {
      const s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temporary1 =
        (h + s1 + choice + arrayValue(constants, index) + arrayValue(words, index)) >>> 0;
      const s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (s0 + majority) >>> 0;
      [a, b, c, d0, e, f, g, h] = [
        (temporary1 + temporary2) >>> 0,
        a,
        b,
        c,
        (d0 + temporary1) >>> 0,
        e,
        f,
        g,
      ];
    }
    const state = [a, b, c, d0, e, f, g, h];
    for (let index = 0; index < 8; index += 1) {
      hash[index] = (arrayValue(hash, index) + arrayValue(state, index)) >>> 0;
    }
  }
  const output = new Uint8Array(32);
  for (let index = 0; index < 8; index += 1) {
    const value = arrayValue(hash, index);
    output[index * 4] = value >>> 24;
    output[index * 4 + 1] = value >>> 16;
    output[index * 4 + 2] = value >>> 8;
    output[index * 4 + 3] = value;
  }
  return output;
}

function rotate(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits));
}

export class Writer {
  readonly #bytes: number[] = [];

  bytes(value: Uint8Array, length?: number, name?: string): this {
    this.#bytes.push(...copyBytes(value, length, name));
    return this;
  }

  u8(value: number, name: string): this {
    this.#bytes.push(unsigned(value, 0xff, name));
    return this;
  }

  bool(value: boolean, name: string): this {
    if (typeof value !== "boolean") fail("INTERFACE_CODEC", { name, actual: value });
    this.#bytes.push(value ? 1 : 0);
    return this;
  }

  u16(value: number, name: string): this {
    const checked = unsigned(value, 0xffff, name);
    this.#bytes.push(checked & 255, checked >>> 8);
    return this;
  }

  u32(value: number, name: string): this {
    const checked = unsigned(value, 0xffffffff, name);
    this.#bytes.push(checked & 255, (checked >>> 8) & 255, (checked >>> 16) & 255, checked >>> 24);
    return this;
  }

  u64(value: bigint, name: string): this {
    return this.integer(unsignedBigint(value, (1n << 64n) - 1n, name), 8);
  }

  i64(value: bigint, name: string): this {
    const checked = signedBigint(value, -(1n << 63n), (1n << 63n) - 1n, name);
    return this.integer(checked < 0n ? checked + (1n << 64n) : checked, 8);
  }

  option<T>(value: T | undefined, write: (writer: Writer, value: T) => void): this {
    this.bool(value !== undefined, "option");
    if (value !== undefined) write(this, value);
    return this;
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.#bytes);
  }

  private integer(value: bigint, length: number): this {
    for (let index = 0; index < length; index += 1) {
      this.#bytes.push(Number((value >> BigInt(index * 8)) & 255n));
    }
    return this;
  }
}

export class Reader {
  #offset = 0;

  constructor(private readonly input: Uint8Array) {
    copyBytes(input);
  }

  bytes(length: number, name: string): Uint8Array {
    const end = this.#offset + length;
    if (!Number.isSafeInteger(length) || length < 0 || end > this.input.length) {
      fail("INTERFACE_CODEC", {
        name,
        offset: this.#offset,
        expected: length,
        remaining: this.input.length - this.#offset,
      });
    }
    const value = this.input.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  u8(name: string): number {
    return arrayValue(this.bytes(1, name), 0);
  }

  bool(name: string): boolean {
    const value = this.u8(name);
    if (value !== 0 && value !== 1) fail("INTERFACE_CODEC", { name, actual: value });
    return value === 1;
  }

  nonzeroBool(name: string): boolean {
    return this.u8(name) !== 0;
  }

  u16(name: string): number {
    const value = this.bytes(2, name);
    return arrayValue(value, 0) | (arrayValue(value, 1) << 8);
  }

  u32(name: string): number {
    const value = this.bytes(4, name);
    return (
      arrayValue(value, 0) +
      arrayValue(value, 1) * 0x100 +
      arrayValue(value, 2) * 0x10000 +
      arrayValue(value, 3) * 0x1000000
    );
  }

  u64(name: string): bigint {
    return this.integer(8, name);
  }

  i64(name: string): bigint {
    const value = this.integer(8, name);
    return value >= 1n << 63n ? value - (1n << 64n) : value;
  }

  option<T>(name: string, read: (reader: Reader) => T): T | undefined {
    return this.bool(name) ? read(this) : undefined;
  }

  done(): void {
    if (this.#offset !== this.input.length) {
      fail("INTERFACE_CODEC", {
        reason: "trailing bytes",
        offset: this.#offset,
        length: this.input.length,
      });
    }
  }

  private integer(length: number, name: string): bigint {
    const value = this.bytes(length, name);
    let result = 0n;
    for (let index = value.length - 1; index >= 0; index -= 1) {
      result = (result << 8n) | BigInt(arrayValue(value, index));
    }
    return result;
  }
}
