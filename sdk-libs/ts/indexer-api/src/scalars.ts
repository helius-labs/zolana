import type { Address, Bytes32, Signature } from "@zolana/interface";

import type { Base64String, Hash, Limit } from "./types.js";

export const MIN_PAGE_LIMIT = 1n;
export const PAGE_LIMIT = 1000n;

export type IndexerSchemaErrorCode = `INDEXER_SCHEMA_${string}`;

export class IndexerSchemaError extends Error {
  readonly code: IndexerSchemaErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: IndexerSchemaErrorCode,
    message: string,
    options: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }> = {},
  ) {
    super(message);
    this.name = "IndexerSchemaError";
    this.code = code;
    if (options.details !== undefined) this.details = options.details;
    if (options.cause !== undefined) this.cause = options.cause;
  }
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function fail(
  code: IndexerSchemaErrorCode,
  path: string,
  expected: string,
  actual?: unknown,
): never {
  const details: Record<string, unknown> = { path, expected };
  if (actual !== undefined) details["actual"] = describeActual(actual);
  throw new IndexerSchemaError(code, `Invalid value at ${path}`, { details });
}

function describeActual(value: unknown): unknown {
  if (typeof value === "string") return { type: "string", length: value.length };
  if (typeof value === "bigint") return { type: "bigint", value: value.toString() };
  if (value instanceof Uint8Array) return { type: "Uint8Array", length: value.length };
  if (Array.isArray(value)) return { type: "array", length: value.length };
  if (value === null) return { type: "null" };
  if (typeof value === "object") return { type: "object" };
  return value;
}

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      const value = (digits[index] ?? 0) * 256 + carry;
      digits[index] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let encoded = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded += "1";
  }
  const hasOnlyZeroBytes = encoded.length === bytes.length;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    if (hasOnlyZeroBytes && index === 0) continue;
    encoded += BASE58_ALPHABET.charAt(digits[index] ?? 0);
  }
  return encoded;
}

function decodeBase58(value: string): Uint8Array | undefined {
  if (value.length === 0) return undefined;
  const bytes = [0];
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) return undefined;
    let carry = digit;
    for (let index = 0; index < bytes.length; index += 1) {
      const next = (bytes[index] ?? 0) * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >>> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>>= 8;
    }
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === "1") {
    leadingZeroes += 1;
  }
  const decoded = new Uint8Array(leadingZeroes + bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    decoded[decoded.length - 1 - index] = bytes[index] ?? 0;
  }
  if (leadingZeroes > 0 && bytes.length === 1 && bytes[0] === 0) {
    return decoded.slice(0, -1);
  }
  return decoded;
}

function encodeBase64(bytes: Uint8Array): string {
  let encoded = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const bits = (first << 16) | (second << 8) | third;
    encoded += BASE64_ALPHABET.charAt((bits >>> 18) & 63);
    encoded += BASE64_ALPHABET.charAt((bits >>> 12) & 63);
    encoded += index + 1 < bytes.length ? BASE64_ALPHABET.charAt((bits >>> 6) & 63) : "=";
    encoded += index + 2 < bytes.length ? BASE64_ALPHABET.charAt(bits & 63) : "=";
  }
  return encoded;
}

function decodeBase64(value: string, path: string): Uint8Array {
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  const bytes = new Uint8Array((value.length / 4) * 3 - padding);
  let outputIndex = 0;
  for (let index = 0; index < value.length; index += 4) {
    const a = BASE64_ALPHABET.indexOf(value[index] ?? "");
    const b = BASE64_ALPHABET.indexOf(value[index + 1] ?? "");
    const c = value[index + 2] === "=" ? 0 : BASE64_ALPHABET.indexOf(value[index + 2] ?? "");
    const d = value[index + 3] === "=" ? 0 : BASE64_ALPHABET.indexOf(value[index + 3] ?? "");
    const bits = (a << 18) | (b << 12) | (c << 6) | d;
    if (outputIndex < bytes.length) bytes[outputIndex++] = (bits >>> 16) & 0xff;
    if (outputIndex < bytes.length) bytes[outputIndex++] = (bits >>> 8) & 0xff;
    if (outputIndex < bytes.length) bytes[outputIndex++] = bits & 0xff;
  }
  if (encodeBase64(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
  }
  return bytes;
}

export function base64String(value: string | Uint8Array): Base64String {
  if (typeof value === "string") {
    decodeBase64(value, "$");
    return value as Base64String;
  }
  if (!(value instanceof Uint8Array)) {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", "$", "a string or Uint8Array", value);
  }
  return encodeBase64(value) as Base64String;
}

export function hash(value: string | Bytes32): Hash {
  if (typeof value !== "string") {
    if (!(value instanceof Uint8Array) || value.length !== 32) {
      return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "exactly 32 bytes", value);
    }
    return encodeBase58(value) as Hash;
  }
  const bytes = value.length <= 44 ? decodeBase58(value) : undefined;
  if (bytes === undefined || bytes.length !== 32 || encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "a base58 encoded 32-byte hash", value);
  }
  return value as Hash;
}

export function hashBytes(value: Hash): Bytes32 {
  if (typeof value !== "string") {
    return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "a base58 encoded 32-byte hash", value);
  }
  const bytes = decodeBase58(value);
  if (bytes === undefined || bytes.length !== 32 || encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "a base58 encoded 32-byte hash", value);
  }
  return bytes as Bytes32;
}

export function limit(value: bigint): Limit {
  if (typeof value !== "bigint" || value < MIN_PAGE_LIMIT || value > PAGE_LIMIT) {
    return fail("INDEXER_SCHEMA_INVALID_LIMIT", "$", "an integer from 1 through 1000", value);
  }
  return value as Limit;
}

export function checkedHash(value: unknown, path: string): Hash {
  if (typeof value !== "string") {
    return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
  }
  try {
    return hash(value);
  } catch (error) {
    if (error instanceof IndexerSchemaError) {
      return fail(error.code, path, "a base58 encoded 32-byte hash", value);
    }
    throw error;
  }
}

export function checkedBase64(value: unknown, path: string): Base64String {
  if (typeof value !== "string") {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
  }
  try {
    return base64String(value);
  } catch (error) {
    if (error instanceof IndexerSchemaError) {
      return fail(error.code, path, "canonical base64", value);
    }
    throw error;
  }
}

export function checkedAddress(value: unknown, path: string): Address {
  if (typeof value !== "string" || value.length > 44) {
    return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
  }
  const bytes = decodeBase58(value);
  if (bytes === undefined || bytes.length !== 32 || encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
  }
  return value as Address;
}

export function checkedSignature(value: unknown, path: string): Signature {
  if (typeof value !== "string" || value.length > 88) {
    return fail("INDEXER_SCHEMA_INVALID_SIGNATURE", path, "a base58 encoded signature", value);
  }
  const bytes = decodeBase58(value);
  if (bytes === undefined || bytes.length !== 64 || encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_SIGNATURE", path, "a base58 encoded signature", value);
  }
  return value as Signature;
}

export function schemaFailure(
  code: IndexerSchemaErrorCode,
  path: string,
  expected: string,
  actual?: unknown,
): never {
  return fail(code, path, expected, actual);
}
