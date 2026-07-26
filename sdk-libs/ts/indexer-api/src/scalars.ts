import type { Address, Bytes32, Signature } from "@zolana/interface";
import {
  decodeBase58 as decodeBase58Canonical,
  decodeBase64 as decodeBase64Canonical,
  encodeBase58 as encodeBase58Canonical,
  encodeBase64 as encodeBase64Canonical,
} from "@zolana/interface";

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

/** Max Bitcoin-base58 length of a 32-byte payload. */
const MAX_BASE58_32_LEN = 44;
/** Max Bitcoin-base58 length of a 64-byte signature. */
const MAX_BASE58_64_LEN = 88;

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
  return encodeBase58Canonical(bytes);
}

function decodeBase58(value: string): Uint8Array | undefined {
  try {
    return decodeBase58Canonical(value);
  } catch {
    return undefined;
  }
}

function encodeBase64(bytes: Uint8Array): string {
  return encodeBase64Canonical(bytes);
}

function decodeBase64(value: string, path: string): Uint8Array {
  try {
    return decodeBase64Canonical(value);
  } catch {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
  }
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

/**
 * Byte view of a wire payload, the counterpart of `base64String`.
 *
 * Rust's `Base64String` holds `Vec<u8>` and encodes only at the serde boundary,
 * so `From<Base64String> for Vec<u8>` is free there. The port brands the wire
 * string instead, which left callers no way back to the bytes except a decoder
 * that does not enforce the canonical form this package requires.
 */
export function base64Bytes(value: Base64String): Uint8Array {
  if (typeof value !== "string") {
    return fail("INDEXER_SCHEMA_INVALID_BASE64", "$", "canonical base64", value);
  }
  return decodeBase64(value, "$");
}

/**
 * Distinguish the two failures Rust's `ParseHashError` names: a length the
 * encoding cannot carry (`WrongSize`) against input outside the base58
 * alphabet (`Invalid`). Rust reports the over-long string and the wrongly
 * sized decode as the same `WrongSize`, so both map to the same code here.
 */
function parseHash(value: string, path: string): Uint8Array {
  if (value.length > MAX_BASE58_32_LEN) {
    return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", path, "a base58 encoded 32-byte hash", value);
  }
  const bytes = decodeBase58(value);
  if (bytes === undefined) {
    return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
  }
  if (bytes.length !== 32) {
    return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", path, "a base58 encoded 32-byte hash", value);
  }
  if (encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
  }
  return bytes;
}

export function hash(value: string | Bytes32): Hash {
  if (typeof value !== "string") {
    if (!(value instanceof Uint8Array)) {
      return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "exactly 32 bytes", value);
    }
    if (value.length !== 32) {
      return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", "$", "exactly 32 bytes", value);
    }
    return encodeBase58(value) as Hash;
  }
  parseHash(value, "$");
  return value as Hash;
}

export function hashBytes(value: Hash): Bytes32 {
  if (typeof value !== "string") {
    return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "a base58 encoded 32-byte hash", value);
  }
  return parseHash(value, "$") as Bytes32;
}

export function limit(value: bigint): Limit {
  if (typeof value !== "bigint" || value < MIN_PAGE_LIMIT || value > PAGE_LIMIT) {
    return fail(
      "INDEXER_SCHEMA_INVALID_LIMIT",
      "$",
      `an integer from ${MIN_PAGE_LIMIT.toString()} through ${PAGE_LIMIT.toString()}`,
      value,
    );
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
  if (typeof value !== "string" || value.length > MAX_BASE58_32_LEN) {
    return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
  }
  const bytes = decodeBase58(value);
  if (bytes === undefined || bytes.length !== 32 || encodeBase58(bytes) !== value) {
    return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
  }
  return value as Address;
}

export function checkedSignature(value: unknown, path: string): Signature {
  if (typeof value !== "string" || value.length > MAX_BASE58_64_LEN) {
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
