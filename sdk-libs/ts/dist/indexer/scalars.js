import { address, assertIsSignature, getBase58Decoder, getBase58Encoder, getBase64Decoder, getBase64Encoder, } from "@solana/kit";
export const MIN_PAGE_LIMIT = 1n;
export const PAGE_LIMIT = 1000n;
const base58Decoder = getBase58Decoder();
const base58Encoder = getBase58Encoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();
export class IndexerSchemaError extends Error {
    code;
    details;
    cause;
    constructor(code, message, options = {}) {
        super(message);
        this.name = "IndexerSchemaError";
        this.code = code;
        if (options.details !== undefined)
            this.details = options.details;
        if (options.cause !== undefined)
            this.cause = options.cause;
    }
}
function fail(code, path, expected, actual) {
    const details = { path, expected };
    if (actual !== undefined)
        details["actual"] = describeActual(actual);
    throw new IndexerSchemaError(code, `Invalid value at ${path}`, { details });
}
function describeActual(value) {
    if (typeof value === "string")
        return { type: "string", length: value.length };
    if (typeof value === "bigint")
        return { type: "bigint", value: value.toString() };
    if (value instanceof Uint8Array)
        return { type: "Uint8Array", length: value.length };
    if (Array.isArray(value))
        return { type: "array", length: value.length };
    if (value === null)
        return { type: "null" };
    if (typeof value === "object")
        return { type: "object" };
    return value;
}
function decodeBase64(value, path) {
    let bytes;
    try {
        bytes = new Uint8Array(base64Encoder.encode(value));
    }
    catch {
        return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
    }
    if (base64Decoder.decode(bytes) !== value) {
        return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
    }
    return bytes;
}
export function base64String(value) {
    if (typeof value === "string") {
        decodeBase64(value, "$");
        return value;
    }
    if (!(value instanceof Uint8Array)) {
        return fail("INDEXER_SCHEMA_INVALID_BASE64", "$", "a string or Uint8Array", value);
    }
    return base64Decoder.decode(value);
}
/**
 * Byte view of a wire payload, the counterpart of `base64String`.
 *
 * Rust's `Base64String` holds `Vec<u8>` and encodes only at the serde boundary,
 * so `From<Base64String> for Vec<u8>` is free there. The port brands the wire
 * string instead, which left callers no way back to the bytes except a decoder
 * that does not enforce the canonical form this package requires.
 */
export function base64Bytes(value) {
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
function parseHash(value, path) {
    if (value.length > 44) {
        return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", path, "a base58 encoded 32-byte hash", value);
    }
    if (value.length === 0) {
        return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
    }
    let bytes;
    try {
        bytes = new Uint8Array(base58Encoder.encode(value));
    }
    catch {
        return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
    }
    if (bytes.length !== 32) {
        return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", path, "a base58 encoded 32-byte hash", value);
    }
    if (base58Decoder.decode(bytes) !== value) {
        return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
    }
    return bytes;
}
export function hash(value) {
    if (typeof value !== "string") {
        if (!(value instanceof Uint8Array)) {
            return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "exactly 32 bytes", value);
        }
        if (value.length !== 32) {
            return fail("INDEXER_SCHEMA_HASH_WRONG_SIZE", "$", "exactly 32 bytes", value);
        }
        return base58Decoder.decode(value);
    }
    parseHash(value, "$");
    return value;
}
export function hashBytes(value) {
    if (typeof value !== "string") {
        return fail("INDEXER_SCHEMA_INVALID_HASH", "$", "a base58 encoded 32-byte hash", value);
    }
    return parseHash(value, "$");
}
export function limit(value) {
    if (typeof value !== "bigint" || value < MIN_PAGE_LIMIT || value > PAGE_LIMIT) {
        return fail("INDEXER_SCHEMA_INVALID_LIMIT", "$", "an integer from 1 through 1000", value);
    }
    return value;
}
export function checkedHash(value, path) {
    if (typeof value !== "string") {
        return fail("INDEXER_SCHEMA_INVALID_HASH", path, "a base58 encoded 32-byte hash", value);
    }
    try {
        return hash(value);
    }
    catch (error) {
        if (error instanceof IndexerSchemaError) {
            return fail(error.code, path, "a base58 encoded 32-byte hash", value);
        }
        throw error;
    }
}
export function checkedBase64(value, path) {
    if (typeof value !== "string") {
        return fail("INDEXER_SCHEMA_INVALID_BASE64", path, "canonical base64", value);
    }
    try {
        return base64String(value);
    }
    catch (error) {
        if (error instanceof IndexerSchemaError) {
            return fail(error.code, path, "canonical base64", value);
        }
        throw error;
    }
}
export function checkedAddress(value, path) {
    if (typeof value !== "string") {
        return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
    }
    try {
        return address(value);
    }
    catch {
        return fail("INDEXER_SCHEMA_INVALID_ADDRESS", path, "a base58 encoded address", value);
    }
}
export function checkedSignature(value, path) {
    if (typeof value !== "string") {
        return fail("INDEXER_SCHEMA_INVALID_SIGNATURE", path, "a base58 encoded signature", value);
    }
    try {
        assertIsSignature(value);
        return value;
    }
    catch {
        return fail("INDEXER_SCHEMA_INVALID_SIGNATURE", path, "a base58 encoded signature", value);
    }
}
export function schemaFailure(code, path, expected, actual) {
    return fail(code, path, expected, actual);
}
