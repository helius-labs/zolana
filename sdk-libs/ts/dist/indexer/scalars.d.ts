import type { Address, Bytes32, Signature } from "../interface/types.js";
import type { Base64String, Hash, Limit } from "./types.js";
export declare const MIN_PAGE_LIMIT = 1n;
export declare const PAGE_LIMIT = 1000n;
export type IndexerSchemaErrorCode = `INDEXER_SCHEMA_${string}`;
export declare class IndexerSchemaError extends Error {
    readonly code: IndexerSchemaErrorCode;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly cause?: unknown;
    constructor(code: IndexerSchemaErrorCode, message: string, options?: Readonly<{
        details?: Readonly<Record<string, unknown>>;
        cause?: unknown;
    }>);
}
export declare function base64String(value: string | Uint8Array): Base64String;
/**
 * Byte view of a wire payload, the counterpart of `base64String`.
 *
 * Rust's `Base64String` holds `Vec<u8>` and encodes only at the serde boundary,
 * so `From<Base64String> for Vec<u8>` is free there. The port brands the wire
 * string instead, which left callers no way back to the bytes except a decoder
 * that does not enforce the canonical form this package requires.
 */
export declare function base64Bytes(value: Base64String): Uint8Array;
export declare function hash(value: string | Bytes32): Hash;
export declare function hashBytes(value: Hash): Bytes32;
export declare function limit(value: bigint): Limit;
export declare function checkedHash(value: unknown, path: string): Hash;
export declare function checkedBase64(value: unknown, path: string): Base64String;
export declare function checkedAddress(value: unknown, path: string): Address;
export declare function checkedSignature(value: unknown, path: string): Signature;
export declare function schemaFailure(code: IndexerSchemaErrorCode, path: string, expected: string, actual?: unknown): never;
