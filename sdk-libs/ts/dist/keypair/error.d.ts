/**
 * Errors reachable through the TypeScript key APIs, plus the two
 * TypeScript-only shape errors below. Rust encodes lengths in its types, so a
 * JavaScript caller can reach malformed inputs Rust cannot express.
 *
 * A TypeScript-only code is justified at a boundary only when the input it
 * describes cannot be expressed in Rust. Where Rust accepts the same input and
 * answers with a variant, the boundary must raise the code mirroring that
 * variant, or the port reports a divergence Rust does not have. The K10 suite
 * enforces this by scanning the sources for each TypeScript-only code.
 */
export type KeypairErrorCode = "KEYPAIR_INVALID_PUBLIC_KEY" | "KEYPAIR_INVALID_SECRET_KEY" | "KEYPAIR_ZERO_SCALAR" | "KEYPAIR_INVALID_SIGNATURE_TYPE" | "KEYPAIR_HKDF" | "KEYPAIR_POSEIDON" | "KEYPAIR_FIELD_ELEMENT_TOO_LONG" | "KEYPAIR_INVALID_PREHASH_LENGTH" | "KEYPAIR_INFO_TOO_LONG" | "KEYPAIR_INVALID_LENGTH" | "KEYPAIR_HASH";
/** The Rust variant each code mirrors, or `null` for the two TypeScript-only codes. */
export declare const KEYPAIR_ERROR_RUST_VARIANT: Readonly<Record<KeypairErrorCode, string | null>>;
/**
 * Diagnostics are a closed set of non-secret descriptors. Anything else -- a
 * key, a plaintext, a scalar -- must never reach an error object, because
 * errors get logged and serialized.
 */
export type KeypairErrorDetails = {
    readonly name?: string;
    readonly expected?: number | string;
    readonly actual?: number | string;
    readonly minimum?: number | string;
    readonly maximum?: number | string;
    readonly index?: number;
    readonly prefix?: number;
    readonly reason?: string;
    readonly type?: string;
};
export declare class KeypairError extends Error {
    readonly code: KeypairErrorCode;
    readonly details?: KeypairErrorDetails;
    constructor(code: KeypairErrorCode, details?: KeypairErrorDetails, cause?: unknown);
    /** The Rust variant this code mirrors, or `null` for a TypeScript-only code. */
    get rustVariant(): string | null;
    toJSON(): Readonly<{
        name: string;
        code: KeypairErrorCode;
        details?: KeypairErrorDetails;
    }>;
}
export declare function invalidLength(name: string, expected: number, actual: number): KeypairError;
export declare function wrapKeypairError(code: KeypairErrorCode, cause: unknown, details?: KeypairErrorDetails): KeypairError;
