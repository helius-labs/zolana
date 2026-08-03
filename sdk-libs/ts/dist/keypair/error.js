/** The Rust variant each code mirrors, or `null` for the two TypeScript-only codes. */
export const KEYPAIR_ERROR_RUST_VARIANT = Object.freeze({
    KEYPAIR_INVALID_PUBLIC_KEY: "InvalidPublicKey",
    KEYPAIR_INVALID_SECRET_KEY: "InvalidSecretKey",
    KEYPAIR_ZERO_SCALAR: "ZeroScalar",
    KEYPAIR_INVALID_SIGNATURE_TYPE: "InvalidSignatureType",
    KEYPAIR_HKDF: "Hkdf",
    KEYPAIR_POSEIDON: "Poseidon",
    KEYPAIR_FIELD_ELEMENT_TOO_LONG: "FieldElementTooLong",
    KEYPAIR_INVALID_PREHASH_LENGTH: "InvalidPrehashLength",
    KEYPAIR_INFO_TOO_LONG: "InfoTooLong",
    KEYPAIR_INVALID_LENGTH: null,
    KEYPAIR_HASH: null,
});
const DETAIL_KEYS = [
    "name",
    "expected",
    "actual",
    "minimum",
    "maximum",
    "index",
    "prefix",
    "reason",
    "type",
];
/**
 * Copies only the known keys and only primitive values, so a caller cannot
 * smuggle a `Uint8Array` of key material into a thrown error.
 */
function sanitizeDetails(details) {
    const output = {};
    let present = false;
    for (const key of DETAIL_KEYS) {
        const value = details[key];
        if (typeof value === "number" || typeof value === "string") {
            output[key] = value;
            present = true;
        }
    }
    return present ? Object.freeze(output) : undefined;
}
export class KeypairError extends Error {
    code;
    details;
    constructor(code, details, cause) {
        super(code);
        this.name = "KeypairError";
        this.code = code;
        const sanitized = details === undefined ? undefined : sanitizeDetails(details);
        if (sanitized !== undefined)
            this.details = sanitized;
        // The cause is whatever a dependency threw and may quote input bytes, so it
        // stays reachable for debugging but out of enumeration and serialization.
        Object.defineProperty(this, "cause", {
            value: cause,
            enumerable: false,
            writable: false,
            configurable: true,
        });
    }
    /** The Rust variant this code mirrors, or `null` for a TypeScript-only code. */
    get rustVariant() {
        return KEYPAIR_ERROR_RUST_VARIANT[this.code];
    }
    toJSON() {
        return this.details === undefined
            ? { name: this.name, code: this.code }
            : { name: this.name, code: this.code, details: this.details };
    }
}
export function invalidLength(name, expected, actual) {
    return new KeypairError("KEYPAIR_INVALID_LENGTH", { name, expected, actual });
}
export function wrapKeypairError(code, cause, details) {
    if (cause instanceof KeypairError)
        return cause;
    return new KeypairError(code, details, cause);
}
