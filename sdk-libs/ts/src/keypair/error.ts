/**
 * Errors reachable through the TypeScript key APIs, plus the TypeScript-only
 * shape errors below. Rust encodes lengths in its types, so a JavaScript
 * caller can reach malformed inputs Rust cannot express.
 *
 * A TypeScript-only code is justified at a boundary only when the input it
 * describes cannot be expressed in Rust. Where Rust accepts the same input and
 * answers with a variant, the boundary must raise the code mirroring that
 * variant, or the port reports a divergence Rust does not have.
 */
export type KeypairErrorCode =
  | "KEYPAIR_INVALID_PUBLIC_KEY"
  | "KEYPAIR_INVALID_SECRET_KEY"
  | "KEYPAIR_ZERO_SCALAR"
  | "KEYPAIR_INVALID_SIGNATURE_TYPE"
  | "KEYPAIR_HKDF"
  | "KEYPAIR_POSEIDON"
  | "KEYPAIR_NOT_ED25519"
  | "KEYPAIR_DERIVATION_INPUT"
  // TypeScript-only: Rust rejects these at the type level.
  | "KEYPAIR_INVALID_PREHASH_LENGTH"
  | "KEYPAIR_INVALID_LENGTH"
  | "KEYPAIR_HASH";

/** The Rust variant each code mirrors, or `null` for a TypeScript-only code. */
export const KEYPAIR_ERROR_RUST_VARIANT: Readonly<Record<KeypairErrorCode, string | null>> =
  Object.freeze({
    KEYPAIR_INVALID_PUBLIC_KEY: "InvalidPublicKey",
    KEYPAIR_INVALID_SECRET_KEY: "InvalidSecretKey",
    KEYPAIR_ZERO_SCALAR: "ZeroScalar",
    KEYPAIR_INVALID_SIGNATURE_TYPE: "InvalidSignatureType",
    KEYPAIR_HKDF: "Hkdf",
    KEYPAIR_POSEIDON: "Poseidon",
    KEYPAIR_NOT_ED25519: "NotEd25519",
    KEYPAIR_DERIVATION_INPUT: "DerivationInput",
    KEYPAIR_INVALID_PREHASH_LENGTH: null,
    KEYPAIR_INVALID_LENGTH: null,
    KEYPAIR_HASH: null,
  });

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

const DETAIL_KEYS: readonly (keyof KeypairErrorDetails)[] = [
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
function sanitizeDetails(details: KeypairErrorDetails): KeypairErrorDetails | undefined {
  const output: Record<string, number | string> = {};
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
  readonly code: KeypairErrorCode;
  readonly details?: KeypairErrorDetails;

  constructor(code: KeypairErrorCode, details?: KeypairErrorDetails, cause?: unknown) {
    super(code);
    this.name = "KeypairError";
    this.code = code;
    const sanitized = details === undefined ? undefined : sanitizeDetails(details);
    if (sanitized !== undefined) this.details = sanitized;
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
  get rustVariant(): string | null {
    return KEYPAIR_ERROR_RUST_VARIANT[this.code];
  }

  toJSON(): Readonly<{ name: string; code: KeypairErrorCode; details?: KeypairErrorDetails }> {
    return this.details === undefined
      ? { name: this.name, code: this.code }
      : { name: this.name, code: this.code, details: this.details };
  }
}

export function invalidLength(name: string, expected: number, actual: number): KeypairError {
  return new KeypairError("KEYPAIR_INVALID_LENGTH", { name, expected, actual });
}

export function wrapKeypairError(
  code: KeypairErrorCode,
  cause: unknown,
  details?: KeypairErrorDetails,
): KeypairError {
  if (cause instanceof KeypairError) return cause;
  return new KeypairError(code, details, cause);
}
