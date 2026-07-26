/**
 * One code per `zolana_keypair::error::KeypairError` variant, plus the two
 * TypeScript-only codes below. Rust encodes lengths and rails in its types, so
 * a JavaScript caller can reach malformed shapes Rust cannot express.
 *
 * A TypeScript-only code is justified at a boundary only when the input it
 * describes cannot be expressed in Rust. Where Rust accepts the same input and
 * answers with a variant, the boundary must raise the code mirroring that
 * variant, or the port reports a divergence Rust does not have. The K10 suite
 * enforces this by scanning the sources for each TypeScript-only code.
 */
export type KeypairErrorCode =
  | "KEYPAIR_INVALID_PUBLIC_KEY"
  | "KEYPAIR_INVALID_SECRET_KEY"
  | "KEYPAIR_ZERO_SCALAR"
  | "KEYPAIR_INVALID_SIGNATURE_TYPE"
  | "KEYPAIR_NOT_ED25519"
  | "KEYPAIR_HKDF"
  | "KEYPAIR_POSEIDON"
  | "KEYPAIR_FIELD_ELEMENT_TOO_LONG"
  | "KEYPAIR_INVALID_PREHASH_LENGTH"
  | "KEYPAIR_INFO_TOO_LONG"
  // TypeScript-only: Rust rejects these at the type level.
  | "KEYPAIR_INVALID_LENGTH"
  | "KEYPAIR_HASH";

/** The Rust variant each code mirrors, or `null` for the two TypeScript-only codes. */
export const KEYPAIR_ERROR_RUST_VARIANT: Readonly<Record<KeypairErrorCode, string | null>> =
  Object.freeze({
    KEYPAIR_INVALID_PUBLIC_KEY: "InvalidPublicKey",
    KEYPAIR_INVALID_SECRET_KEY: "InvalidSecretKey",
    KEYPAIR_ZERO_SCALAR: "ZeroScalar",
    KEYPAIR_INVALID_SIGNATURE_TYPE: "InvalidSignatureType",
    KEYPAIR_NOT_ED25519: "NotEd25519",
    KEYPAIR_HKDF: "Hkdf",
    KEYPAIR_POSEIDON: "Poseidon",
    KEYPAIR_FIELD_ELEMENT_TOO_LONG: "FieldElementTooLong",
    KEYPAIR_INVALID_PREHASH_LENGTH: "InvalidPrehashLength",
    KEYPAIR_INFO_TOO_LONG: "InfoTooLong",
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
 * SDK-wide fail-closed allow-list for structured error `details`. Union of the
 * keypair descriptors and the diagnostic keys transaction / wallet / client
 * wrap paths already emit. Unknown keys and non-primitives drop.
 */
export const SAFE_ERROR_DETAIL_KEYS = Object.freeze([
  "name",
  "expected",
  "actual",
  "minimum",
  "maximum",
  "index",
  "prefix",
  "reason",
  "type",
  "requested",
  "available",
  "inputs",
  "outputs",
  "address",
  "amount",
  "asset",
  "assetField",
  "assetId",
  "attempts",
  "bits",
  "byte",
  "byteLength",
  "code",
  "declared",
  "encoding",
  "encodingTag",
  "expectedEncoding",
  "expectedMaximum",
  "expectedMinimum",
  "field",
  "got",
  "hash",
  "input",
  "inputCount",
  "instructionIndex",
  "jobId",
  "keypair",
  "kind",
  "max",
  "method",
  "mint",
  "missing",
  "numOutputs",
  "offset",
  "optionTag",
  "owner",
  "parts",
  "path",
  "perOutput",
  "position",
  "proofTree",
  "provided",
  "required",
  "retryable",
  "scheme",
  "signature",
  "signed",
  "spendTree",
  "status",
  "submitTree",
  "tag",
  "timeoutMs",
  "trailing",
  "treeCount",
  "typePrefix",
  "utxoTree",
  "value",
  "variant",
] as const);

export type SafeErrorDetailKey = (typeof SAFE_ERROR_DETAIL_KEYS)[number];

/**
 * Copies only allow-listed keys and only `string` / `number` values, so a
 * caller cannot smuggle a `Uint8Array` of key material into a thrown error.
 */
export function sanitizeSafeErrorDetails(
  details: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, string | number>> | undefined {
  if (details === undefined) return undefined;
  const output: Record<string, string | number> = {};
  let present = false;
  for (const key of SAFE_ERROR_DETAIL_KEYS) {
    const value = details[key];
    if (typeof value === "number" || typeof value === "string") {
      output[key] = value;
      present = true;
    }
  }
  return present ? Object.freeze(output) : undefined;
}

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
