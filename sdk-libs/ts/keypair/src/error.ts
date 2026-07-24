export type KeypairErrorCode =
  | "KEYPAIR_INVALID_LENGTH"
  | "KEYPAIR_INVALID_PUBLIC_KEY"
  | "KEYPAIR_INVALID_SECRET_KEY"
  | "KEYPAIR_INVALID_SIGNATURE_TYPE"
  | "KEYPAIR_INVALID_SIGNATURE"
  | "KEYPAIR_ENCRYPTION"
  | "KEYPAIR_DECRYPTION"
  | "KEYPAIR_HASH";

export class KeypairError extends Error {
  readonly code: KeypairErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: KeypairErrorCode,
    details?: Readonly<Record<string, unknown>>,
    cause?: unknown,
  ) {
    super(code, { cause });
    this.name = "KeypairError";
    this.code = code;
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}

export function invalidLength(name: string, expected: number, actual: number): KeypairError {
  return new KeypairError("KEYPAIR_INVALID_LENGTH", { name, expected, actual });
}

export function wrapKeypairError(
  code: KeypairErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): KeypairError {
  if (cause instanceof KeypairError) return cause;
  return new KeypairError(code, details, cause);
}
