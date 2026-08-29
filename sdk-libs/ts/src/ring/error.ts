export const RING_ERROR_CODES = [
  "RING_AUDIT_KEY_MISMATCH",
  "RING_AUDIT_MESSAGE",
  "RING_AUDIT_UNSEALED",
  "RING_BUILD_DEPOSIT",
  "RING_BUILD_LOOKUP_TABLE",
  "RING_BUILD_TRANSFER",
  "RING_BUILD_WITHDRAWAL",
  "RING_CONFIG_INVALID",
  "RING_CONFIG_NOT_FOUND",
  "RING_DATA_OUTSIDE_RING",
  "RING_FOREIGN_RING",
  "RING_INSUFFICIENT_BALANCE",
  "RING_INVALID_LENGTH",
  "RING_LOOKUP_TABLE_INCOMPLETE",
  "RING_LOOKUP_TABLE_NOT_FOUND",
  "RING_MULTIPLE_INPUT_TREES",
  "RING_ORIGIN_DECODE",
  "RING_ORIGIN_STACK",
  "RING_ORIGIN_UNAVAILABLE",
  "RING_PADDED_CHANGE",
  "RING_PASSKEY",
  "RING_PROOF_LENGTH",
  "RING_READ_ACCESS_RECORD_INVALID",
  "RING_READ_CURSOR",
  "RING_READ_LIMIT",
  "RING_READER_KEY",
  "RING_RESERVED_AUDITOR_KEY",
  "RING_RPC",
  "RING_RPC_TRANSPORT",
  "RING_TOO_MANY_INPUTS",
  "RING_TREE_MISMATCH",
] as const;

export type RingErrorCode = (typeof RING_ERROR_CODES)[number];

export class RingError extends Error {
  readonly code: RingErrorCode;
  readonly causeCode?: string;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: RingErrorCode,
    options?: Readonly<{
      causeCode?: string;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(code);
    this.name = "RingError";
    this.code = code;
    if (options?.causeCode !== undefined) this.causeCode = options.causeCode;
    if (options?.details !== undefined) this.details = Object.freeze({ ...options.details });
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

function causeCode(cause: unknown): string | undefined {
  if (typeof cause !== "object" || cause === null) return undefined;
  const code = (cause as Readonly<{ code?: unknown }>).code;
  return typeof code === "string" ? code : undefined;
}

export function wrapRingError(
  code: RingErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): RingError {
  if (cause instanceof RingError) return cause;
  const inner = causeCode(cause);
  return new RingError(code, {
    ...(inner === undefined ? {} : { causeCode: inner }),
    ...(details === undefined ? {} : { details }),
    cause,
  });
}
