export const RING_ERROR_CODES = [
  "RING_AUDIT_KEY_MISMATCH",
  "RING_AUDIT_MESSAGE",
  "RING_AUDIT_UNSEALED",
  "RING_BUILD_DEPOSIT",
  "RING_BUILD_ENTRY",
  "RING_BUILD_LOOKUP_TABLE",
  "RING_BUILD_TRANSFER",
  "RING_BUILD_WITHDRAWAL",
  "RING_CONFIG_INVALID",
  "RING_CONFIG_NOT_FOUND",
  "RING_DATA_OUTSIDE_RING",
  "RING_ENTRIES_ROOTS_INVALID",
  "RING_ENTRIES_ROOTS_REQUIRED",
  "RING_ENTRIES_TREE_REQUIRED",
  "RING_FOREIGN_RING",
  "RING_INSUFFICIENT_BALANCE",
  "RING_INTENT_MISMATCH",
  "RING_INVALID_LENGTH",
  "RING_LOOKUP_TABLE_INCOMPLETE",
  "RING_LOOKUP_TABLE_NOT_FOUND",
  "RING_MULTIPLE_INPUT_TREES",
  "RING_ORIGIN_DECODE",
  "RING_ORIGIN_STACK",
  "RING_ORIGIN_UNAVAILABLE",
  "RING_PADDED_CHANGE",
  "RING_PASSKEY",
  "RING_POLICY_CONFIG_INVALID",
  "RING_POLICY_CONFIG_NOT_FOUND",
  "RING_PROOF_LENGTH",
  "RING_READ_ACCESS_RECORD_INVALID",
  "RING_READ_CURSOR",
  "RING_READ_LIMIT",
  "RING_READER_KEY",
  "RING_RECORDS_TREE_MISMATCH",
  "RING_RESERVED_AUDITOR_KEY",
  "RING_RPC",
  "RING_RPC_CONFIG",
  "RING_RPC_TRANSPORT",
  "RING_RULES_UNSUPPORTED",
  "RING_SELECTED_BALANCE_OVERFLOW",
  "RING_TOO_MANY_INPUTS",
  "RING_TREE_MISMATCH",
  "RING_ZERO_AMOUNT",
] as const;

import {
  extractCauseCodes,
  hideCause,
  sanitizeDetails,
  type ErrorEnvelope,
} from "../errors/internal.js";

export type RingErrorCode = (typeof RING_ERROR_CODES)[number];

export class RingError extends Error {
  readonly code: RingErrorCode;
  readonly causeCode?: string;
  /** The wrapped operation chain, innermost codes last. */
  readonly causeCodes?: readonly string[];
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: RingErrorCode,
    options?: Readonly<{
      causeCode?: string;
      causeCodes?: readonly string[];
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(code);
    this.name = "RingError";
    this.code = code;
    if (options?.causeCode !== undefined) this.causeCode = options.causeCode;
    if (options?.causeCodes !== undefined) this.causeCodes = Object.freeze([...options.causeCodes]);
    const details = sanitizeDetails(options?.details);
    if (details !== undefined) this.details = details;
    hideCause(this, options?.cause);
  }

  toJSON(): ErrorEnvelope {
    return {
      name: this.name,
      code: this.code,
      ...(this.details === undefined ? {} : { details: this.details }),
      ...(this.causeCode === undefined ? {} : { causeCode: this.causeCode }),
      ...(this.causeCodes === undefined ? {} : { causeCodes: this.causeCodes }),
    };
  }
}

/** Keeps the outer operation code, the wrapped code lands in `causeCode`. */
export function wrapRingError(
  code: RingErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): RingError {
  if (cause instanceof RingError && cause.code === code) return cause;
  const chain = extractCauseCodes(cause);
  return new RingError(code, {
    ...(chain.length === 0 ? {} : { causeCode: chain[0], causeCodes: chain }),
    ...(details === undefined ? {} : { details }),
    cause,
  });
}
