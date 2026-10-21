export const RING_ERROR_CODES = [
  "RING_ANONYMOUS_REFUSED",
  "RING_AUDIT_KEY_MISMATCH",
  "RING_AUDIT_MESSAGE",
  "RING_AUDIT_NONCANONICAL_KEY",
  "RING_AUDIT_OUTPUT_MISMATCH",
  "RING_AUDIT_UNSEALED",
  "RING_BUILD_DEPOSIT",
  "RING_BUILD_ENTRY",
  "RING_BUILD_LIST_WRITE",
  "RING_BUILD_MERGE",
  "RING_NOTHING_TO_MERGE",
  "RING_BUILD_POLICY",
  "RING_BUILD_TRANSFER",
  "RING_BUILD_WITHDRAWAL",
  "RING_CONFIG_INVALID",
  "RING_CONFIG_NOT_FOUND",
  "RING_CO_SIGNER_INVALID",
  "RING_COSIGNER_REQUIRED",
  "RING_DATA_OUTSIDE_RING",
  "RING_DELEGATE_INVALID",
  "RING_DEPLOY_OPTIONS_INVALID",
  "RING_DEPLOY_PROGRAM",
  "RING_ENTRY_INVALID",
  "RING_FOREIGN_RING",
  "RING_INSUFFICIENT_BALANCE",
  "RING_INTENT_MISMATCH",
  "RING_INVALID_LENGTH",
  "RING_KEY_ENVELOPE_INVALID",
  "RING_MEMBER_REGISTRY_INVALID",
  "RING_MEMBER_REGISTRY_MISSING",
  "RING_MEMBER_REGISTRY_STALE",
  "RING_LIST_WRITER_UNAUTHORIZED",
  "RING_NULLIFIER_KEY_MISMATCH",
  "RING_ORIGIN_DECODE",
  "RING_ORIGIN_STACK",
  "RING_ORIGIN_UNAVAILABLE",
  "RING_PASSKEY",
  "RING_POLICY_HASH_MISMATCH",
  "RING_POLICY_RULE_UNSATISFIED",
  "RING_POLICY_SOURCE_INVALID",
  "RING_POLICY_TIER_MISMATCH",
  "RING_OUTFLOW_CAP_EXCEEDED",
  "RING_PROGRAM_ADDRESS_OCCUPIED",
  "RING_PROGRAM_AUTHORITY_MISMATCH",
  "RING_PROGRAM_BINARY_INVALID",
  "RING_PROGRAM_BUFFER_INVALID",
  "RING_PROGRAM_DATA_INVALID",
  "RING_PROGRAM_IMMUTABLE",
  "RING_PROGRAM_KEYPAIR_INVALID",
  "RING_PROGRAM_MISMATCH",
  "RING_PROGRAM_NOT_DEPLOYED",
  "RING_PROGRAM_NOT_USABLE",
  "RING_PROGRAM_UNDERFUNDED",
  "RING_PROGRAM_WRITE_TOO_LARGE",
  "RING_PROOF_LENGTH",
  "RING_READ_ACCESS_RECORD_INVALID",
  "RING_READ_CURSOR",
  "RING_READ_LIMIT",
  "RING_READER_KEY",
  "RING_RECOVERY_INCOMPLETE",
  "RING_RESERVED_INPUT_SPENT",
  "RING_RPC",
  "RING_RPC_CONFIG",
  "RING_RPC_TRANSPORT",
  "RING_RULE_TABLE_INVALID",
  "RING_SELECTED_BALANCE_OVERFLOW",
  "RING_SUBMISSION_PENDING",
  "RING_TOO_MANY_INPUTS",
  "RING_TREE_MISMATCH",
  "RING_UNREGISTERED_OUTPUT_KEY",
  "RING_ZERO_AMOUNT",
  "RING_NOT_ANONYMOUS",
  "RING_ANONYMOUS_SIGNER_REQUIRED",
  "RING_ANONYMOUS_SIGNER_MISMATCH",
  "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
  "RING_ANONYMOUS_SLOT_INVALID",
  "RING_SCAN_FRONTIER_MISSING",
  "RING_ANONYMOUS_MERGE_TOO_WIDE",
  "RING_ANONYMOUS_EXIT_LINKS_OWNER",
  "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
  "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA",
  "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
  "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE",
  "RING_TRANSACT_DATA_INVALID",
  "RING_LIST_WRITE_INVALID",
  "RING_AUTHORITY_BATCH_SPLIT",
  "RING_UNAUTHORIZED_AUTHORITY",
  "RING_REGISTRY_FULL",
  "RING_KEY_ALREADY_REGISTERED",
  "RING_KEY_NOT_REGISTERED",
  "RING_BUILD_KEY_REGISTRATION",
  "RING_PROGRAM_STATE_INCOMPATIBLE",
  "RING_ADDRESS_EXIT",
  "RING_DELIVERED_COMPACT_PADDING",
  "RING_DELIVERED_OUTPUT_DATA",
  "RING_OUTPUT_FRAMING",
  "RING_PAYMENT_SLOT",
  "RING_UNPLANNED_OUTPUT",
  "RING_POLICY_NOT_SET",
  "RING_DEPOSIT_ABOVE_OUTFLOW",
  "RING_ANCHOR_INVALID",
  "RING_DUPLICATE_INPUT",
  "RING_EPOCH_PASSED",
  "RING_EXTERNAL_DATA_MISMATCH",
  "RING_SPP_PROOF_MISMATCH",
  "RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH",
  "RING_KEYS_REQUIRED",
  "RING_MIXED_OWNERS",
  "RING_NOT_ACTIVATED",
  "RING_NOT_REGISTERED",
  "RING_PAUSED",
  "RING_SETTLEMENT_ACCOUNTS_INVALID",
  "RING_ENTRY_INPUT_DATA",
  "RING_AUDIT_UNSEEN_INPUT",
  "RING_RECORD_QUEUE_INVALID",
  "RING_RECORD_QUEUE_MISSING",
  "RING_ANONYMOUS_RECIPIENT_CURVE",
  "RING_RECORD_QUEUE_FULL",
] as const;

import {
  extractCauseCodes,
  hideCause,
  sanitizeDetails,
  type ErrorEnvelope,
} from "../errors/internal.js";

export type RingErrorCode = (typeof RING_ERROR_CODES)[number];

/** Rust `CustomRingError` codes a submission reacts to. */
export const RingProgramError = Object.freeze({
  proofVerificationFailed: 8101,
  rootBelowFloor: 8203,
  curatorRootStale: 8204,
  rootIndexEmpty: 8205,
  authorityBatchTooLarge: 8214,
} as const);

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
