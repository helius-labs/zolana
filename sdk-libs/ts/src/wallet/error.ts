/**
 * Closed set of wallet error codes. Rust has no wallet error type and returns
 * `ClientError` and `TransactionError` unchanged, so a wrapped code must stay
 * readable: `wrapWalletError` lifts it to `causeCode` instead of leaving it
 * reachable only through `cause`.
 */
export const WALLET_ERROR_CODES = [
  "WALLET_BUILD_DEPOSIT",
  "WALLET_BUILD_MERGE",
  "WALLET_BUILD_REGISTRATION",
  "WALLET_BUILD_SET_MERGING_ENABLED",
  "WALLET_BUILD_SPLIT",
  "WALLET_BUILD_TRANSFER",
  "WALLET_BUILD_WITHDRAWAL",
  "WALLET_ASSET_METADATA",
  "WALLET_CREATE_DEPOSIT",
  "WALLET_CREATE_TRANSFER",
  "WALLET_DUPLICATE_INPUT_UTXO",
  "WALLET_FETCH_USER_RECORD",
  "WALLET_INPUT_UTXO_TREE_MISMATCH",
  "WALLET_INPUT_UTXO_UNAVAILABLE",
  "WALLET_INSUFFICIENT_BALANCE",
  "WALLET_INTENT_MISMATCH",
  "WALLET_KEYS_BATCH_MISMATCH",
  "WALLET_INVALID_ADDRESS",
  "WALLET_INVALID_AMOUNT",
  "WALLET_INVALID_BASE64",
  "WALLET_INVALID_LENGTH",
  "WALLET_INVALID_SYNC_CONFIG",
  "WALLET_INVALID_USER_RECORD",
  "WALLET_MERGE_DISABLED",
  "WALLET_MERGE_NULLIFIER_KEY_MISMATCH",
  "WALLET_MERGE_SIGNING_KEY_MISMATCH",
  "WALLET_MERGE_TREE_MISMATCH",
  "WALLET_MERGE_VIEWING_KEY_MISMATCH",
  "WALLET_MISSING_SPL_TOKEN_ACCOUNT",
  "WALLET_MULTIPLE_INPUT_TREES",
  "WALLET_NO_INPUTS",
  "WALLET_NOTE_RESERVED",
  "WALLET_NOTHING_TO_MERGE",
  "WALLET_P256_REGISTRATION_UNSUPPORTED",
  "WALLET_PDA_DERIVATION",
  "WALLET_PERSIST",
  "WALLET_REGISTERED_KEYPAIR_MISMATCH",
  "WALLET_RECIPIENT_CLIENT_REQUIRED",
  "WALLET_RECIPIENT_NOT_REGISTERED",
  "WALLET_SELECTED_BALANCE_OVERFLOW",
  "WALLET_SPLIT_INPUT_HAS_DATA",
  "WALLET_SPLIT_INPUT_RING_MISMATCH",
  "WALLET_SPLIT_INVALID_PART_COUNT",
  "WALLET_SNAPSHOT",
  "WALLET_SPLIT_NOT_DIVISIBLE",
  "WALLET_SYNC",
  "WALLET_TOO_MANY_INPUTS",
  "WALLET_UNRESOLVED_ASSET",
  "WALLET_UNSIGNED_INPUT_UNAVAILABLE",
  "WALLET_USER_RECORD_BUMP_MISMATCH",
  "WALLET_USER_RECORD_OWNER_MISMATCH",
  "WALLET_USER_RECORD_PROGRAM_MISMATCH",
  "WALLET_USER_REGISTRY_RECORD_NOT_FOUND",
] as const;

import {
  extractCauseCodes,
  hideCause,
  sanitizeDetails,
  type ErrorEnvelope,
} from "../errors/internal.js";

export type WalletErrorCode = (typeof WALLET_ERROR_CODES)[number];

export class WalletError extends Error {
  readonly code: WalletErrorCode;
  readonly causeCode?: string;
  /** The wrapped operation chain, innermost codes last. */
  readonly causeCodes?: readonly string[];
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: WalletErrorCode,
    options?: Readonly<{
      causeCode?: string;
      causeCodes?: readonly string[];
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(code);
    this.name = "WalletError";
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
export function wrapWalletError(
  code: WalletErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): WalletError {
  if (cause instanceof WalletError && cause.code === code) return cause;
  const chain = extractCauseCodes(cause);
  return new WalletError(code, {
    ...(chain.length === 0 ? {} : { causeCode: chain[0], causeCodes: chain }),
    ...(details === undefined ? {} : { details }),
    cause,
  });
}
