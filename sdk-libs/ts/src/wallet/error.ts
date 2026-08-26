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
  "WALLET_CREATE_DEPOSIT",
  "WALLET_CREATE_TRANSFER",
  "WALLET_DUPLICATE_INPUT_UTXO",
  "WALLET_FETCH_USER_RECORD",
  "WALLET_INPUT_UTXO_TREE_MISMATCH",
  "WALLET_INPUT_UTXO_UNAVAILABLE",
  "WALLET_INSUFFICIENT_BALANCE",
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
  "WALLET_NOTHING_TO_MERGE",
  "WALLET_P256_REGISTRATION_UNSUPPORTED",
  "WALLET_PDA_DERIVATION",
  "WALLET_REGISTERED_KEYPAIR_MISMATCH",
  "WALLET_RECIPIENT_CLIENT_REQUIRED",
  "WALLET_RECIPIENT_NOT_REGISTERED",
  "WALLET_SELECTED_BALANCE_OVERFLOW",
  "WALLET_SPLIT_INPUT_HAS_DATA",
  "WALLET_SPLIT_INPUT_RING_MISMATCH",
  "WALLET_SPLIT_INVALID_PART_COUNT",
  "WALLET_SPLIT_NOT_DIVISIBLE",
  "WALLET_SYNC",
  "WALLET_TOO_MANY_INPUTS",
  "WALLET_UNSIGNED_INPUT_UNAVAILABLE",
  "WALLET_USER_RECORD_BUMP_MISMATCH",
  "WALLET_USER_RECORD_OWNER_MISMATCH",
  "WALLET_USER_RECORD_PROGRAM_MISMATCH",
  "WALLET_USER_REGISTRY_RECORD_NOT_FOUND",
] as const;

export type WalletErrorCode = (typeof WALLET_ERROR_CODES)[number];

export class WalletError extends Error {
  readonly code: WalletErrorCode;
  readonly causeCode?: string;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: WalletErrorCode,
    options?: Readonly<{
      causeCode?: string;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(code);
    this.name = "WalletError";
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

export function wrapWalletError(
  code: WalletErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): WalletError {
  if (cause instanceof WalletError) return cause;
  const inner = causeCode(cause);
  return new WalletError(code, {
    ...(inner === undefined ? {} : { causeCode: inner }),
    ...(details === undefined ? {} : { details }),
    cause,
  });
}
