import { KeypairError } from "../keypair/error.js";

export const TRANSACTION_ERROR_CODES = Object.freeze([
  "TRANSACTION_BAD_DISCRIMINATOR",
  "TRANSACTION_DATA_WITHOUT_OUTPUT",
  "TRANSACTION_DESERIALIZE",
  "TRANSACTION_DUMMY_INPUT_NOT_ALLOWED",
  "TRANSACTION_DUPLICATE_ASSET_ID",
  "TRANSACTION_DUPLICATE_DATA_RECORD",
  "TRANSACTION_DUPLICATE_MINT",
  "TRANSACTION_DUPLICATE_OUTPUT",
  "TRANSACTION_ED25519_PAYER_MISMATCH",
  "TRANSACTION_EXCESS_OUTPUT_SLOTS",
  "TRANSACTION_INPUT_OWNER_MISMATCH",
  "TRANSACTION_INSUFFICIENT_BALANCE",
  "TRANSACTION_INVALID_ADDRESS",
  "TRANSACTION_INVALID_AMOUNT",
  "TRANSACTION_INVALID_ASSET_ID",
  "TRANSACTION_INVALID_BLINDING",
  "TRANSACTION_INVALID_DATA_LENGTH",
  "TRANSACTION_INVALID_DERIVATION_SEED",
  "TRANSACTION_INVALID_INTEGER",
  "TRANSACTION_INVALID_LENGTH",
  "TRANSACTION_INVALID_POSITION",
  "TRANSACTION_INVALID_OUTPUT_COUNT",
  "TRANSACTION_INVALID_OUTPUT_POSITION",
  "TRANSACTION_KEYPAIR",
  "TRANSACTION_MERGE_INPUT_ASSET_MISMATCH",
  "TRANSACTION_MERGE_INPUT_HAS_DATA",
  "TRANSACTION_MERGE_INPUT_NULLIFIER_KEY_MISMATCH",
  "TRANSACTION_MERGE_INPUT_OWNER_MISMATCH",
  "TRANSACTION_MERGE_INPUT_RAIL_MISMATCH",
  "TRANSACTION_MERGE_INPUT_RING_MISMATCH",
  "TRANSACTION_MISSING_CURRENT_VIEWING_KEY",
  "TRANSACTION_MISSING_OUTPUT",
  "TRANSACTION_MISSING_PUBLIC_SPL_ASSET",
  "TRANSACTION_MISSING_RING_PROGRAM_ID",
  "TRANSACTION_MULTIPLE_PUBLIC_SPL_ASSETS",
  "TRANSACTION_NON_CANONICAL_DATA_ORDER",
  "TRANSACTION_NONCANONICAL_DUMMY_INPUT",
  "TRANSACTION_NO_INPUTS",
  "TRANSACTION_ADDRESS_HASH_COUNT_MISMATCH",
  "TRANSACTION_OUTPUT_TAG_MISMATCH",
  "TRANSACTION_OUTPUT_AMOUNT_MISMATCH",
  "TRANSACTION_OUTPUT_ASSET_MISMATCH",
  "TRANSACTION_OUTPUT_BLINDING_MISMATCH",
  "TRANSACTION_OUTPUT_COMMITMENT_MISMATCH",
  "TRANSACTION_OUTPUT_DATA_MISMATCH",
  "TRANSACTION_OUTPUT_OWNER_MISMATCH",
  "TRANSACTION_OUTPUT_SLOT_OVERFLOW",
  "TRANSACTION_OUTPUT_RING_MISMATCH",
  "TRANSACTION_P256_TRANSACT_UNSUPPORTED",
  "TRANSACTION_POSEIDON",
  "TRANSACTION_PUBLIC_SOL_ALREADY_SET",
  "TRANSACTION_PUBLIC_SPL_ALREADY_SET",
  "TRANSACTION_RESERVED_ASSET_ID",
  "TRANSACTION_SELECTED_BALANCE_OVERFLOW",
  "TRANSACTION_WALLET_BALANCE_OVERFLOW",
  "TRANSACTION_SERIALIZE",
  "TRANSACTION_SIGNATURE_OWNER_MISMATCH",
  "TRANSACTION_SPLIT_AMOUNT_MISMATCH",
  "TRANSACTION_SPLIT_INPUT_ASSET_MISMATCH",
  "TRANSACTION_SPLIT_INPUT_HAS_DATA",
  "TRANSACTION_SPLIT_INPUT_IS_DUMMY",
  "TRANSACTION_SPLIT_INPUT_NULLIFIER_KEY_MISMATCH",
  "TRANSACTION_SPLIT_INPUT_OWNER_MISMATCH",
  "TRANSACTION_SPLIT_INPUT_RING_MISMATCH",
  "TRANSACTION_SPLIT_INVALID_PART_COUNT",
  "TRANSACTION_TOO_MANY_INPUTS",
  "TRANSACTION_TOO_MANY_INTERFACE_TRANSFERS",
  "TRANSACTION_TOO_MANY_OUTPUTS",
  "TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE",
  "TRANSACTION_TRAILING_BYTES",
  "TRANSACTION_UNKNOWN_ASSET",
  "TRANSACTION_UNKNOWN_ASSET_FIELD",
  "TRANSACTION_UNKNOWN_MINT",
  "TRANSACTION_UNSUPPORTED_SHAPE",
  "TRANSACTION_WALLET_AUTHORITY_MISMATCH",
  "TRANSACTION_WITHDRAWAL_ALREADY_SET",
  "TRANSACTION_WITHDRAWAL_ASSET_MISMATCH",
  "TRANSACTION_ZERO_INTERFACE_TRANSFER_AMOUNT",
] as const);

export type TransactionErrorCode = (typeof TRANSACTION_ERROR_CODES)[number];
export type TransactionErrorValue =
  | string
  | number
  | bigint
  | boolean
  | null
  | readonly TransactionErrorValue[]
  | Readonly<{ [key: string]: TransactionErrorValue }>;
export type TransactionErrorDetails = Readonly<Record<string, TransactionErrorValue>>;
export type TransactionErrorCause =
  | Readonly<{ category: "transaction"; code: TransactionErrorCode }>
  | Readonly<{ category: "keypair"; code: string }>
  | Readonly<{ category: "external"; code?: string }>;

export class TransactionError extends Error {
  readonly code: TransactionErrorCode;
  readonly details: TransactionErrorDetails | undefined;
  override readonly cause: TransactionErrorCause | undefined;

  constructor(
    code: TransactionErrorCode,
    details?: Readonly<Record<string, unknown>>,
    cause?: unknown,
  ) {
    const safe = safeCause(cause);
    super(code, safe === undefined ? undefined : { cause: safe });
    this.name = "TransactionError";
    this.code = code;
    this.details = safeDetails(details);
    this.cause = safe;
  }
}

export function transactionError(
  code: TransactionErrorCode,
  details?: Readonly<Record<string, unknown>>,
  cause?: unknown,
): TransactionError {
  return new TransactionError(code, details, cause);
}

function safeCause(cause: unknown): TransactionErrorCause | undefined {
  if (cause instanceof TransactionError) {
    return Object.freeze({ category: "transaction", code: cause.code });
  }
  if (cause instanceof KeypairError) {
    return Object.freeze({ category: "keypair", code: cause.code });
  }
  if (isCauseCategory(cause)) {
    return Object.freeze({
      category: cause.category,
      ...(typeof cause.code === "string" ? { code: cause.code } : {}),
    });
  }
  if (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    typeof cause.code === "string"
  ) {
    return Object.freeze({ category: "external", code: cause.code });
  }
  return cause === undefined ? undefined : Object.freeze({ category: "external" });
}

function isCauseCategory(
  value: unknown,
): value is Readonly<{ category: "external"; code?: string }> {
  if (typeof value !== "object" || value === null || !("category" in value)) return false;
  return value.category === "external";
}

function safeDetails(
  details: Readonly<Record<string, unknown>> | undefined,
): TransactionErrorDetails | undefined {
  if (details === undefined) return undefined;
  const safe = Object.fromEntries(
    Object.entries(details).flatMap(([key, value]) => {
      if (/(secret|private|seed|blinding|nonce|scalar|signature)/iu.test(key)) return [];
      const sanitized = safeValue(value);
      return sanitized === undefined ? [] : [[key, sanitized]];
    }),
  );
  return Object.freeze(safe);
}

function safeValue(value: unknown): TransactionErrorValue | undefined {
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "bigint" ||
    typeof value === "boolean" ||
    value === null
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.flatMap((entry) => {
        const safe = safeValue(entry);
        return safe === undefined ? [] : [safe];
      }),
    );
  }
  if (typeof value !== "object" || value instanceof Uint8Array) return undefined;
  return safeDetails(value as Readonly<Record<string, unknown>>);
}
