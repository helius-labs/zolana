import type { DecodedShieldedPoolError } from "@zolana/interface";
import { KeypairError, type KeypairErrorCode } from "@zolana/keypair";
import { TransactionError, type TransactionErrorCode } from "@zolana/transaction";

type NoDetails = undefined;
type IndexDetails = Readonly<{ index: number }>;
type CountDetails = Readonly<{ got: number; expected: number }>;
type HashDetails = Readonly<{ hash: string }>;
type MethodDetails = Readonly<{ method: string }>;

export type HasherErrorCode =
  | "IntegerOverflow"
  | "Poseidon"
  | "PoseidonSyscall"
  | "UnknownSolanaSyscall"
  | "InvalidInputLength"
  | "InvalidNumFields"
  | "EmptyInput"
  | "BorshError"
  | "OptionHashToFieldSizeZero"
  | "PoseidonFeatureNotEnabled"
  | "Sha256FeatureNotEnabled"
  | "KeccakFeatureNotEnabled";

export const CANONICAL_CLIENT_ERROR_CODES = Object.freeze([
  "CLIENT_KEYPAIR",
  "CLIENT_TRANSACTION",
  "CLIENT_HASHER",
  "CLIENT_UNSUPPORTED_SHAPE",
  "CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE",
  "CLIENT_TOO_MANY_INPUTS",
  "CLIENT_TOO_MANY_OUTPUTS",
  "CLIENT_INSUFFICIENT_BALANCE",
  "CLIENT_SELECTED_BALANCE_OVERFLOW",
  "CLIENT_UNSIGNED_INPUT_UNAVAILABLE",
  "CLIENT_FEE_PAYER_MISMATCH",
  "CLIENT_SOLANA_TRANSACTION_SIGNING",
  "CLIENT_AMBIGUOUS_TREE",
  "CLIENT_TREE_MISMATCH",
  "CLIENT_MISSING_SPL_TOKEN_ACCOUNT",
  "CLIENT_ADDRESS_RESOLUTION",
  "CLIENT_USER_REGISTRY_RECORD_NOT_FOUND",
  "CLIENT_MULTIPLE_PUBLIC_SPL_ASSETS",
  "CLIENT_WITHDRAWAL_ALREADY_SET",
  "CLIENT_NO_INPUTS",
  "CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED",
  "CLIENT_MISSING_P256_SIGNATURE",
  "CLIENT_MERGE_INPUT_RAIL_MISMATCH",
  "CLIENT_MERGE_INPUT_ASSET_MISMATCH",
  "CLIENT_MERGE_DISABLED",
  "CLIENT_NOTHING_TO_MERGE",
  "CLIENT_DUPLICATE_INPUT_UTXO",
  "CLIENT_MERGE_SIGNING_KEY_MISMATCH",
  "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
  "CLIENT_MERGE_VIEWING_KEY_MISMATCH",
  "CLIENT_MERGE_TREE_MISMATCH",
  "CLIENT_SPLIT_NOT_DIVISIBLE",
  "CLIENT_INPUT_UTXO_UNAVAILABLE",
  "CLIENT_INPUT_UTXO_TREE_MISMATCH",
  "CLIENT_SPLIT_INPUT_HAS_DATA",
  "CLIENT_SPLIT_INPUT_ZONE_MISMATCH",
  "CLIENT_P256_SIGNATURE",
  "CLIENT_FIELD_TOO_LONG",
  "CLIENT_INVALID_FIELD",
  "CLIENT_PROVER_SERVER",
  "CLIENT_PROOF_PARSE",
  "CLIENT_PROVER",
  "CLIENT_MISSING_INPUT_MERKLE_PROOF",
  "CLIENT_INCOMPLETE_INPUT_PROOFS",
  "CLIENT_STATE_PROOF_LEAF_MISMATCH",
  "CLIENT_STATE_PROOF_TREE_MISMATCH",
  "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH",
  "CLIENT_NULLIFIER_PROOF_TREE_MISMATCH",
  "CLIENT_INPUT_TREE_INDEX_COUNT_MISMATCH",
  "CLIENT_MISSING_OUTPUT",
  "CLIENT_RPC",
  "CLIENT_INDEXER",
  "CLIENT_UNSUPPORTED_RPC_METHOD",
  "CLIENT_INDEXER_TIMEOUT",
  "CLIENT_CONFIRMATION_TIMEOUT",
  "CLIENT_INDEXER_NOT_CAUGHT_UP",
  "CLIENT_POLL_TIMED_OUT",
  "CLIENT_PROOF_PATH_LENGTH",
  "CLIENT_PROOF_INPUT_COUNT_MISMATCH",
  "CLIENT_ACCOUNT_NOT_FOUND",
  "CLIENT_DEPOSIT_SENDER_NOT_SIGNER",
] as const);

export type CanonicalClientErrorCode = (typeof CANONICAL_CLIENT_ERROR_CODES)[number];

export interface ClientErrorDetailsMap {
  readonly CLIENT_KEYPAIR: Readonly<{ code: KeypairErrorCode }>;
  readonly CLIENT_TRANSACTION: Readonly<{ code: TransactionErrorCode }>;
  readonly CLIENT_HASHER: Readonly<{ code: HasherErrorCode }>;
  readonly CLIENT_UNSUPPORTED_SHAPE: Readonly<{ nIn: number; nOut: number }>;
  readonly CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE: Readonly<{ nIn: number; nOut: number }>;
  readonly CLIENT_TOO_MANY_INPUTS: Readonly<{ got: number; max: number }>;
  readonly CLIENT_TOO_MANY_OUTPUTS: Readonly<{ got: number; max: number }>;
  readonly CLIENT_INSUFFICIENT_BALANCE: Readonly<{ requested: string; available: string }>;
  readonly CLIENT_SELECTED_BALANCE_OVERFLOW: NoDetails;
  readonly CLIENT_UNSIGNED_INPUT_UNAVAILABLE: IndexDetails;
  readonly CLIENT_FEE_PAYER_MISMATCH: NoDetails;
  readonly CLIENT_SOLANA_TRANSACTION_SIGNING: Readonly<{ reason: string }>;
  readonly CLIENT_AMBIGUOUS_TREE: Readonly<{ asset: string; treeCount: number }>;
  readonly CLIENT_TREE_MISMATCH: Readonly<{ transactionTree: string; clientTree: string }>;
  readonly CLIENT_MISSING_SPL_TOKEN_ACCOUNT: Readonly<{ mint: string }>;
  readonly CLIENT_ADDRESS_RESOLUTION: Readonly<{ reason: string }>;
  readonly CLIENT_USER_REGISTRY_RECORD_NOT_FOUND: Readonly<{ owner: string; record: string }>;
  readonly CLIENT_MULTIPLE_PUBLIC_SPL_ASSETS: NoDetails;
  readonly CLIENT_WITHDRAWAL_ALREADY_SET: NoDetails;
  readonly CLIENT_NO_INPUTS: NoDetails;
  readonly CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED: IndexDetails;
  readonly CLIENT_MISSING_P256_SIGNATURE: NoDetails;
  readonly CLIENT_MERGE_INPUT_RAIL_MISMATCH: IndexDetails;
  readonly CLIENT_MERGE_INPUT_ASSET_MISMATCH: IndexDetails;
  readonly CLIENT_MERGE_DISABLED: Readonly<{ owner: string }>;
  readonly CLIENT_NOTHING_TO_MERGE: Readonly<{ asset: string }>;
  readonly CLIENT_DUPLICATE_INPUT_UTXO: HashDetails;
  readonly CLIENT_MERGE_SIGNING_KEY_MISMATCH: NoDetails;
  readonly CLIENT_MERGE_NULLIFIER_KEY_MISMATCH: NoDetails;
  readonly CLIENT_MERGE_VIEWING_KEY_MISMATCH: Readonly<{ owner: string }>;
  readonly CLIENT_MERGE_TREE_MISMATCH: Readonly<{ proofTree: string; submitTree: string }>;
  readonly CLIENT_SPLIT_NOT_DIVISIBLE: Readonly<{ amount: string; parts: number }>;
  readonly CLIENT_INPUT_UTXO_UNAVAILABLE: HashDetails;
  readonly CLIENT_INPUT_UTXO_TREE_MISMATCH: Readonly<{
    hash: string;
    utxoTree: string;
    spendTree: string;
  }>;
  readonly CLIENT_SPLIT_INPUT_HAS_DATA: HashDetails;
  readonly CLIENT_SPLIT_INPUT_ZONE_MISMATCH: HashDetails;
  readonly CLIENT_P256_SIGNATURE: Readonly<{ reason: string }>;
  readonly CLIENT_FIELD_TOO_LONG:
    | Readonly<{
        field?: string;
        actual?: number;
        maximum?: number;
      }>
    | undefined;
  readonly CLIENT_INVALID_FIELD:
    | Readonly<{
        field?: string;
        value?: string;
      }>
    | undefined;
  readonly CLIENT_PROVER_SERVER: Readonly<{
    method?: string;
    status?: number | "failed";
    reason?: string;
  }>;
  readonly CLIENT_PROOF_PARSE: Readonly<{ path?: string; reason?: string }>;
  readonly CLIENT_PROVER: Readonly<{ reason: string }>;
  readonly CLIENT_MISSING_INPUT_MERKLE_PROOF: IndexDetails;
  readonly CLIENT_INCOMPLETE_INPUT_PROOFS: Readonly<{
    expected: number;
    state: number;
    nullifier: number;
  }>;
  readonly CLIENT_STATE_PROOF_LEAF_MISMATCH: IndexDetails;
  readonly CLIENT_STATE_PROOF_TREE_MISMATCH: IndexDetails;
  readonly CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH: IndexDetails;
  readonly CLIENT_NULLIFIER_PROOF_TREE_MISMATCH: IndexDetails;
  readonly CLIENT_INPUT_TREE_INDEX_COUNT_MISMATCH: Readonly<{
    expected: number;
    actual: number;
  }>;
  readonly CLIENT_MISSING_OUTPUT: NoDetails;
  readonly CLIENT_RPC: Readonly<{ method?: string; reason?: string }>;
  /** Carries no response text: an indexer body can hold caller data. */
  readonly CLIENT_INDEXER: Readonly<{ method: string; retryable: boolean }>;
  readonly CLIENT_UNSUPPORTED_RPC_METHOD: MethodDetails;
  readonly CLIENT_INDEXER_TIMEOUT:
    | Readonly<{
        signature?: string;
        expectedTags?: number;
        attempts?: number;
      }>
    | undefined;
  readonly CLIENT_CONFIRMATION_TIMEOUT:
    | Readonly<{
        signature?: string;
        attempts?: number;
      }>
    | undefined;
  readonly CLIENT_INDEXER_NOT_CAUGHT_UP: Readonly<{
    target: string;
    latest: string;
    attempts: number;
  }>;
  readonly CLIENT_POLL_TIMED_OUT: Readonly<{
    attempts: number;
    lastCause?: RetryErrorCause;
  }>;
  readonly CLIENT_PROOF_PATH_LENGTH: Readonly<{
    got: number;
    expected: number;
    index?: number;
    kind?: "state" | "nullifier";
  }>;
  readonly CLIENT_PROOF_INPUT_COUNT_MISMATCH: CountDetails;
  readonly CLIENT_ACCOUNT_NOT_FOUND: Readonly<{ address: string }>;
  readonly CLIENT_DEPOSIT_SENDER_NOT_SIGNER: Readonly<{ sender: string }>;

  readonly CLIENT_INVALID_CONFIG: Readonly<{ field?: string }> | undefined;
  readonly CLIENT_UNEXPECTED: NoDetails;
  readonly CLIENT_INVALID_INTEGER:
    | Readonly<{
        field?: string;
        value?: string;
        length?: number;
      }>
    | undefined;
  readonly CLIENT_INVALID_INPUT_CONTEXT: Readonly<{ index?: number }> | undefined;
  readonly CLIENT_INVALID_PROOF_INPUTS: NoDetails;
  readonly CLIENT_INVALID_MERGE: NoDetails;
  readonly CLIENT_MERGE_PROOF_COMMITMENT: NoDetails;
  readonly CLIENT_MERGE_OUTPUT_MISMATCH: NoDetails;
  readonly CLIENT_INVALID_TRANSACTION: NoDetails;
  readonly CLIENT_TOO_MANY_ACCOUNTS: NoDetails;
  readonly CLIENT_TRANSACTION_ASSEMBLY: NoDetails;
  readonly CLIENT_INCOMPLETE_SIGNATURES: Readonly<{
    required: number;
    provided: number;
    missingIndex?: number;
  }>;
  readonly CLIENT_INVALID_LENGTH: Readonly<{
    field: string;
    expected: number;
    actual: number;
  }>;
  readonly CLIENT_INVALID_BASE58:
    | Readonly<{
        field?: string;
        expectedLength?: number;
        actualLength?: number;
      }>
    | undefined;
  readonly CLIENT_INVALID_BASE64: Readonly<{ field: string }>;
  readonly CLIENT_INVALID_P256_KEY: NoDetails;
  readonly CLIENT_INVALID_CONTEXT: Readonly<{ field: string; method: string }>;
  readonly CLIENT_ABORTED: Readonly<{ method?: string; retryable?: boolean }> | undefined;
  readonly CLIENT_TIMEOUT: Readonly<{ method: string; retryable: boolean }>;
  readonly CLIENT_REQUEST: Readonly<{ method: string; retryable: boolean }>;
  readonly CLIENT_INVALID_POLL_CONFIG: Readonly<{ field: string; value?: string }>;
  readonly CLIENT_INVALID_INDEXER: Readonly<{ field: string }>;
  readonly CLIENT_PROOF_RAIL_MISMATCH: Readonly<{ expected?: "p256" | "eddsa" }> | undefined;
  readonly CLIENT_PROOF_POINT: Readonly<{ field: string }>;
  readonly CLIENT_PROOF_TREE_MISMATCH: IndexDetails;
  readonly CLIENT_INVALID_MERGE_OUTPUT: NoDetails;
  readonly CLIENT_INVALID_MERGE_CIPHERTEXT: Readonly<{ expected: number; actual: number }>;
  readonly CLIENT_INVALID_MERGE_MATERIAL: NoDetails;
  readonly CLIENT_MERGE_MATERIAL_VIEWING_KEY_MISMATCH: NoDetails;
  readonly CLIENT_INVALID_MERGE_SHAPE: Readonly<{ expected: number; actual: number }>;
  readonly CLIENT_PROVER_INPUT: NoDetails;
  readonly CLIENT_PROVER_REQUEST: Readonly<{ method: string; attempts: number }>;
  readonly CLIENT_PROVER_HTTP: Readonly<{
    method: string;
    status?: number;
    attempts?: number;
  }>;
  readonly CLIENT_PROVER_JOB: MethodDetails;
  readonly CLIENT_PROVER_TIMEOUT: Readonly<{
    method: string;
    jobId: string;
    timeoutMs: number;
  }>;
  readonly CLIENT_PROVER_RESPONSE_TOO_LARGE: NoDetails;
  readonly CLIENT_PROVER_TEXT: NoDetails;
  readonly CLIENT_PROVER_JSON: NoDetails;
  readonly CLIENT_INVALID_RPC_RESPONSE: Readonly<{
    path?: string;
    method?: string;
    expected?: number;
    actual?: number;
  }>;
  readonly CLIENT_RPC_TRANSACTION_NOT_FOUND: Readonly<{ signature: string }>;
  readonly CLIENT_RPC_HTTP: Readonly<{ method: string; status: number }>;
  readonly CLIENT_RPC_JSON: MethodDetails;
  readonly CLIENT_RPC_ENVELOPE: MethodDetails;
  readonly CLIENT_RPC_PROGRAM_ERROR: Readonly<{
    method: string;
    instructionIndex: number;
    programError: DecodedShieldedPoolError;
  }>;
  readonly CLIENT_RPC_TRANSACT_DECODE: NoDetails;
  readonly CLIENT_RPC_OWNER_TAG: NoDetails;
  readonly CLIENT_RPC_TRANSACT_NOT_FOUND: NoDetails;
}

export type ClientErrorCode = keyof ClientErrorDetailsMap;
export type ClientErrorDetails<Code extends ClientErrorCode = ClientErrorCode> =
  ClientErrorDetailsMap[Code];

export const TYPESCRIPT_CLIENT_ERROR_CODES = Object.freeze([
  "CLIENT_INVALID_CONFIG",
  "CLIENT_UNEXPECTED",
  "CLIENT_INVALID_INTEGER",
  "CLIENT_INVALID_INPUT_CONTEXT",
  "CLIENT_INVALID_PROOF_INPUTS",
  "CLIENT_INVALID_MERGE",
  "CLIENT_MERGE_PROOF_COMMITMENT",
  "CLIENT_MERGE_OUTPUT_MISMATCH",
  "CLIENT_INVALID_TRANSACTION",
  "CLIENT_TOO_MANY_ACCOUNTS",
  "CLIENT_TRANSACTION_ASSEMBLY",
  "CLIENT_INCOMPLETE_SIGNATURES",
  "CLIENT_INVALID_LENGTH",
  "CLIENT_INVALID_BASE58",
  "CLIENT_INVALID_BASE64",
  "CLIENT_INVALID_P256_KEY",
  "CLIENT_INVALID_CONTEXT",
  "CLIENT_ABORTED",
  "CLIENT_TIMEOUT",
  "CLIENT_REQUEST",
  "CLIENT_INVALID_POLL_CONFIG",
  "CLIENT_INVALID_INDEXER",
  "CLIENT_PROOF_RAIL_MISMATCH",
  "CLIENT_PROOF_POINT",
  "CLIENT_PROOF_TREE_MISMATCH",
  "CLIENT_INVALID_MERGE_OUTPUT",
  "CLIENT_INVALID_MERGE_CIPHERTEXT",
  "CLIENT_INVALID_MERGE_MATERIAL",
  "CLIENT_MERGE_MATERIAL_VIEWING_KEY_MISMATCH",
  "CLIENT_INVALID_MERGE_SHAPE",
  "CLIENT_PROVER_INPUT",
  "CLIENT_PROVER_REQUEST",
  "CLIENT_PROVER_HTTP",
  "CLIENT_PROVER_JOB",
  "CLIENT_PROVER_TIMEOUT",
  "CLIENT_PROVER_RESPONSE_TOO_LARGE",
  "CLIENT_PROVER_TEXT",
  "CLIENT_PROVER_JSON",
  "CLIENT_INVALID_RPC_RESPONSE",
  "CLIENT_RPC_TRANSACTION_NOT_FOUND",
  "CLIENT_RPC_HTTP",
  "CLIENT_RPC_JSON",
  "CLIENT_RPC_ENVELOPE",
  "CLIENT_RPC_PROGRAM_ERROR",
  "CLIENT_RPC_TRANSACT_DECODE",
  "CLIENT_RPC_OWNER_TAG",
  "CLIENT_RPC_TRANSACT_NOT_FOUND",
] as const satisfies readonly ClientErrorCode[]);

const CLIENT_ERROR_CODE_SET: ReadonlySet<string> = new Set([
  ...CANONICAL_CLIENT_ERROR_CODES,
  ...TYPESCRIPT_CLIENT_ERROR_CODES,
]);

/** The three transient causes Rust's `RetryErrorCause` can hold. */
export type RetryErrorCause = Readonly<{ category: "rpc" | "indexer" | "indexerTimeout" }>;

export type ClientErrorCause =
  | Readonly<{ category: "client"; code: ClientErrorCode }>
  | Readonly<{
      category: "keypair";
      code: KeypairErrorCode;
      details?: Readonly<Record<string, unknown>>;
    }>
  | Readonly<{
      category: "transaction";
      code: TransactionErrorCode;
      details?: Readonly<Record<string, unknown>>;
    }>
  | Readonly<{ category: "hasher"; code: HasherErrorCode }>
  | RetryErrorCause
  | Readonly<{ category: "external"; code?: string }>;

type ClientErrorOptions<Code extends ClientErrorCode> = Readonly<{
  details?: Exclude<ClientErrorDetails<Code>, undefined>;
  cause?: unknown;
}>;

type ClientErrorArguments<Code extends ClientErrorCode> =
  undefined extends ClientErrorDetails<Code>
    ? readonly [options?: ClientErrorOptions<Code>]
    : readonly [
        options: Readonly<{
          details: ClientErrorDetails<Code>;
          cause?: unknown;
        }>,
      ];

type FieldKind = "boolean" | "number" | "object" | "retryCause" | "string";
type DetailShape = Readonly<Record<string, FieldKind>>;

const NO_DETAIL_CODES: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_SELECTED_BALANCE_OVERFLOW",
  "CLIENT_FEE_PAYER_MISMATCH",
  "CLIENT_MULTIPLE_PUBLIC_SPL_ASSETS",
  "CLIENT_WITHDRAWAL_ALREADY_SET",
  "CLIENT_NO_INPUTS",
  "CLIENT_MISSING_P256_SIGNATURE",
  "CLIENT_MERGE_SIGNING_KEY_MISMATCH",
  "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
  "CLIENT_MISSING_OUTPUT",
  "CLIENT_INVALID_PROOF_INPUTS",
  "CLIENT_INVALID_MERGE",
  "CLIENT_MERGE_PROOF_COMMITMENT",
  "CLIENT_MERGE_OUTPUT_MISMATCH",
  "CLIENT_INVALID_TRANSACTION",
  "CLIENT_TOO_MANY_ACCOUNTS",
  "CLIENT_TRANSACTION_ASSEMBLY",
  "CLIENT_INVALID_P256_KEY",
  "CLIENT_INVALID_MERGE_OUTPUT",
  "CLIENT_INVALID_MERGE_MATERIAL",
  "CLIENT_MERGE_MATERIAL_VIEWING_KEY_MISMATCH",
  "CLIENT_PROVER_INPUT",
  "CLIENT_PROVER_RESPONSE_TOO_LARGE",
  "CLIENT_PROVER_TEXT",
  "CLIENT_PROVER_JSON",
  "CLIENT_RPC_TRANSACT_DECODE",
  "CLIENT_RPC_OWNER_TAG",
  "CLIENT_RPC_TRANSACT_NOT_FOUND",
  "CLIENT_UNEXPECTED",
]);

const OPTIONAL_DETAIL_CODES: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_FIELD_TOO_LONG",
  "CLIENT_INVALID_FIELD",
  "CLIENT_INDEXER_TIMEOUT",
  "CLIENT_CONFIRMATION_TIMEOUT",
  "CLIENT_INVALID_CONFIG",
  "CLIENT_INVALID_INTEGER",
  "CLIENT_INVALID_INPUT_CONTEXT",
  "CLIENT_INVALID_BASE58",
  "CLIENT_ABORTED",
  "CLIENT_PROOF_RAIL_MISMATCH",
]);

const DETAIL_SHAPES: Partial<Readonly<Record<ClientErrorCode, DetailShape>>> = {
  CLIENT_KEYPAIR: { code: "string" },
  CLIENT_TRANSACTION: { code: "string" },
  CLIENT_HASHER: { code: "string" },
  CLIENT_UNSUPPORTED_SHAPE: { nIn: "number", nOut: "number" },
  CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE: { nIn: "number", nOut: "number" },
  CLIENT_TOO_MANY_INPUTS: { got: "number", max: "number" },
  CLIENT_TOO_MANY_OUTPUTS: { got: "number", max: "number" },
  CLIENT_INSUFFICIENT_BALANCE: { requested: "string", available: "string" },
  CLIENT_UNSIGNED_INPUT_UNAVAILABLE: { index: "number" },
  CLIENT_SOLANA_TRANSACTION_SIGNING: { reason: "string" },
  CLIENT_INCOMPLETE_SIGNATURES: {
    required: "number",
    provided: "number",
    missingIndex: "number",
  },
  CLIENT_AMBIGUOUS_TREE: { asset: "string", treeCount: "number" },
  CLIENT_TREE_MISMATCH: { transactionTree: "string", clientTree: "string" },
  CLIENT_MISSING_SPL_TOKEN_ACCOUNT: { mint: "string" },
  CLIENT_ADDRESS_RESOLUTION: { reason: "string" },
  CLIENT_USER_REGISTRY_RECORD_NOT_FOUND: { owner: "string", record: "string" },
  CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED: { index: "number" },
  CLIENT_MERGE_INPUT_RAIL_MISMATCH: { index: "number" },
  CLIENT_MERGE_INPUT_ASSET_MISMATCH: { index: "number" },
  CLIENT_MERGE_DISABLED: { owner: "string" },
  CLIENT_NOTHING_TO_MERGE: { asset: "string" },
  CLIENT_DUPLICATE_INPUT_UTXO: { hash: "string" },
  CLIENT_MERGE_VIEWING_KEY_MISMATCH: { owner: "string" },
  CLIENT_MERGE_TREE_MISMATCH: { proofTree: "string", submitTree: "string" },
  CLIENT_SPLIT_NOT_DIVISIBLE: { amount: "string", parts: "number" },
  CLIENT_INPUT_UTXO_UNAVAILABLE: { hash: "string" },
  CLIENT_INPUT_UTXO_TREE_MISMATCH: { hash: "string", utxoTree: "string", spendTree: "string" },
  CLIENT_SPLIT_INPUT_HAS_DATA: { hash: "string" },
  CLIENT_SPLIT_INPUT_ZONE_MISMATCH: { hash: "string" },
  CLIENT_P256_SIGNATURE: { reason: "string" },
  CLIENT_FIELD_TOO_LONG: { field: "string", actual: "number", maximum: "number" },
  CLIENT_PROVER_SERVER: { method: "string", status: "number", reason: "string" },
  CLIENT_PROOF_PARSE: { path: "string", reason: "string" },
  CLIENT_PROVER: { reason: "string" },
  CLIENT_MISSING_INPUT_MERKLE_PROOF: { index: "number" },
  CLIENT_INCOMPLETE_INPUT_PROOFS: { expected: "number", state: "number", nullifier: "number" },
  CLIENT_STATE_PROOF_LEAF_MISMATCH: { index: "number" },
  CLIENT_STATE_PROOF_TREE_MISMATCH: { index: "number" },
  CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH: { index: "number" },
  CLIENT_NULLIFIER_PROOF_TREE_MISMATCH: { index: "number" },
  CLIENT_INPUT_TREE_INDEX_COUNT_MISMATCH: { expected: "number", actual: "number" },
  CLIENT_RPC: { method: "string", reason: "string" },
  CLIENT_INDEXER: { method: "string", retryable: "boolean" },
  CLIENT_UNSUPPORTED_RPC_METHOD: { method: "string" },
  CLIENT_INDEXER_TIMEOUT: { signature: "string", expectedTags: "number", attempts: "number" },
  CLIENT_INDEXER_NOT_CAUGHT_UP: { target: "string", latest: "string", attempts: "number" },
  CLIENT_POLL_TIMED_OUT: { attempts: "number", lastCause: "retryCause" },
  CLIENT_PROOF_PATH_LENGTH: { got: "number", expected: "number", index: "number", kind: "string" },
  CLIENT_PROOF_INPUT_COUNT_MISMATCH: { got: "number", expected: "number" },
  CLIENT_ACCOUNT_NOT_FOUND: { address: "string" },
  CLIENT_DEPOSIT_SENDER_NOT_SIGNER: { sender: "string" },
  CLIENT_INVALID_CONFIG: { field: "string" },
  CLIENT_INVALID_INTEGER: { field: "string", value: "string", length: "number" },
  CLIENT_INVALID_INPUT_CONTEXT: { index: "number" },
  CLIENT_CONFIRMATION_TIMEOUT: { signature: "string", attempts: "number" },
  CLIENT_INVALID_LENGTH: { field: "string", expected: "number", actual: "number" },
  CLIENT_INVALID_FIELD: { field: "string", value: "string" },
  CLIENT_INVALID_BASE58: { field: "string", expectedLength: "number", actualLength: "number" },
  CLIENT_INVALID_BASE64: { field: "string" },
  CLIENT_INVALID_CONTEXT: { field: "string", method: "string" },
  CLIENT_ABORTED: { method: "string", retryable: "boolean" },
  CLIENT_TIMEOUT: { method: "string", retryable: "boolean" },
  CLIENT_REQUEST: { method: "string", retryable: "boolean" },
  CLIENT_INVALID_POLL_CONFIG: { field: "string", value: "string" },
  CLIENT_INVALID_INDEXER: { field: "string" },
  CLIENT_PROOF_RAIL_MISMATCH: { expected: "string" },
  CLIENT_PROOF_POINT: { field: "string" },
  CLIENT_PROOF_TREE_MISMATCH: { index: "number" },
  CLIENT_INVALID_MERGE_CIPHERTEXT: { expected: "number", actual: "number" },
  CLIENT_INVALID_MERGE_SHAPE: { expected: "number", actual: "number" },
  CLIENT_PROVER_REQUEST: { method: "string", attempts: "number" },
  CLIENT_PROVER_HTTP: { method: "string", status: "number", attempts: "number" },
  CLIENT_PROVER_JOB: { method: "string" },
  CLIENT_PROVER_TIMEOUT: { method: "string", jobId: "string", timeoutMs: "number" },
  CLIENT_INVALID_RPC_RESPONSE: {
    path: "string",
    method: "string",
    expected: "number",
    actual: "number",
  },
  CLIENT_RPC_TRANSACTION_NOT_FOUND: { signature: "string" },
  CLIENT_RPC_HTTP: { method: "string", status: "number" },
  CLIENT_RPC_JSON: { method: "string" },
  CLIENT_RPC_ENVELOPE: { method: "string" },
  CLIENT_RPC_PROGRAM_ERROR: {
    method: "string",
    instructionIndex: "number",
    programError: "object",
  },
};

const REQUIRED_DETAIL_FIELDS: Partial<Readonly<Record<ClientErrorCode, readonly string[]>>> = {
  CLIENT_PROVER_SERVER: [],
  CLIENT_PROOF_PARSE: [],
  CLIENT_RPC: [],
  CLIENT_FIELD_TOO_LONG: [],
  CLIENT_INVALID_FIELD: [],
  CLIENT_INDEXER_TIMEOUT: [],
  CLIENT_CONFIRMATION_TIMEOUT: [],
  CLIENT_PROOF_PATH_LENGTH: ["got", "expected"],
  CLIENT_POLL_TIMED_OUT: ["attempts"],
  CLIENT_INVALID_CONFIG: [],
  CLIENT_INVALID_INTEGER: [],
  CLIENT_INVALID_INPUT_CONTEXT: [],
  CLIENT_INVALID_BASE58: [],
  CLIENT_ABORTED: [],
  CLIENT_INVALID_POLL_CONFIG: ["field"],
  CLIENT_PROOF_RAIL_MISMATCH: [],
  CLIENT_PROVER_HTTP: ["method"],
  CLIENT_INVALID_RPC_RESPONSE: [],
  CLIENT_INCOMPLETE_SIGNATURES: ["required", "provided"],
};

export class ClientError<Code extends ClientErrorCode = ClientErrorCode> extends Error {
  readonly code: Code;
  readonly details: ClientErrorDetails<Code> | undefined;
  override readonly cause: ClientErrorCause | undefined;

  constructor(code: Code, ...[options = {}]: ClientErrorArguments<Code>) {
    validateClientError(code, options.details);
    const cause = safeCause(options.cause);
    super(code, cause === undefined ? undefined : { cause });
    this.name = "ClientError";
    this.code = code;
    this.details =
      options.details === undefined
        ? undefined
        : (copyAndFreeze(options.details) as ClientErrorDetails<Code>);
    this.cause = cause;
  }
}

export function fromClientCause(cause: unknown): ClientError {
  if (isClientError(cause)) return cause;
  if (cause instanceof KeypairError) {
    return new ClientError("CLIENT_KEYPAIR", {
      details: { code: cause.code },
      cause,
    });
  }
  if (cause instanceof TransactionError) {
    return new ClientError("CLIENT_TRANSACTION", {
      details: { code: cause.code },
      cause,
    });
  }
  return new ClientError("CLIENT_UNEXPECTED", { cause });
}

export function hasherError(code: HasherErrorCode, cause?: unknown): ClientError {
  return new ClientError("CLIENT_HASHER", {
    details: { code },
    cause: { category: "hasher", code, cause },
  });
}

function safeCause(cause: unknown): ClientErrorCause | undefined {
  if (isClientError(cause)) {
    return Object.freeze({ category: "client", code: cause.code });
  }
  if (cause instanceof KeypairError) {
    return Object.freeze({
      category: "keypair",
      code: cause.code,
      ...safeDetails(cause.details),
    });
  }
  if (cause instanceof TransactionError) {
    return Object.freeze({
      category: "transaction",
      code: cause.code,
      ...safeDetails(cause.details),
    });
  }
  if (
    typeof cause === "object" &&
    cause !== null &&
    "category" in cause &&
    cause.category === "hasher" &&
    "code" in cause &&
    isHasherErrorCode(cause.code)
  ) {
    return Object.freeze({ category: "hasher", code: cause.code });
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

export function isClientError(value: unknown): value is ClientError {
  return value instanceof ClientError;
}

function safeDetails(
  details: Readonly<Record<string, unknown>> | undefined,
): Readonly<{ details?: Readonly<Record<string, unknown>> }> {
  if (details === undefined) return Object.freeze({});
  const sanitized = sanitizeDetails(details);
  return Object.keys(sanitized).length === 0
    ? Object.freeze({})
    : Object.freeze({ details: sanitized });
}

function validateClientError(code: unknown, details: unknown): asserts code is ClientErrorCode {
  if (typeof code !== "string" || !CLIENT_ERROR_CODE_SET.has(code)) {
    throw new TypeError("invalid ClientError code");
  }
  const typedCode = code as ClientErrorCode;
  const noDetails = NO_DETAIL_CODES.has(typedCode);
  const shape = DETAIL_SHAPES[typedCode];
  if (details === undefined) {
    if (noDetails || OPTIONAL_DETAIL_CODES.has(typedCode)) return;
    throw new TypeError(`missing details for ${code}`);
  }
  if (noDetails || shape === undefined || !isPlainObject(details)) {
    throw new TypeError(`invalid details for ${code}`);
  }
  const required = REQUIRED_DETAIL_FIELDS[typedCode] ?? Object.keys(shape);
  for (const field of required) {
    if (!Object.hasOwn(details, field)) throw new TypeError(`missing ${code}.${field}`);
  }
  for (const [field, value] of ownDataEntries(details)) {
    const kind = shape[field];
    if (kind === undefined || !matchesFieldKind(value, kind, field)) {
      throw new TypeError(`invalid ${code}.${field}`);
    }
  }
}

function matchesFieldKind(value: unknown, kind: FieldKind, field: string): boolean {
  if (field === "status" && value === "failed") return true;
  if (kind === "number") return typeof value === "number" && Number.isSafeInteger(value);
  if (kind === "retryCause") return isRetryErrorCause(value);
  if (kind === "object") return isPlainObject(value);
  return typeof value === kind;
}

function isRetryErrorCause(value: unknown): value is RetryErrorCause {
  if (!isPlainObject(value) || Object.keys(value).length !== 1) return false;
  const category = value["category"];
  return category === "rpc" || category === "indexer" || category === "indexerTimeout";
}

function copyAndFreeze(
  value: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const copy: Record<string, unknown> = {};
  for (const [key, item] of ownDataEntries(value)) {
    copy[key] = cloneSafeValue(item);
  }
  return Object.freeze(copy);
}

function cloneSafeValue(value: unknown): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value;
  }
  if (Array.isArray(value)) return Object.freeze(value.map(cloneSafeValue));
  if (isPlainObject(value)) return copyAndFreeze(value);
  throw new TypeError("ClientError details must contain safe data");
}

/**
 * Fail-closed allow-list for wrapped cause details. Matches `@zolana/keypair`'s
 * policy (known keys, primitives only) and admits the small set of transaction
 * diagnostic keys the wrap path already forwards. Unknown keys and nested
 * values drop rather than surviving a deny-list walk.
 */
const CAUSE_DETAIL_KEYS = Object.freeze([
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
] as const);

function sanitizeDetails(
  details: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const safe: Record<string, string | number> = {};
  for (const key of CAUSE_DETAIL_KEYS) {
    const value = details[key];
    if (typeof value === "number" || typeof value === "string") {
      safe[key] = value;
    }
  }
  return Object.freeze(safe);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function ownDataEntries(value: Record<string, unknown>): readonly (readonly [string, unknown])[] {
  return Object.entries(Object.getOwnPropertyDescriptors(value))
    .filter(([, descriptor]) => descriptor.enumerable)
    .map(([key, descriptor]) => {
      if (!("value" in descriptor)) throw new TypeError("ClientError details cannot use accessors");
      return [key, descriptor.value] as const;
    });
}

function isHasherErrorCode(value: unknown): value is HasherErrorCode {
  return (
    typeof value === "string" &&
    [
      "IntegerOverflow",
      "Poseidon",
      "PoseidonSyscall",
      "UnknownSolanaSyscall",
      "InvalidInputLength",
      "InvalidNumFields",
      "EmptyInput",
      "BorshError",
      "OptionHashToFieldSizeZero",
      "PoseidonFeatureNotEnabled",
      "Sha256FeatureNotEnabled",
      "KeccakFeatureNotEnabled",
    ].includes(value)
  );
}
