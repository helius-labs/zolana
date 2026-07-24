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

export interface ClientErrorDetailsMap {
  readonly CLIENT_KEYPAIR: Readonly<{ code: KeypairErrorCode }>;
  readonly CLIENT_TRANSACTION: Readonly<{ code: TransactionErrorCode }>;
  readonly CLIENT_HASHER: Readonly<{ code: HasherErrorCode }>;
  readonly CLIENT_UNSUPPORTED_SHAPE: Readonly<{ nIn: number; nOut: number }>;
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
  readonly CLIENT_FIELD_TOO_LONG: Readonly<{
    field?: string;
    actual?: number;
    maximum?: number;
  }>;
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
  readonly CLIENT_INDEXER: MethodDetails;
  readonly CLIENT_UNSUPPORTED_RPC_METHOD: MethodDetails;
  readonly CLIENT_INDEXER_TIMEOUT: Readonly<{
    signature?: string;
    expectedTags?: number;
    attempts?: number;
  }>;
  readonly CLIENT_INDEXER_NOT_CAUGHT_UP: Readonly<{
    target: string;
    latest: string;
    attempts: number;
  }>;
  readonly CLIENT_POLL_TIMED_OUT: Readonly<{
    attempts: number;
    lastError?: string;
  }>;
  readonly CLIENT_PROOF_PATH_LENGTH: Readonly<{
    got: number;
    expected: number;
    index?: number;
    kind?: "state" | "nullifier";
  }>;
  readonly CLIENT_WITNESS_INPUT_COUNT_MISMATCH: CountDetails;
  readonly CLIENT_ACCOUNT_NOT_FOUND: Readonly<{ address: string }>;
  readonly CLIENT_DEPOSIT_SENDER_NOT_SIGNER: Readonly<{ sender: string }>;

  readonly CLIENT_INVALID_CONFIG: Readonly<{ field?: string }> | undefined;
  readonly CLIENT_UNEXPECTED: NoDetails;
  readonly CLIENT_INVALID_INTEGER: Readonly<{
    field?: string;
    value?: string;
    length?: number;
  }>;
  readonly CLIENT_INVALID_INPUT_CONTEXT: Readonly<{ index?: number }>;
  readonly CLIENT_INVALID_PROOF_INPUTS: NoDetails;
  readonly CLIENT_INVALID_MERGE: NoDetails;
  readonly CLIENT_MERGE_PROOF_COMMITMENT: NoDetails;
  readonly CLIENT_MERGE_OUTPUT_MISMATCH: NoDetails;
  readonly CLIENT_INVALID_TRANSACTION: NoDetails;
  readonly CLIENT_CONFIRMATION_TIMEOUT: Readonly<{
    signature: string;
    attempts: number;
  }>;
  readonly CLIENT_TOO_MANY_ACCOUNTS: NoDetails;
  readonly CLIENT_TRANSACTION_ASSEMBLY: NoDetails;
  readonly CLIENT_INVALID_LENGTH: Readonly<{
    field: string;
    expected: number;
    actual: number;
  }>;
  readonly CLIENT_INVALID_FIELD: Readonly<{ field: string; value: string }>;
  readonly CLIENT_INVALID_BASE58: Readonly<{
    field?: string;
    expectedLength?: number;
    actualLength?: number;
  }>;
  readonly CLIENT_INVALID_BASE64: Readonly<{ field: string }>;
  readonly CLIENT_INVALID_P256_KEY: NoDetails;
  readonly CLIENT_INVALID_CONTEXT: Readonly<{ field: string; method: string }>;
  readonly CLIENT_ABORTED: Readonly<{ method?: string }> | undefined;
  readonly CLIENT_TIMEOUT: Readonly<{ method: string; retryable: boolean }>;
  readonly CLIENT_REQUEST: Readonly<{ method: string; retryable: boolean }>;
  readonly CLIENT_INVALID_POLL_CONFIG: Readonly<{ field: string; value?: string }>;
  readonly CLIENT_INVALID_INDEXER: Readonly<{ field: string }>;
  readonly CLIENT_PROOF_RAIL_MISMATCH: Readonly<{ expected?: "p256" | "eddsa" }>;
  readonly CLIENT_PROOF_POINT: Readonly<{ field: string }>;
  readonly CLIENT_PROOF_TREE_MISMATCH: IndexDetails;
  readonly CLIENT_PUBLIC_SPL_ASSET: NoDetails;
  readonly CLIENT_INVALID_MERGE_OUTPUT: NoDetails;
  readonly CLIENT_INVALID_MERGE_CIPHERTEXT: Readonly<{ expected: number; actual: number }>;
  readonly CLIENT_INVALID_MERGE_MATERIAL: NoDetails;
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
  readonly CLIENT_RPC_TRANSACT_DECODE: NoDetails;
  readonly CLIENT_RPC_OWNER_TAG: NoDetails;
  readonly CLIENT_RPC_TRANSACT_NOT_FOUND: NoDetails;
}

export type ClientErrorCode = keyof ClientErrorDetailsMap;
export type ClientErrorDetails<Code extends ClientErrorCode = ClientErrorCode> =
  ClientErrorDetailsMap[Code];

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
  | Readonly<{ category: "external"; code?: string }>;

type ClientErrorOptions<Code extends ClientErrorCode> = Readonly<{
  details?: Exclude<ClientErrorDetails<Code>, undefined>;
  cause?: unknown;
}>;

export class ClientError<Code extends ClientErrorCode = ClientErrorCode> extends Error {
  readonly code: Code;
  readonly details: ClientErrorDetails<Code> | undefined;
  override readonly cause: ClientErrorCause | undefined;

  constructor(code: Code, options: ClientErrorOptions<Code> = {}) {
    const cause = safeCause(options.cause);
    super(code, cause === undefined ? undefined : { cause });
    this.name = "ClientError";
    this.code = code;
    this.details =
      options.details === undefined
        ? undefined
        : (Object.freeze({ ...options.details }) as unknown as ClientErrorDetails<Code>);
    this.cause = cause;
  }
}

export function fromClientCause(cause: unknown): ClientError {
  if (cause instanceof ClientError) return cause;
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
  return new ClientError("CLIENT_HASHER", { details: { code }, cause });
}

function safeCause(cause: unknown): ClientErrorCause | undefined {
  if (cause instanceof ClientError) {
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
    "code" in cause &&
    typeof cause.code === "string"
  ) {
    return Object.freeze({ category: "external", code: cause.code });
  }
  return cause === undefined ? undefined : Object.freeze({ category: "external" });
}

function safeDetails(
  details: Readonly<Record<string, unknown>> | undefined,
): Readonly<{ details?: Readonly<Record<string, unknown>> }> {
  if (details === undefined) return Object.freeze({});
  const safe = Object.fromEntries(
    Object.entries(details).filter(
      ([key, value]) =>
        !/(secret|private|seed|blinding|nonce|scalar)/iu.test(key) &&
        (typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "bigint" ||
          typeof value === "boolean" ||
          value === null),
    ),
  );
  return Object.freeze({ details: Object.freeze(safe) });
}
