import { type KeypairErrorCode } from "../keypair/error.js";
import { type TransactionErrorCode } from "../transaction/error.js";
type NoDetails = undefined;
type IndexDetails = Readonly<{
    index: number;
}>;
type CountDetails = Readonly<{
    got: number;
    expected: number;
}>;
type MethodDetails = Readonly<{
    method: string;
}>;
export type HasherErrorCode = "InvalidNumFields" | "EmptyInput";
export declare const CANONICAL_CLIENT_ERROR_CODES: readonly ["CLIENT_KEYPAIR", "CLIENT_TRANSACTION", "CLIENT_HASHER", "CLIENT_FEE_PAYER_MISMATCH", "CLIENT_TREE_MISMATCH", "CLIENT_NO_INPUTS", "CLIENT_MERGE_SIGNING_KEY_MISMATCH", "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH", "CLIENT_MERGE_TREE_MISMATCH", "CLIENT_FIELD_TOO_LONG", "CLIENT_PROVER_SERVER", "CLIENT_PROOF_PARSE", "CLIENT_MISSING_INPUT_MERKLE_PROOF", "CLIENT_INCOMPLETE_INPUT_PROOFS", "CLIENT_STATE_PROOF_LEAF_MISMATCH", "CLIENT_STATE_PROOF_TREE_MISMATCH", "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", "CLIENT_NULLIFIER_PROOF_TREE_MISMATCH", "CLIENT_MISSING_OUTPUT", "CLIENT_RPC", "CLIENT_INDEXER", "CLIENT_UNSUPPORTED_RPC_METHOD", "CLIENT_INDEXER_TIMEOUT", "CLIENT_INDEXER_NOT_CAUGHT_UP", "CLIENT_POLL_TIMED_OUT", "CLIENT_PROOF_PATH_LENGTH", "CLIENT_PROOF_INPUT_COUNT_MISMATCH"];
export type CanonicalClientErrorCode = (typeof CANONICAL_CLIENT_ERROR_CODES)[number];
export interface ClientErrorDetailsMap {
    readonly CLIENT_KEYPAIR: Readonly<{
        code: KeypairErrorCode;
    }>;
    readonly CLIENT_TRANSACTION: Readonly<{
        code: TransactionErrorCode;
    }>;
    readonly CLIENT_HASHER: Readonly<{
        code: HasherErrorCode;
    }>;
    readonly CLIENT_FEE_PAYER_MISMATCH: NoDetails;
    readonly CLIENT_TREE_MISMATCH: Readonly<{
        transactionTree: string;
        clientTree: string;
    }>;
    readonly CLIENT_NO_INPUTS: NoDetails;
    readonly CLIENT_MERGE_SIGNING_KEY_MISMATCH: NoDetails;
    readonly CLIENT_MERGE_NULLIFIER_KEY_MISMATCH: NoDetails;
    readonly CLIENT_MERGE_TREE_MISMATCH: Readonly<{
        proofTree: string;
        submitTree: string;
    }>;
    readonly CLIENT_FIELD_TOO_LONG: Readonly<{
        field?: string;
        actual?: number;
        maximum?: number;
    }> | undefined;
    readonly CLIENT_PROVER_SERVER: Readonly<{
        method?: string;
        status?: number | "failed";
        reason?: string;
    }>;
    readonly CLIENT_PROOF_PARSE: Readonly<{
        path?: string;
        reason?: string;
    }>;
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
    readonly CLIENT_MISSING_OUTPUT: NoDetails;
    readonly CLIENT_RPC: Readonly<{
        method?: string;
        reason?: string;
    }>;
    /** Carries no response text: an indexer body can hold caller data. */
    readonly CLIENT_INDEXER: Readonly<{
        method: string;
        retryable: boolean;
    }>;
    readonly CLIENT_UNSUPPORTED_RPC_METHOD: MethodDetails;
    readonly CLIENT_INDEXER_TIMEOUT: Readonly<{
        signature?: string;
        expectedTags?: number;
        attempts?: number;
    }> | undefined;
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
    readonly CLIENT_INVALID_CONFIG: Readonly<{
        field?: string;
    }> | undefined;
    readonly CLIENT_UNEXPECTED: NoDetails;
    readonly CLIENT_INVALID_INTEGER: Readonly<{
        field?: string;
        value?: string;
        length?: number;
    }> | undefined;
    readonly CLIENT_INVALID_INPUT_CONTEXT: Readonly<{
        index?: number;
    }> | undefined;
    readonly CLIENT_INVALID_PROOF_INPUTS: NoDetails;
    readonly CLIENT_INVALID_MERGE: NoDetails;
    readonly CLIENT_MERGE_OUTPUT_MISMATCH: NoDetails;
    readonly CLIENT_INVALID_TRANSACTION: NoDetails;
    readonly CLIENT_TRANSACTION_ASSEMBLY: NoDetails;
    readonly CLIENT_INVALID_LENGTH: Readonly<{
        field: string;
        expected: number;
        actual: number;
    }>;
    readonly CLIENT_INVALID_FIELD: Readonly<{
        field: string;
        value: string;
    }>;
    readonly CLIENT_INVALID_BASE58: Readonly<{
        field?: string;
        expectedLength?: number;
        actualLength?: number;
    }> | undefined;
    readonly CLIENT_INVALID_BASE64: Readonly<{
        field: string;
    }>;
    readonly CLIENT_INVALID_P256_KEY: NoDetails;
    readonly CLIENT_INVALID_CONTEXT: Readonly<{
        field: string;
        method: string;
    }>;
    readonly CLIENT_ABORTED: Readonly<{
        method?: string;
        retryable?: boolean;
    }> | undefined;
    readonly CLIENT_TIMEOUT: Readonly<{
        method: string;
        retryable: boolean;
    }>;
    readonly CLIENT_REQUEST: Readonly<{
        method: string;
        retryable: boolean;
    }>;
    readonly CLIENT_INVALID_POLL_CONFIG: Readonly<{
        field: string;
        value?: string;
    }>;
    readonly CLIENT_INVALID_INDEXER: Readonly<{
        field: string;
    }>;
    readonly CLIENT_PROOF_POINT: Readonly<{
        field: string;
    }>;
    readonly CLIENT_PROOF_TREE_MISMATCH: IndexDetails;
    readonly CLIENT_INVALID_MERGE_OUTPUT: NoDetails;
    readonly CLIENT_INVALID_MERGE_MATERIAL: NoDetails;
    readonly CLIENT_INVALID_MERGE_SHAPE: Readonly<{
        expected: number;
        actual: number;
    }>;
    readonly CLIENT_PROVER_INPUT: NoDetails;
    readonly CLIENT_PROVER_REQUEST: Readonly<{
        method: string;
        attempts: number;
    }>;
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
}
export type ClientErrorCode = keyof ClientErrorDetailsMap;
export type ClientErrorDetails<Code extends ClientErrorCode = ClientErrorCode> = ClientErrorDetailsMap[Code];
export declare const TYPESCRIPT_CLIENT_ERROR_CODES: readonly ["CLIENT_INVALID_CONFIG", "CLIENT_UNEXPECTED", "CLIENT_INVALID_INTEGER", "CLIENT_INVALID_INPUT_CONTEXT", "CLIENT_INVALID_PROOF_INPUTS", "CLIENT_INVALID_MERGE", "CLIENT_MERGE_OUTPUT_MISMATCH", "CLIENT_INVALID_TRANSACTION", "CLIENT_TRANSACTION_ASSEMBLY", "CLIENT_INVALID_LENGTH", "CLIENT_INVALID_FIELD", "CLIENT_INVALID_BASE58", "CLIENT_INVALID_BASE64", "CLIENT_INVALID_P256_KEY", "CLIENT_INVALID_CONTEXT", "CLIENT_ABORTED", "CLIENT_TIMEOUT", "CLIENT_REQUEST", "CLIENT_INVALID_POLL_CONFIG", "CLIENT_INVALID_INDEXER", "CLIENT_PROOF_POINT", "CLIENT_PROOF_TREE_MISMATCH", "CLIENT_INVALID_MERGE_OUTPUT", "CLIENT_INVALID_MERGE_MATERIAL", "CLIENT_INVALID_MERGE_SHAPE", "CLIENT_PROVER_INPUT", "CLIENT_PROVER_REQUEST", "CLIENT_PROVER_HTTP", "CLIENT_PROVER_JOB", "CLIENT_PROVER_TIMEOUT", "CLIENT_PROVER_RESPONSE_TOO_LARGE", "CLIENT_PROVER_TEXT", "CLIENT_PROVER_JSON", "CLIENT_INVALID_RPC_RESPONSE"];
/** The three transient causes Rust's `RetryErrorCause` can hold. */
export type RetryErrorCause = Readonly<{
    category: "rpc" | "indexer" | "indexerTimeout";
}>;
export type ClientErrorCause = Readonly<{
    category: "client";
    code: ClientErrorCode;
}> | Readonly<{
    category: "keypair";
    code: KeypairErrorCode;
    details?: Readonly<Record<string, unknown>>;
}> | Readonly<{
    category: "transaction";
    code: TransactionErrorCode;
    details?: Readonly<Record<string, unknown>>;
}> | Readonly<{
    category: "hasher";
    code: HasherErrorCode;
}> | RetryErrorCause | Readonly<{
    category: "external";
    code?: string;
}>;
type ClientErrorOptions<Code extends ClientErrorCode> = Readonly<{
    details?: Exclude<ClientErrorDetails<Code>, undefined>;
    cause?: unknown;
}>;
type ClientErrorArguments<Code extends ClientErrorCode> = undefined extends ClientErrorDetails<Code> ? readonly [options?: ClientErrorOptions<Code>] : readonly [
    options: Readonly<{
        details: ClientErrorDetails<Code>;
        cause?: unknown;
    }>
];
export declare class ClientError<Code extends ClientErrorCode = ClientErrorCode> extends Error {
    readonly code: Code;
    readonly details: ClientErrorDetails<Code> | undefined;
    readonly cause: ClientErrorCause | undefined;
    constructor(code: Code, ...[options]: ClientErrorArguments<Code>);
}
export declare function fromClientCause(cause: unknown): ClientError;
export declare function hasherError(code: HasherErrorCode, cause?: unknown): ClientError;
export declare function isClientError(value: unknown): value is ClientError;
export {};
