import { KeypairError } from "../keypair/error.js";
import { TransactionError } from "../transaction/error.js";
export const CANONICAL_CLIENT_ERROR_CODES = Object.freeze([
    "CLIENT_KEYPAIR",
    "CLIENT_TRANSACTION",
    "CLIENT_HASHER",
    "CLIENT_FEE_PAYER_MISMATCH",
    "CLIENT_TREE_MISMATCH",
    "CLIENT_NO_INPUTS",
    "CLIENT_MERGE_SIGNING_KEY_MISMATCH",
    "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
    "CLIENT_MERGE_TREE_MISMATCH",
    "CLIENT_FIELD_TOO_LONG",
    "CLIENT_PROVER_SERVER",
    "CLIENT_PROOF_PARSE",
    "CLIENT_MISSING_INPUT_MERKLE_PROOF",
    "CLIENT_INCOMPLETE_INPUT_PROOFS",
    "CLIENT_STATE_PROOF_LEAF_MISMATCH",
    "CLIENT_STATE_PROOF_TREE_MISMATCH",
    "CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH",
    "CLIENT_NULLIFIER_PROOF_TREE_MISMATCH",
    "CLIENT_MISSING_OUTPUT",
    "CLIENT_RPC",
    "CLIENT_INDEXER",
    "CLIENT_UNSUPPORTED_RPC_METHOD",
    "CLIENT_INDEXER_TIMEOUT",
    "CLIENT_INDEXER_NOT_CAUGHT_UP",
    "CLIENT_POLL_TIMED_OUT",
    "CLIENT_PROOF_PATH_LENGTH",
    "CLIENT_PROOF_INPUT_COUNT_MISMATCH",
]);
export const TYPESCRIPT_CLIENT_ERROR_CODES = Object.freeze([
    "CLIENT_INVALID_CONFIG",
    "CLIENT_UNEXPECTED",
    "CLIENT_INVALID_INTEGER",
    "CLIENT_INVALID_INPUT_CONTEXT",
    "CLIENT_INVALID_PROOF_INPUTS",
    "CLIENT_INVALID_MERGE",
    "CLIENT_MERGE_OUTPUT_MISMATCH",
    "CLIENT_INVALID_TRANSACTION",
    "CLIENT_TRANSACTION_ASSEMBLY",
    "CLIENT_INVALID_LENGTH",
    "CLIENT_INVALID_FIELD",
    "CLIENT_INVALID_BASE58",
    "CLIENT_INVALID_BASE64",
    "CLIENT_INVALID_P256_KEY",
    "CLIENT_INVALID_CONTEXT",
    "CLIENT_ABORTED",
    "CLIENT_TIMEOUT",
    "CLIENT_REQUEST",
    "CLIENT_INVALID_POLL_CONFIG",
    "CLIENT_INVALID_INDEXER",
    "CLIENT_PROOF_POINT",
    "CLIENT_PROOF_TREE_MISMATCH",
    "CLIENT_INVALID_MERGE_OUTPUT",
    "CLIENT_INVALID_MERGE_MATERIAL",
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
]);
const CLIENT_ERROR_CODE_SET = new Set([
    ...CANONICAL_CLIENT_ERROR_CODES,
    ...TYPESCRIPT_CLIENT_ERROR_CODES,
]);
const NO_DETAIL_CODES = new Set([
    "CLIENT_FEE_PAYER_MISMATCH",
    "CLIENT_NO_INPUTS",
    "CLIENT_MERGE_SIGNING_KEY_MISMATCH",
    "CLIENT_MERGE_NULLIFIER_KEY_MISMATCH",
    "CLIENT_MISSING_OUTPUT",
    "CLIENT_INVALID_PROOF_INPUTS",
    "CLIENT_INVALID_MERGE",
    "CLIENT_MERGE_OUTPUT_MISMATCH",
    "CLIENT_INVALID_TRANSACTION",
    "CLIENT_TRANSACTION_ASSEMBLY",
    "CLIENT_INVALID_P256_KEY",
    "CLIENT_INVALID_MERGE_OUTPUT",
    "CLIENT_INVALID_MERGE_MATERIAL",
    "CLIENT_PROVER_INPUT",
    "CLIENT_PROVER_RESPONSE_TOO_LARGE",
    "CLIENT_PROVER_TEXT",
    "CLIENT_PROVER_JSON",
    "CLIENT_UNEXPECTED",
]);
const OPTIONAL_DETAIL_CODES = new Set([
    "CLIENT_FIELD_TOO_LONG",
    "CLIENT_INDEXER_TIMEOUT",
    "CLIENT_INVALID_CONFIG",
    "CLIENT_INVALID_INTEGER",
    "CLIENT_INVALID_INPUT_CONTEXT",
    "CLIENT_INVALID_BASE58",
    "CLIENT_ABORTED",
]);
const DETAIL_SHAPES = {
    CLIENT_KEYPAIR: { code: "string" },
    CLIENT_TRANSACTION: { code: "string" },
    CLIENT_HASHER: { code: "string" },
    CLIENT_TREE_MISMATCH: { transactionTree: "string", clientTree: "string" },
    CLIENT_MERGE_TREE_MISMATCH: { proofTree: "string", submitTree: "string" },
    CLIENT_FIELD_TOO_LONG: { field: "string", actual: "number", maximum: "number" },
    CLIENT_PROVER_SERVER: { method: "string", status: "number", reason: "string" },
    CLIENT_PROOF_PARSE: { path: "string", reason: "string" },
    CLIENT_MISSING_INPUT_MERKLE_PROOF: { index: "number" },
    CLIENT_INCOMPLETE_INPUT_PROOFS: { expected: "number", state: "number", nullifier: "number" },
    CLIENT_STATE_PROOF_LEAF_MISMATCH: { index: "number" },
    CLIENT_STATE_PROOF_TREE_MISMATCH: { index: "number" },
    CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH: { index: "number" },
    CLIENT_NULLIFIER_PROOF_TREE_MISMATCH: { index: "number" },
    CLIENT_RPC: { method: "string", reason: "string" },
    CLIENT_INDEXER: { method: "string", retryable: "boolean" },
    CLIENT_UNSUPPORTED_RPC_METHOD: { method: "string" },
    CLIENT_INDEXER_TIMEOUT: { signature: "string", expectedTags: "number", attempts: "number" },
    CLIENT_INDEXER_NOT_CAUGHT_UP: { target: "string", latest: "string", attempts: "number" },
    CLIENT_POLL_TIMED_OUT: { attempts: "number", lastCause: "retryCause" },
    CLIENT_PROOF_PATH_LENGTH: { got: "number", expected: "number", index: "number", kind: "string" },
    CLIENT_PROOF_INPUT_COUNT_MISMATCH: { got: "number", expected: "number" },
    CLIENT_INVALID_CONFIG: { field: "string" },
    CLIENT_INVALID_INTEGER: { field: "string", value: "string", length: "number" },
    CLIENT_INVALID_INPUT_CONTEXT: { index: "number" },
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
    CLIENT_PROOF_POINT: { field: "string" },
    CLIENT_PROOF_TREE_MISMATCH: { index: "number" },
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
};
const REQUIRED_DETAIL_FIELDS = {
    CLIENT_PROVER_SERVER: [],
    CLIENT_PROOF_PARSE: [],
    CLIENT_RPC: [],
    CLIENT_FIELD_TOO_LONG: [],
    CLIENT_INDEXER_TIMEOUT: [],
    CLIENT_PROOF_PATH_LENGTH: ["got", "expected"],
    CLIENT_POLL_TIMED_OUT: ["attempts"],
    CLIENT_INVALID_CONFIG: [],
    CLIENT_INVALID_INTEGER: [],
    CLIENT_INVALID_INPUT_CONTEXT: [],
    CLIENT_INVALID_BASE58: [],
    CLIENT_ABORTED: [],
    CLIENT_INVALID_POLL_CONFIG: ["field"],
    CLIENT_PROVER_HTTP: ["method"],
    CLIENT_INVALID_RPC_RESPONSE: [],
};
export class ClientError extends Error {
    code;
    details;
    cause;
    constructor(code, ...[options = {}]) {
        validateClientError(code, options.details);
        const cause = safeCause(options.cause);
        super(code, cause === undefined ? undefined : { cause });
        this.name = "ClientError";
        this.code = code;
        this.details =
            options.details === undefined
                ? undefined
                : copyAndFreeze(options.details);
        this.cause = cause;
    }
}
export function fromClientCause(cause) {
    if (isClientError(cause))
        return cause;
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
export function hasherError(code, cause) {
    return new ClientError("CLIENT_HASHER", {
        details: { code },
        cause: { category: "hasher", code, cause },
    });
}
function safeCause(cause) {
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
    if (typeof cause === "object" &&
        cause !== null &&
        "category" in cause &&
        cause.category === "hasher" &&
        "code" in cause &&
        isHasherErrorCode(cause.code)) {
        return Object.freeze({ category: "hasher", code: cause.code });
    }
    if (typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        typeof cause.code === "string") {
        return Object.freeze({ category: "external", code: cause.code });
    }
    return cause === undefined ? undefined : Object.freeze({ category: "external" });
}
export function isClientError(value) {
    return value instanceof ClientError;
}
function safeDetails(details) {
    if (details === undefined)
        return Object.freeze({});
    return Object.freeze({ details: sanitizeDetails(details) });
}
function validateClientError(code, details) {
    if (typeof code !== "string" || !CLIENT_ERROR_CODE_SET.has(code)) {
        throw new TypeError("invalid ClientError code");
    }
    const typedCode = code;
    const noDetails = NO_DETAIL_CODES.has(typedCode);
    const shape = DETAIL_SHAPES[typedCode];
    if (details === undefined) {
        if (noDetails || OPTIONAL_DETAIL_CODES.has(typedCode))
            return;
        throw new TypeError(`missing details for ${code}`);
    }
    if (noDetails || shape === undefined || !isPlainObject(details)) {
        throw new TypeError(`invalid details for ${code}`);
    }
    const required = REQUIRED_DETAIL_FIELDS[typedCode] ?? Object.keys(shape);
    for (const field of required) {
        if (!Object.hasOwn(details, field))
            throw new TypeError(`missing ${code}.${field}`);
    }
    for (const [field, value] of ownDataEntries(details)) {
        const kind = shape[field];
        if (kind === undefined || !matchesFieldKind(value, kind, field)) {
            throw new TypeError(`invalid ${code}.${field}`);
        }
    }
}
function matchesFieldKind(value, kind, field) {
    if (field === "status" && value === "failed")
        return true;
    if (kind === "number")
        return typeof value === "number" && Number.isSafeInteger(value);
    if (kind === "retryCause")
        return isRetryErrorCause(value);
    if (kind === "object")
        return isPlainObject(value);
    return typeof value === kind;
}
function isRetryErrorCause(value) {
    if (!isPlainObject(value) || Object.keys(value).length !== 1)
        return false;
    const category = value["category"];
    return category === "rpc" || category === "indexer" || category === "indexerTimeout";
}
function copyAndFreeze(value) {
    const copy = {};
    for (const [key, item] of ownDataEntries(value)) {
        copy[key] = cloneSafeValue(item);
    }
    return Object.freeze(copy);
}
function cloneSafeValue(value) {
    if (value === null ||
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean" ||
        typeof value === "bigint") {
        return value;
    }
    if (Array.isArray(value))
        return Object.freeze(value.map(cloneSafeValue));
    if (isPlainObject(value))
        return copyAndFreeze(value);
    throw new TypeError("ClientError details must contain safe data");
}
function sanitizeDetails(details) {
    const seen = new WeakSet();
    const sanitize = (value) => {
        if (value === null ||
            typeof value === "string" ||
            typeof value === "number" ||
            typeof value === "bigint" ||
            typeof value === "boolean") {
            return value;
        }
        if (typeof value !== "object" || seen.has(value))
            return undefined;
        seen.add(value);
        if (Array.isArray(value)) {
            return Object.freeze(value.map(sanitize).filter((item) => item !== undefined));
        }
        if (!isPlainObject(value))
            return undefined;
        const safe = {};
        for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
            if (!descriptor.enumerable || !("value" in descriptor))
                continue;
            if (/(secret|private|seed|blinding|nonce|scalar)/iu.test(key))
                continue;
            const sanitized = sanitize(descriptor.value);
            if (sanitized !== undefined)
                safe[key] = sanitized;
        }
        return Object.freeze(safe);
    };
    return sanitize(details);
}
function isPlainObject(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function ownDataEntries(value) {
    return Object.entries(Object.getOwnPropertyDescriptors(value))
        .filter(([, descriptor]) => descriptor.enumerable)
        .map(([key, descriptor]) => {
        if (!("value" in descriptor))
            throw new TypeError("ClientError details cannot use accessors");
        return [key, descriptor.value];
    });
}
function isHasherErrorCode(value) {
    return value === "InvalidNumFields" || value === "EmptyInput";
}
