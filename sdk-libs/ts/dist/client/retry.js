import { ClientError, isClientError } from "./error.js";
const MAX_U32 = 0xffff_ffff;
const MAX_U64 = 0xffffffffffffffffn;
const MAX_TIMER_DELAY_MS = 0x7fffffffn;
const RPC_CAUSE = Object.freeze({ category: "rpc" });
const INDEXER_CAUSE = Object.freeze({ category: "indexer" });
const INDEXER_TIMEOUT_CAUSE = Object.freeze({ category: "indexerTimeout" });
export const DEFAULT_INDEXER_POLL_CONFIG = Object.freeze({
    numRetries: 10,
    delayMs: 400n,
    maxDelayMs: 8000n,
});
export const DEFAULT_INDEXER_RPC_CONFIG = Object.freeze({
    waitForIndexer: false,
    poll: DEFAULT_INDEXER_POLL_CONFIG,
});
export function createIndexerPollConfig(numRetries, delayMs, maxDelayMs) {
    return validatePollConfig({ numRetries, delayMs, maxDelayMs });
}
export function createIndexerRpcConfig(waitForIndexer = false, poll = DEFAULT_INDEXER_POLL_CONFIG) {
    if (typeof waitForIndexer !== "boolean") {
        throw invalidPollConfig("waitForIndexer");
    }
    return Object.freeze({ waitForIndexer, poll: validatePollConfig(poll) });
}
export function waitForIndexer(poll = DEFAULT_INDEXER_POLL_CONFIG) {
    return createIndexerRpcConfig(true, poll);
}
export function validatePollConfig(config) {
    const candidate = config;
    if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
        throw invalidPollConfig("poll");
    }
    const value = candidate;
    const numRetries = value["numRetries"];
    const delayMs = value["delayMs"];
    const maxDelayMs = value["maxDelayMs"];
    if (typeof numRetries !== "number" ||
        !Number.isSafeInteger(numRetries) ||
        numRetries < 0 ||
        numRetries > MAX_U32) {
        throw invalidPollConfig("numRetries", numRetries);
    }
    if (typeof delayMs !== "bigint" || delayMs < 0n || delayMs > MAX_U64) {
        throw invalidPollConfig("delayMs", delayMs);
    }
    if (typeof maxDelayMs !== "bigint" || maxDelayMs < 0n || maxDelayMs > MAX_U64) {
        throw invalidPollConfig("maxDelayMs", maxDelayMs);
    }
    return Object.freeze({ numRetries, delayMs, maxDelayMs });
}
export function attempts(config) {
    return validatePollConfig(config).numRetries + 1;
}
export function* backoff(config) {
    const poll = validatePollConfig(config);
    let delay = poll.delayMs < poll.maxDelayMs ? poll.delayMs : poll.maxDelayMs;
    for (let retry = 0; retry < poll.numRetries; retry++) {
        yield delay;
        delay = delay * 2n < poll.maxDelayMs ? delay * 2n : poll.maxDelayMs;
    }
}
export async function pollUntil(request, accept, options = {}) {
    if (typeof request !== "function")
        throw invalidPollConfig("request");
    if (typeof accept !== "function")
        throw invalidPollConfig("accept");
    const poll = validatePollConfig(options.config ?? DEFAULT_INDEXER_POLL_CONFIG);
    let lastCause;
    for (const delay of pollSchedule(poll)) {
        if (delay !== 0n)
            await sleep(delay, options.context);
        try {
            const response = await request();
            if (accept(response))
                return response;
        }
        catch (cause) {
            const transient = retryCause(cause);
            if (transient === undefined)
                throw cause;
            lastCause = transient;
        }
    }
    throw new ClientError("CLIENT_POLL_TIMED_OUT", {
        details: {
            attempts: attempts(poll),
            ...(lastCause === undefined ? {} : { lastCause }),
        },
    });
}
function* pollSchedule(config) {
    yield 0n;
    yield* backoff(config);
}
export function retryCause(error) {
    if (!isClientError(error))
        return undefined;
    switch (error.code) {
        case "CLIENT_RPC":
        case "CLIENT_INVALID_RPC_RESPONSE":
            return RPC_CAUSE;
        case "CLIENT_INDEXER_TIMEOUT":
            return INDEXER_TIMEOUT_CAUSE;
        case "CLIENT_INDEXER":
            return retryableDetail(error) ? INDEXER_CAUSE : undefined;
        case "CLIENT_TIMEOUT":
        case "CLIENT_REQUEST":
            return retryableDetail(error) ? transportCause(error) : undefined;
        default:
            return undefined;
    }
}
export function isRetryable(cause) {
    return retryCause(cause) !== undefined;
}
function retryableDetail(error) {
    const details = error.details;
    return (typeof details === "object" &&
        details !== null &&
        "retryable" in details &&
        details.retryable === true);
}
// Both adapters raise the shared transport codes, but only `ZolanaIndexer`
// attaches an indexer transport cause, and Rust folds those failures
// into `ClientError::Indexer` rather than `ClientError::Rpc`.
function transportCause(error) {
    const cause = error.cause;
    if (cause === undefined || cause.category !== "external")
        return RPC_CAUSE;
    return cause.code?.startsWith("API_") === true ? INDEXER_CAUSE : RPC_CAUSE;
}
async function sleep(delayMs, context) {
    let remaining = delayMs;
    do {
        assertNotAborted(context);
        const chunk = remaining < MAX_TIMER_DELAY_MS ? remaining : MAX_TIMER_DELAY_MS;
        if (chunk === 0n)
            return;
        await sleepChunk(Number(chunk), context);
        remaining -= chunk;
    } while (remaining > 0n);
}
function sleepChunk(delayMs, context) {
    return new Promise((resolve, reject) => {
        const finish = () => {
            context?.signal?.removeEventListener("abort", abort);
            resolve();
        };
        const timeout = setTimeout(finish, delayMs);
        const abort = () => {
            clearTimeout(timeout);
            context?.signal?.removeEventListener("abort", abort);
            reject(new ClientError("CLIENT_ABORTED"));
        };
        context?.signal?.addEventListener("abort", abort, { once: true });
    });
}
function assertNotAborted(context) {
    if (context?.signal?.aborted === true) {
        throw new ClientError("CLIENT_ABORTED");
    }
}
function invalidPollConfig(field, value) {
    return new ClientError("CLIENT_INVALID_POLL_CONFIG", {
        details: {
            field,
            ...(value === undefined ? {} : { value: printableValue(value) }),
        },
    });
}
function printableValue(value) {
    switch (typeof value) {
        case "bigint":
        case "boolean":
        case "number":
        case "string":
            return String(value);
        default:
            return typeof value;
    }
}
