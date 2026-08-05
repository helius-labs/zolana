import type { RequestContext } from "../interface/types.js";

import { ClientError, isClientError, type RetryErrorCause } from "./error.js";

export type { RetryErrorCause } from "./error.js";

const MAX_U32 = 0xffff_ffff;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_TIMER_DELAY_MS = 0x7fff_ffffn;

const RPC_CAUSE: RetryErrorCause = Object.freeze({ category: "rpc" });
const INDEXER_CAUSE: RetryErrorCause = Object.freeze({ category: "indexer" });
const INDEXER_TIMEOUT_CAUSE: RetryErrorCause = Object.freeze({ category: "indexerTimeout" });

export interface IndexerPollConfig {
  readonly numRetries: number;
  readonly delayMs: bigint;
  readonly maxDelayMs: bigint;
}

export interface IndexerRpcConfig {
  readonly poll: IndexerPollConfig;
  /**
   * Slot the indexer must have persisted before its answer is accepted.
   * Omitted accepts whatever the indexer currently has.
   *
   * There is deliberately no "wait, but for nothing in particular" state: a
   * freshness requirement is a slot. The previous shape paired a boolean with no
   * target and compared the indexer's block time against `Date.now()`, mixing
   * clock domains so the check could not pass while block time trailed real time.
   */
  readonly requireSlot?: bigint;
}

export const DEFAULT_INDEXER_POLL_CONFIG: IndexerPollConfig = Object.freeze({
  numRetries: 10,
  delayMs: 400n,
  maxDelayMs: 8_000n,
});

export const DEFAULT_INDEXER_RPC_CONFIG: IndexerRpcConfig = Object.freeze({
  poll: DEFAULT_INDEXER_POLL_CONFIG,
});

export function createIndexerPollConfig(
  numRetries: number,
  delayMs: bigint,
  maxDelayMs: bigint,
): IndexerPollConfig {
  return validatePollConfig({ numRetries, delayMs, maxDelayMs });
}

export function createIndexerRpcConfig(
  poll: IndexerPollConfig = DEFAULT_INDEXER_POLL_CONFIG,
  requireSlot?: bigint,
): IndexerRpcConfig {
  if (requireSlot !== undefined && typeof requireSlot !== "bigint") {
    throw invalidPollConfig("requireSlot");
  }
  const validated = validatePollConfig(poll);
  return Object.freeze(
    requireSlot === undefined ? { poll: validated } : { poll: validated, requireSlot },
  );
}

/** Require the indexer to have persisted `slot` before answering. */
export function atSlot(
  slot: bigint,
  poll: IndexerPollConfig = DEFAULT_INDEXER_POLL_CONFIG,
): IndexerRpcConfig {
  return createIndexerRpcConfig(poll, slot);
}

export function validatePollConfig(config: IndexerPollConfig): IndexerPollConfig {
  const candidate: unknown = config;
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
    throw invalidPollConfig("poll");
  }
  const value = candidate as Record<string, unknown>;
  const numRetries = value["numRetries"];
  const delayMs = value["delayMs"];
  const maxDelayMs = value["maxDelayMs"];
  if (
    typeof numRetries !== "number" ||
    !Number.isSafeInteger(numRetries) ||
    numRetries < 0 ||
    numRetries > MAX_U32
  ) {
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

export function attempts(config: IndexerPollConfig): number {
  return validatePollConfig(config).numRetries + 1;
}

export function* backoff(config: IndexerPollConfig): IterableIterator<bigint> {
  const poll = validatePollConfig(config);
  let delay = poll.delayMs < poll.maxDelayMs ? poll.delayMs : poll.maxDelayMs;
  for (let retry = 0; retry < poll.numRetries; retry++) {
    yield delay;
    delay = delay * 2n < poll.maxDelayMs ? delay * 2n : poll.maxDelayMs;
  }
}

export interface PollUntilOptions {
  readonly config?: IndexerPollConfig;
  readonly context?: RequestContext;
}

export async function pollUntil<T>(
  request: () => Promise<T>,
  accept: (response: T) => boolean,
  options: PollUntilOptions = {},
): Promise<T> {
  if (typeof request !== "function") throw invalidPollConfig("request");
  if (typeof accept !== "function") throw invalidPollConfig("accept");
  const poll = validatePollConfig(options.config ?? DEFAULT_INDEXER_POLL_CONFIG);
  let lastCause: RetryErrorCause | undefined;
  for (const delay of pollSchedule(poll)) {
    if (delay !== 0n) await sleep(delay, options.context);
    try {
      const response = await request();
      if (accept(response)) return response;
    } catch (cause) {
      const transient = retryCause(cause);
      if (transient === undefined) throw cause;
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

function* pollSchedule(config: IndexerPollConfig): IterableIterator<bigint> {
  yield 0n;
  yield* backoff(config);
}

export function retryCause(error: unknown): RetryErrorCause | undefined {
  if (!isClientError(error)) return undefined;
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

export function isRetryable(cause: unknown): cause is ClientError {
  return retryCause(cause) !== undefined;
}

function retryableDetail(error: ClientError): boolean {
  const details: unknown = error.details;
  return (
    typeof details === "object" &&
    details !== null &&
    "retryable" in details &&
    details.retryable === true
  );
}

// Both adapters raise the shared transport codes, but only `ZolanaIndexer`
// attaches an indexer transport cause, and Rust folds those failures
// into `ClientError::Indexer` rather than `ClientError::Rpc`.
function transportCause(error: ClientError): RetryErrorCause {
  const cause = error.cause;
  if (cause === undefined || cause.category !== "external") return RPC_CAUSE;
  return cause.code?.startsWith("API_") === true ? INDEXER_CAUSE : RPC_CAUSE;
}

async function sleep(delayMs: bigint, context?: RequestContext): Promise<void> {
  let remaining = delayMs;
  do {
    assertNotAborted(context);
    const chunk = remaining < MAX_TIMER_DELAY_MS ? remaining : MAX_TIMER_DELAY_MS;
    if (chunk === 0n) return;
    await sleepChunk(Number(chunk), context);
    remaining -= chunk;
  } while (remaining > 0n);
}

function sleepChunk(delayMs: number, context?: RequestContext): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (): void => {
      context?.signal?.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = setTimeout(finish, delayMs);
    const abort = (): void => {
      clearTimeout(timeout);
      context?.signal?.removeEventListener("abort", abort);
      reject(new ClientError("CLIENT_ABORTED"));
    };
    context?.signal?.addEventListener("abort", abort, { once: true });
  });
}

function assertNotAborted(context?: RequestContext): void {
  if (context?.signal?.aborted === true) {
    throw new ClientError("CLIENT_ABORTED");
  }
}

function invalidPollConfig(field: string, value?: unknown): ClientError {
  return new ClientError("CLIENT_INVALID_POLL_CONFIG", {
    details: {
      field,
      ...(value === undefined ? {} : { value: printableValue(value) }),
    },
  });
}

function printableValue(value: unknown): string {
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
