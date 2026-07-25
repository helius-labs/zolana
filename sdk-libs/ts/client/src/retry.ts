import type { RequestContext } from "@zolana/interface";

import { ClientError, isClientError, type ClientErrorCause } from "./error.js";

const MAX_U32 = 0xffff_ffff;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_TIMER_DELAY_MS = 0x7fff_ffffn;

export interface IndexerPollConfig {
  readonly numRetries: number;
  readonly delayMs: bigint;
  readonly maxDelayMs: bigint;
}

export interface IndexerRpcConfig {
  readonly waitForIndexer: boolean;
  readonly poll: IndexerPollConfig;
}

export const DEFAULT_INDEXER_POLL_CONFIG: IndexerPollConfig = Object.freeze({
  numRetries: 10,
  delayMs: 400n,
  maxDelayMs: 8_000n,
});

export const DEFAULT_INDEXER_RPC_CONFIG: IndexerRpcConfig = Object.freeze({
  waitForIndexer: false,
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
  waitForIndexer = false,
  poll: IndexerPollConfig = DEFAULT_INDEXER_POLL_CONFIG,
): IndexerRpcConfig {
  if (typeof waitForIndexer !== "boolean") {
    throw invalidPollConfig("waitForIndexer");
  }
  return Object.freeze({ waitForIndexer, poll: validatePollConfig(poll) });
}

export function waitForIndexer(
  poll: IndexerPollConfig = DEFAULT_INDEXER_POLL_CONFIG,
): IndexerRpcConfig {
  return createIndexerRpcConfig(true, poll);
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
  let lastCause: ClientErrorCause | undefined;
  let attempt = 0;
  for (const delay of pollSchedule(poll)) {
    attempt++;
    if (delay !== 0n) await sleep(delay, options.context);
    try {
      const response = await request();
      if (accept(response)) return response;
    } catch (cause) {
      if (!isRetryable(cause)) throw cause;
      lastCause = retryErrorCause(cause);
    }
  }

  throw new ClientError("CLIENT_POLL_TIMED_OUT", {
    details: {
      attempts: attempt,
      ...(lastCause === undefined ? {} : { lastCause }),
    },
  });
}

function* pollSchedule(config: IndexerPollConfig): IterableIterator<bigint> {
  yield 0n;
  yield* backoff(config);
}

export function isRetryable(cause: unknown): cause is ClientError {
  if (!isClientError(cause)) return false;
  switch (cause.code) {
    case "CLIENT_RPC":
    case "CLIENT_INDEXER":
    case "CLIENT_INDEXER_TIMEOUT":
      return true;
    case "CLIENT_TIMEOUT":
    case "CLIENT_REQUEST": {
      const details: unknown = cause.details;
      return (
        typeof details === "object" &&
        details !== null &&
        "retryable" in details &&
        details.retryable === true
      );
    }
    default:
      return false;
  }
}

function retryErrorCause(error: ClientError): ClientErrorCause {
  switch (error.code) {
    case "CLIENT_RPC":
      return Object.freeze({ category: "rpc" });
    case "CLIENT_INDEXER":
      return Object.freeze({ category: "indexer" });
    case "CLIENT_INDEXER_TIMEOUT":
      return Object.freeze({ category: "indexerTimeout" });
    default:
      return error.cause ?? Object.freeze({ category: "client", code: error.code });
  }
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
