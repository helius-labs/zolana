import { ClientError, isClientError, type ClientErrorCode } from "../client/error.js";
import {
  attempts,
  createIndexerPollConfig,
  pollUntil,
  type IndexerPollConfig,
} from "../client/retry.js";
import { composeSignal } from "../client/internal.js";
import type { RequestContext } from "../interface/types.js";

export const KEY_REGISTRY_PROJECTION_ERRORS: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_KEY_REGISTRY_OUT_OF_SYNC",
  "CLIENT_KEY_REGISTRY_ROOT_CHANGED",
]);

// Match the Rust CLI's bounded wait: projection lag must not make a valid ring
// transaction fail, and a bad indexer must not hold a caller forever.
const PROJECTION_TIMEOUT_MS = 120_000;
const PROJECTION_POLL = createIndexerPollConfig(240, 500n, 500n);

type ProjectionAttempt<T> =
  | Readonly<{ kind: "ready"; value: T }>
  | Readonly<{ kind: "retry"; error: ClientError }>;

/** Refetches correlated chain and indexer state while a ring projection catches up. */
export async function waitForRingProjection<T>(
  read: (context: RequestContext) => Promise<T>,
  retryable: ReadonlySet<ClientErrorCode>,
  context?: RequestContext,
  poll: IndexerPollConfig = PROJECTION_POLL,
): Promise<T> {
  let last: ClientError | undefined;
  const operation = composeSignal(overallContext(context), "waitForRingProjection");
  const attemptContext = Object.freeze({ signal: operation.signal });
  let rejectAborted: ((error: ClientError) => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAborted = reject;
  });
  const abort = (): void => rejectAborted?.(new ClientError("CLIENT_ABORTED"));
  operation.signal.addEventListener("abort", abort, { once: true });
  try {
    const result = await pollUntil<ProjectionAttempt<T>>(
      async () => {
        try {
          const value = await Promise.race([read(attemptContext), aborted]);
          return { kind: "ready", value };
        } catch (cause) {
          if (!isClientError(cause) || !retryable.has(cause.code)) throw cause;
          last = cause;
          return { kind: "retry", error: cause };
        }
      },
      (attempt) => attempt.kind === "ready",
      {
        config: poll,
        context: attemptContext,
        retryErrors: false,
        onTimeout: (config) => last ?? pollTimedOut(config),
      },
    );
    if (result.kind === "retry") throw result.error;
    return result.value;
  } catch (cause) {
    if (operation.timedOut()) throw last ?? pollTimedOut(poll);
    throw cause;
  } finally {
    operation.signal.removeEventListener("abort", abort);
    operation.cleanup();
  }
}

function overallContext(context?: RequestContext): RequestContext {
  const requested = context?.timeoutMs;
  const timeoutMs =
    requested === undefined || (Number.isSafeInteger(requested) && requested > 0)
      ? Math.min(requested ?? PROJECTION_TIMEOUT_MS, PROJECTION_TIMEOUT_MS)
      : requested;
  return {
    ...(context?.signal === undefined ? {} : { signal: context.signal }),
    timeoutMs,
  };
}

function pollTimedOut(config: IndexerPollConfig): ClientError {
  return new ClientError("CLIENT_POLL_TIMED_OUT", {
    details: { attempts: attempts(config) },
  });
}
