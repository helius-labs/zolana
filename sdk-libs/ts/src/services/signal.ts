import type { RequestContext } from "../interface/types.js";

import { TransportFailure } from "./transport.js";

export interface ComposedSignal {
  readonly signal: AbortSignal;
  readonly timedOut: () => boolean;
  cleanup(): void;
}

export function composeSignal(context: RequestContext | undefined): ComposedSignal {
  const timeoutMs = context?.timeoutMs;
  if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)) {
    throw new TransportFailure("context", "request timeout is invalid", { field: "timeoutMs" });
  }
  if (context?.signal?.aborted === true) {
    throw new TransportFailure("aborted", "request was aborted", { retryable: false });
  }

  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  let didTimeOut = false;
  const abortFromCaller = (): void => {
    controller.abort();
  };
  context?.signal?.addEventListener("abort", abortFromCaller, { once: true });
  if (timeoutMs !== undefined) {
    timeout = setTimeout(() => {
      didTimeOut = true;
      controller.abort();
    }, timeoutMs);
  }

  return {
    signal: controller.signal,
    timedOut: () => didTimeOut,
    cleanup(): void {
      if (timeout !== undefined) clearTimeout(timeout);
      context?.signal?.removeEventListener("abort", abortFromCaller);
    },
  };
}

/** Stop waiting for I/O even when a caller-provided transport ignores its signal. */
export async function awaitWithSignal<T>(
  operation: () => Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  const aborted = () =>
    new TransportFailure("aborted", "request was aborted", { retryable: false });
  if (signal.aborted) throw aborted();
  let onAbort: () => void = () => {};
  const cancellation = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(aborted());
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const work = Promise.resolve().then(() => {
      if (signal.aborted) throw aborted();
      return operation();
    });
    const result = await Promise.race([work, cancellation]);
    if (signal.aborted) throw aborted();
    return result;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}
