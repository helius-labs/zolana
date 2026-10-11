import type { RequestContext } from "../interface/types.js";

import { TransportFailure } from "./transport.js";

const MAX_TIMER_DELAY_MS = 0x7fff_ffff;

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
    const startedAt = performance.now();
    const expire = (): void => {
      const remaining = timeoutMs - (performance.now() - startedAt);
      if (remaining > 0) {
        // Native timers overflow above 2^31 - 1 ms. Recheck elapsed time so a
        // delayed callback does not extend the caller's original deadline.
        timeout = setTimeout(expire, Math.min(remaining, MAX_TIMER_DELAY_MS));
        return;
      }
      didTimeOut = true;
      controller.abort();
    };
    timeout = setTimeout(expire, Math.min(timeoutMs, MAX_TIMER_DELAY_MS));
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
