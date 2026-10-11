import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { composeSignal } from "../src/services/signal.js";

const MAX_TIMER_DELAY_MS = 0x7fff_ffff;

describe("request timeout scheduling", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("does not overflow a timeout longer than one native timer", () => {
    const composed = composeSignal({ timeoutMs: MAX_TIMER_DELAY_MS + 50 });
    try {
      vi.advanceTimersByTime(1);
      expect(composed.signal.aborted).toBe(false);
      expect(composed.timedOut()).toBe(false);
      vi.advanceTimersByTime(MAX_TIMER_DELAY_MS - 1);
      expect(composed.signal.aborted).toBe(false);
      vi.advanceTimersByTime(49);
      expect(composed.signal.aborted).toBe(false);
      vi.advanceTimersByTime(1);
      expect(composed.signal.aborted).toBe(true);
      expect(composed.timedOut()).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      composed.cleanup();
    }
  });

  it("cleans up the next timer after a long timeout has been rescheduled", () => {
    const composed = composeSignal({ timeoutMs: MAX_TIMER_DELAY_MS + 50 });
    vi.advanceTimersByTime(MAX_TIMER_DELAY_MS);
    composed.cleanup();
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(50);
    expect(composed.signal.aborted).toBe(false);
    expect(composed.timedOut()).toBe(false);
  });

  it("does not extend the deadline when a timer callback runs late", () => {
    const now = vi.spyOn(performance, "now").mockReturnValue(0);
    const composed = composeSignal({ timeoutMs: MAX_TIMER_DELAY_MS + 50 });
    try {
      now.mockReturnValue(MAX_TIMER_DELAY_MS + 100);
      vi.advanceTimersByTime(MAX_TIMER_DELAY_MS);
      expect(composed.signal.aborted).toBe(true);
      expect(composed.timedOut()).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      composed.cleanup();
    }
  });

  it("preserves caller cancellation during a long timeout", () => {
    const caller = new AbortController();
    const composed = composeSignal({
      timeoutMs: MAX_TIMER_DELAY_MS + 50,
      signal: caller.signal,
    });
    try {
      vi.advanceTimersByTime(MAX_TIMER_DELAY_MS);
      caller.abort();
      expect(composed.signal.aborted).toBe(true);
      expect(composed.timedOut()).toBe(false);
    } finally {
      composed.cleanup();
    }
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shortens the remaining timer when a callback runs late before expiry", () => {
    const now = vi.spyOn(performance, "now").mockReturnValue(0);
    const composed = composeSignal({ timeoutMs: MAX_TIMER_DELAY_MS + 50 });
    try {
      now.mockReturnValue(MAX_TIMER_DELAY_MS + 20);
      vi.advanceTimersByTime(MAX_TIMER_DELAY_MS);
      expect(composed.signal.aborted).toBe(false);
      now.mockReturnValue(MAX_TIMER_DELAY_MS + 50);
      vi.advanceTimersByTime(30);
      expect(composed.signal.aborted).toBe(true);
      expect(composed.timedOut()).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      composed.cleanup();
    }
  });

  it("accepts the largest safe-integer timeout without overflowing", () => {
    const composed = composeSignal({ timeoutMs: Number.MAX_SAFE_INTEGER });
    try {
      vi.advanceTimersByTime(MAX_TIMER_DELAY_MS * 2);
      expect(composed.signal.aborted).toBe(false);
      expect(composed.timedOut()).toBe(false);
      expect(vi.getTimerCount()).toBe(1);
    } finally {
      composed.cleanup();
    }
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([1, MAX_TIMER_DELAY_MS, MAX_TIMER_DELAY_MS + 1])(
    "keeps a %i ms timeout unchanged",
    (timeoutMs) => {
      const composed = composeSignal({ timeoutMs });
      try {
        vi.advanceTimersByTime(timeoutMs - 1);
        expect(composed.signal.aborted).toBe(false);
        vi.advanceTimersByTime(1);
        expect(composed.signal.aborted).toBe(true);
        expect(composed.timedOut()).toBe(true);
      } finally {
        composed.cleanup();
      }
    },
  );
});
