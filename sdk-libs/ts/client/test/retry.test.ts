import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ClientError,
  DEFAULT_INDEXER_POLL_CONFIG,
  DEFAULT_INDEXER_RPC_CONFIG,
  backoff,
  createIndexerPollConfig,
  createIndexerRpcConfig,
  pollUntil,
  waitForIndexer,
} from "../src/index.js";
import * as retrySubpath from "../src/retry/index.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("retry", () => {
  it("exposes Rust-equivalent defaults and factories", () => {
    expect(DEFAULT_INDEXER_POLL_CONFIG).toEqual({
      numRetries: 10,
      delayMs: 400n,
      maxDelayMs: 8_000n,
    });
    expect(DEFAULT_INDEXER_RPC_CONFIG).toEqual({
      waitForIndexer: false,
      poll: DEFAULT_INDEXER_POLL_CONFIG,
    });
    const poll = createIndexerPollConfig(2, 20n, 5n);
    expect([...backoff(poll)]).toEqual([5n, 5n]);
    expect(createIndexerRpcConfig(false, poll)).toEqual({ waitForIndexer: false, poll });
    expect(waitForIndexer(poll)).toEqual({ waitForIndexer: true, poll });
    expect(Object.keys(retrySubpath).sort()).toEqual([
      "DEFAULT_INDEXER_POLL_CONFIG",
      "DEFAULT_INDEXER_RPC_CONFIG",
      "backoff",
      "createIndexerPollConfig",
      "createIndexerRpcConfig",
      "isRetryable",
      "pollUntil",
      "validatePollConfig",
      "waitForIndexer",
    ]);
  });

  it("accepts zero delay without scheduling timers", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    const pending = pollUntil(
      () => Promise.resolve(++attempts),
      (value) => value === 3,
      { config: createIndexerPollConfig(2, 0n, 0n) },
    );
    await expect(pending).resolves.toBe(3);
    expect(attempts).toBe(3);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reports exact attempts and a structured safe last cause", async () => {
    vi.useFakeTimers();
    const secret = "private response body";
    const pending = pollUntil(
      () =>
        Promise.reject(
          new ClientError("CLIENT_INDEXER", {
            details: { reason: secret },
            cause: { code: "API_REQUEST", message: secret },
          }),
        ),
      () => false,
      { config: createIndexerPollConfig(2, 1n, 2n) },
    );
    const rejection = expect(pending).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: {
        attempts: 3,
        lastCause: { category: "indexer" },
      },
    });
    await vi.runAllTimersAsync();
    await rejection;
    const error = await pending.catch((cause: unknown) => cause);
    expect(JSON.stringify(error)).not.toContain(secret);
  });

  it("stops immediately on a non-retryable error", async () => {
    let attempts = 0;
    const failure = new ClientError("CLIENT_MISSING_OUTPUT");
    await expect(
      pollUntil(
        () => {
          attempts++;
          return Promise.reject(failure);
        },
        () => false,
      ),
    ).rejects.toBe(failure);
    expect(attempts).toBe(1);
  });

  it("aborts during a delay without another request", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    let attempts = 0;
    const pending = pollUntil(
      () => Promise.resolve(++attempts),
      () => false,
      {
        config: createIndexerPollConfig(2, 10n, 10n),
        context: { signal: controller.signal },
      },
    );
    await Promise.resolve();
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
    expect(attempts).toBe(1);
  });

  it("keeps concurrent polls independent", async () => {
    const config = createIndexerPollConfig(1, 0n, 0n);
    let left = 0;
    let right = 0;
    await expect(
      Promise.all([
        pollUntil(() => Promise.resolve(++left), (value) => value === 2, { config }),
        pollUntil(() => Promise.resolve(++right), (value) => value === 1, { config }),
      ]),
    ).resolves.toEqual([2, 1]);
    expect([left, right]).toEqual([2, 1]);
  });

  it("chunks delays above the browser timer limit", async () => {
    vi.useFakeTimers();
    const pending = pollUntil(() => Promise.resolve(false), Boolean, {
      config: createIndexerPollConfig(1, 0x8000_0000n, 0x8000_0000n),
    });
    const rejection = expect(pending).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 2 },
    });
    await Promise.resolve();
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(0x7fff_ffff);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    await rejection;
  });
});
