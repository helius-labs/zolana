import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ClientError,
  DEFAULT_INDEXER_POLL_CONFIG,
  DEFAULT_INDEXER_RPC_CONFIG,
  attempts,
  backoff,
  createIndexerPollConfig,
  createIndexerRpcConfig,
  isRetryable,
  pollUntil,
  retryCause,
  wait,
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
    expect(wait(poll)).toEqual({ waitForIndexer: true, poll });
    expect(Object.keys(retrySubpath).sort()).toEqual([
      "DEFAULT_INDEXER_POLL_CONFIG",
      "DEFAULT_INDEXER_RPC_CONFIG",
      "attempts",
      "backoff",
      "createIndexerPollConfig",
      "createIndexerRpcConfig",
      "isRetryable",
      "pollUntil",
      "retryCause",
      "validatePollConfig",
      "wait",
    ]);
  });

  it("counts attempts exactly at the u32 boundary", () => {
    expect(attempts(DEFAULT_INDEXER_POLL_CONFIG)).toBe(11);
    expect(attempts(createIndexerPollConfig(0xffff_ffff, 0n, 0n))).toBe(0x1_0000_0000);
    expect(() => attempts({ numRetries: -1, delayMs: 0n, maxDelayMs: 0n })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_POLL_CONFIG" }),
    );
  });

  it("names the three Rust retry causes and refuses every other failure", () => {
    const causes: readonly (readonly [ClientError, string | undefined])[] = [
      [new ClientError("CLIENT_RPC", { details: {} }), "rpc"],
      [new ClientError("CLIENT_RPC_HTTP", { details: { method: "getSlot", status: 503 } }), "rpc"],
      [new ClientError("CLIENT_RPC_JSON", { details: { method: "getSlot" } }), "rpc"],
      [new ClientError("CLIENT_RPC_ENVELOPE", { details: { method: "getSlot" } }), "rpc"],
      // The six codes below also narrow Rust's `ClientError::Rpc`, so
      // `ClientError::retry_cause` reports every one of them as
      // `RetryErrorCause::Rpc`. `CLIENT_INVALID_RPC_RESPONSE` is the reachable
      // one: `indexer.rs::fixed_bytes` produces `ClientError::Rpc` for the same
      // malformed field that raises it here.
      [
        new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
          details: {
            path: "transactions[0].tx_viewing_pk",
            expected: 33,
            actual: 32,
          },
        }),
        "rpc",
      ],
      [
        new ClientError("CLIENT_RPC_TRANSACTION_NOT_FOUND", { details: { signature: "sig" } }),
        "rpc",
      ],
      [
        new ClientError("CLIENT_RPC_PROGRAM_ERROR", {
          details: {
            method: "getTransaction",
            instructionIndex: 0,
            programError: { kind: "unknown", code: 7000 },
          },
        }),
        "rpc",
      ],
      [new ClientError("CLIENT_RPC_TRANSACT_DECODE"), "rpc"],
      [new ClientError("CLIENT_RPC_OWNER_TAG"), "rpc"],
      [new ClientError("CLIENT_RPC_TRANSACT_NOT_FOUND"), "rpc"],
      // Rust folds garbled instruction/account encodings into `ClientError::Rpc`.
      [
        new ClientError("CLIENT_INVALID_BASE58", { details: { field: "instruction.data" } }),
        "rpc",
      ],
      [new ClientError("CLIENT_INVALID_BASE64", { details: { field: "account.data" } }), "rpc"],
      [new ClientError("CLIENT_INDEXER_TIMEOUT"), "indexerTimeout"],
      [
        new ClientError("CLIENT_INDEXER", {
          details: { method: "getMerkleProofs", retryable: true },
        }),
        "indexer",
      ],
      [
        new ClientError("CLIENT_INDEXER", {
          details: { method: "getMerkleProofs", retryable: false },
        }),
        undefined,
      ],
      [
        new ClientError("CLIENT_TIMEOUT", {
          details: { method: "getMerkleProofs", retryable: true },
          cause: { code: "API_TIMEOUT" },
        }),
        "indexer",
      ],
      [
        new ClientError("CLIENT_REQUEST", { details: { method: "getSlot", retryable: true } }),
        "rpc",
      ],
      [
        new ClientError("CLIENT_REQUEST", { details: { method: "getSlot", retryable: false } }),
        undefined,
      ],
      [new ClientError("CLIENT_ABORTED"), undefined],
      [new ClientError("CLIENT_MISSING_OUTPUT"), undefined],
      [
        new ClientError("CLIENT_INDEXER_NOT_CAUGHT_UP", {
          details: { target: "100", latest: "99", attempts: 5 },
        }),
        undefined,
      ],
    ];

    for (const [error, category] of causes) {
      expect([error.code, retryCause(error)]).toEqual([
        error.code,
        category === undefined ? undefined : { category },
      ]);
      expect(isRetryable(error)).toBe(category !== undefined);
    }
    expect(retryCause(new Error("not a client error"))).toBeUndefined();
    expect(isRetryable(undefined)).toBe(false);
  });

  // Mirrors `indexer.rs::tests::a_malformed_viewing_key_is_retried_for_the_whole_schedule`,
  // which spends all three attempts on the same rejection and reports the rpc
  // cause. Before `CLIENT_INVALID_RPC_RESPONSE` was classified, this poll
  // rethrew on the first attempt and the indexer response that Rust retried was
  // fatal here.
  it("spends the whole schedule on a malformed indexer field, as the Rust poll does", async () => {
    let attemptCount = 0;
    const rejection = new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: {
        path: "transactions[0].tx_viewing_pk",
        expected: 33,
        actual: 32,
      },
    });

    await expect(
      pollUntil(
        () => {
          attemptCount += 1;
          return Promise.reject(rejection);
        },
        () => false,
        { config: createIndexerPollConfig(2, 0n, 0n) },
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 3, lastCause: { category: "rpc" } },
    });
    expect(attemptCount).toBe(3);
  });

  it("retries garbled base58 in an RPC body for the whole schedule", async () => {
    let attemptCount = 0;
    const rejection = new ClientError("CLIENT_INVALID_BASE58", {
      details: { field: "instruction.data" },
    });

    await expect(
      pollUntil(
        () => {
          attemptCount += 1;
          return Promise.reject(rejection);
        },
        () => false,
        { config: createIndexerPollConfig(2, 0n, 0n) },
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 3, lastCause: { category: "rpc" } },
    });
    expect(attemptCount).toBe(3);
  });

  it("records a last cause the Rust variant can hold", async () => {
    const rejection = new ClientError("CLIENT_RPC_HTTP", {
      details: { method: "getSlot", status: 503 },
    });
    await expect(
      pollUntil(
        () => Promise.reject(rejection),
        () => false,
        {
          config: createIndexerPollConfig(1, 0n, 0n),
        },
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 2, lastCause: { category: "rpc" } },
    });
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
            details: { method: "get_merkle_proofs", retryable: true },
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
        pollUntil(
          () => Promise.resolve(++left),
          (value) => value === 2,
          { config },
        ),
        pollUntil(
          () => Promise.resolve(++right),
          (value) => value === 1,
          { config },
        ),
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
