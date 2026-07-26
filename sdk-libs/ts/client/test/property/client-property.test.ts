import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  ClientError,
  attempts,
  backoff,
  createIndexerPollConfig,
  isRetryable,
  pollUntil,
  retryCause,
  validatePollConfig,
} from "../../src/index.js";

describe("client retry properties", () => {
  it("keeps backoff monotonic, capped, and exactly numRetries long", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 32 }),
        fc.bigInt({ min: 0n, max: 10_000n }),
        fc.bigInt({ min: 0n, max: 10_000n }),
        (numRetries, delayMs, maxDelayMs) => {
          const poll = createIndexerPollConfig(numRetries, delayMs, maxDelayMs);
          const schedule = [...backoff(poll)];
          expect(schedule).toHaveLength(numRetries);
          let previous = 0n;
          for (const delay of schedule) {
            expect(delay).toBeGreaterThanOrEqual(0n);
            expect(delay).toBeLessThanOrEqual(poll.maxDelayMs);
            expect(delay).toBeGreaterThanOrEqual(previous);
            previous = delay;
          }
          expect(attempts(poll)).toBe(numRetries + 1);
        },
      ),
    );
  });

  it("rejects poll configs outside the Rust u32/u64 domain", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant({ numRetries: -1, delayMs: 0n, maxDelayMs: 0n }),
          fc.constant({ numRetries: 0x1_0000_0000, delayMs: 0n, maxDelayMs: 0n }),
          fc.constant({ numRetries: 0, delayMs: -1n, maxDelayMs: 0n }),
          fc.constant({ numRetries: 0, delayMs: 0n, maxDelayMs: -1n }),
        ),
        (config) => {
          expect(() => validatePollConfig(config)).toThrow(
            expect.objectContaining({ code: "CLIENT_INVALID_POLL_CONFIG" }),
          );
        },
      ),
    );
  });

  it("classifies generated retryable errors as a category-only cause", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          () => new ClientError("CLIENT_RPC", { details: { method: "getSlot" } }),
          () => new ClientError("CLIENT_RPC_HTTP", { details: { method: "getSlot", status: 503 } }),
          () => new ClientError("CLIENT_RPC_JSON", { details: { method: "getSlot" } }),
          () => new ClientError("CLIENT_RPC_ENVELOPE", { details: { method: "getSlot" } }),
          () =>
            new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
              details: { path: "transactions[0].tx_viewing_pk", expected: 33, actual: 32 },
            }),
          () =>
            new ClientError("CLIENT_INDEXER", {
              details: { method: "getMerkleProofs", retryable: true },
            }),
          () =>
            new ClientError("CLIENT_TIMEOUT", {
              details: { method: "getMerkleProofs", retryable: true },
              cause: { code: "API_TIMEOUT" },
            }),
          () =>
            new ClientError("CLIENT_REQUEST", { details: { method: "getSlot", retryable: true } }),
        ),
        (build) => {
          const error = build();
          const cause = retryCause(error);
          expect(cause).toBeDefined();
          expect(Object.keys(cause ?? {}).sort()).toEqual(["category"]);
          expect(isRetryable(error)).toBe(true);
        },
      ),
    );
  });

  it("pollUntil counts exactly attempts(poll) tries before timing out", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 5 }), async (numRetries) => {
        const poll = createIndexerPollConfig(numRetries, 0n, 0n);
        let calls = 0;
        await expect(
          pollUntil(
            async () => {
              calls += 1;
              throw new ClientError("CLIENT_RPC", { details: { method: "getSlot" } });
            },
            () => false,
            { config: poll },
          ),
        ).rejects.toEqual(
          expect.objectContaining({
            code: "CLIENT_POLL_TIMED_OUT",
            details: expect.objectContaining({ attempts: attempts(poll) }),
          }),
        );
        expect(calls).toBe(attempts(poll));
      }),
      { numRuns: 20 },
    );
  });
});
