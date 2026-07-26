import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/retry-schedule-v1.json" with { type: "json" };
import { isClientError } from "../../src/error.js";
import { ClientError, attempts, backoff, pollUntil } from "../../src/index.js";

/**
 * `RetryErrorCause` variants as Rust names them, against the category the port
 * carries in `CLIENT_POLL_TIMED_OUT.details.lastCause`.
 */
const CAUSES: Readonly<Record<string, string>> = {
  Rpc: "rpc",
  Indexer: "indexer",
  IndexerTimeout: "indexerTimeout",
};

/** Rust `ClientError` variants and the codes the port raises for them. */
const REJECTIONS: Readonly<Record<string, string>> = {
  PollTimedOut: "CLIENT_POLL_TIMED_OUT",
  Indexer: "CLIENT_INDEXER",
  MissingOutput: "CLIENT_MISSING_OUTPUT",
};

/**
 * What each poll case's request does, matching the closure the oracle polled.
 * A case without an entry keeps answering with a response `accept` refuses.
 */
const REQUESTS: Readonly<Record<string, (requests: number) => Promise<number>>> = {
  retryableIndexer: () =>
    Promise.reject(
      new ClientError("CLIENT_INDEXER", {
        details: { method: "get_merkle_proofs", retryable: true },
      }),
    ),
  fatalIndexer: () =>
    Promise.reject(
      new ClientError("CLIENT_INDEXER", {
        details: { method: "get_merkle_proofs", retryable: false },
      }),
    ),
  retryableRpc: () =>
    Promise.reject(new ClientError("CLIENT_RPC", { details: { reason: "transport" } })),
  indexerTimeout: () => Promise.reject(new ClientError("CLIENT_INDEXER_TIMEOUT")),
  fatalOther: () => Promise.reject(new ClientError("CLIENT_MISSING_OUTPUT")),
  acceptedOnTheThirdRequest: (requests) => Promise.resolve(requests < 3 ? 0 : 1),
};

function pollConfig(
  schedule: Readonly<{ numRetries: string; delayMs: string; maxDelayMs: string }>,
) {
  return {
    numRetries: Number(schedule.numRetries),
    delayMs: BigInt(schedule.delayMs),
    maxDelayMs: BigInt(schedule.maxDelayMs),
  };
}

/** The outcome of a poll in the shape the oracle recorded it. */
async function settle(pending: Promise<number>): Promise<Record<string, unknown>> {
  try {
    return { arm: "ok", value: String(await pending) };
  } catch (error) {
    if (!isClientError(error)) throw error;
    const details: Record<string, unknown> = { ...error.details };
    return {
      arm: "err",
      code: error.code,
      ...(error.code === "CLIENT_POLL_TIMED_OUT"
        ? {
            attempts: String(details["attempts"]),
            lastCause: (details["lastCause"] as { category: string } | undefined)?.category ?? null,
          }
        : {}),
      ...("retryable" in details ? { retryable: details["retryable"] } : {}),
    };
  }
}

/** The same outcome as the oracle recorded it, translated into port terms. */
function expected(outcome: (typeof fixture.polls)[number]["outcome"]): Record<string, unknown> {
  if (outcome.arm === "ok") return { arm: "ok", value: outcome.value };
  const code = REJECTIONS[outcome.variant ?? ""];
  if (code === undefined) throw new Error(`unmapped Rust variant ${String(outcome.variant)}`);
  return {
    arm: "err",
    code,
    ...(outcome.variant === "PollTimedOut"
      ? {
          attempts: outcome.attempts,
          lastCause: outcome.lastCause === null ? null : CAUSES[outcome.lastCause ?? ""],
        }
      : {}),
    ...(outcome.retryable === undefined ? {} : { retryable: outcome.retryable }),
  };
}

describe("the Rust oracle and TypeScript agree on the retry schedule", () => {
  for (const schedule of fixture.schedules) {
    it(`waits and counts the same on ${schedule.id}`, () => {
      const poll = pollConfig(schedule);
      expect(attempts(poll)).toBe(Number(schedule.attempts));
      // The `u32::MAX` retry count is recorded for its attempt arithmetic
      // alone; its delay sequence is four billion entries long.
      if ("delaysMs" in schedule) {
        expect([...backoff(poll)].map(String)).toEqual(schedule.delaysMs);
      }
    });
  }

  // Every case polls a zero-delay schedule, so the request count below is the
  // schedule the poll walked rather than a measurement of how long it waited.
  for (const poll of fixture.polls) {
    it(`ends ${poll.id} the way the Rust poll does`, async () => {
      let requests = 0;
      const respond = REQUESTS[poll.id];
      const outcome = await settle(
        pollUntil(
          () => {
            requests++;
            return respond === undefined ? Promise.resolve(0) : respond(requests);
          },
          (response) => response === 1,
          { config: { numRetries: 3, delayMs: 0n, maxDelayMs: 0n } },
        ),
      );

      expect(outcome).toEqual(expected(poll.outcome));
      expect(String(requests)).toBe(poll.requests);
    });
  }
});
