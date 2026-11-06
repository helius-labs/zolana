import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SprApi } from "../src/api/index.js";
import { ClientError } from "../src/client/error.js";
import { SprIndexer } from "../src/client/indexer.js";
import { atSlot, createIndexerPollConfig, pollUntil } from "../src/client/retry.js";
import { address } from "@solana/kit";
import type { Bytes32 } from "../src/interface/types.js";

const TREE = address("11111111111111111111111111111111");
const LEAF = new Uint8Array(32).fill(7) as Bytes32;
const ONE_RETRY = createIndexerPollConfig(1, 0n, 0n);

type Answer = Readonly<{ slot: number }> | Readonly<{ error: number }>;

/** An indexer answering `getMerkleProofs` with one scripted answer per request. */
function indexer(script: readonly Answer[]) {
  let calls = 0;
  const fetch = vi.fn<typeof globalThis.fetch>(async () => {
    const answer = script[calls++];
    if (answer === undefined) throw new Error("unscripted request");
    return Response.json({
      jsonrpc: "2.0",
      id: "test-account",
      ...("error" in answer
        ? { error: { code: answer.error, message: "server text" } }
        : { result: { context: { blockTime: 0, slot: answer.slot }, proofs: [] } }),
    });
  });
  return { indexer: new SprIndexer(new SprApi({ url: "https://indexer.example", fetch })), fetch };
}

describe("indexer JSON-RPC errors", () => {
  it("retries an internal error inside a slot poll", async () => {
    const { indexer: client, fetch } = indexer([{ error: -32603 }, { slot: 10 }]);
    await expect(
      client.getMerkleProofs(TREE, [LEAF], atSlot(10n, ONE_RETRY)),
    ).resolves.toMatchObject({ context: { slot: 10n } });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("reports an internal error as a retryable indexer failure", async () => {
    const { indexer: client } = indexer([{ error: -32603 }]);
    await expect(client.getMerkleProofs(TREE, [LEAF])).rejects.toMatchObject({
      code: "CLIENT_INDEXER",
      details: { method: "getMerkleProofs", retryable: true },
    });
  });

  it("reports a missing method as unsupported and ends a slot poll at once", async () => {
    const { indexer: client, fetch } = indexer([{ error: -32601 }, { slot: 10 }]);
    const error = await client
      .getMerkleProofs(TREE, [LEAF], atSlot(10n, ONE_RETRY))
      .catch((cause: unknown) => cause);
    expect(error).toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getMerkleProofs" },
    });
    expect(JSON.stringify(error)).not.toContain("server text");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("makes one request without a required slot", async () => {
    const { indexer: client, fetch } = indexer([{ slot: 1 }, { slot: 10 }]);
    await expect(client.getMerkleProofs(TREE, [LEAF])).resolves.toMatchObject({
      context: { slot: 1n },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("classifies an exhausted slot poll by its final attempt", async () => {
    const lagging = indexer([{ error: -32603 }, { slot: 9 }]).indexer;
    await expect(
      lagging.getMerkleProofs(TREE, [LEAF], atSlot(10n, ONE_RETRY)),
    ).rejects.toMatchObject({
      code: "CLIENT_INDEXER_NOT_CAUGHT_UP",
      details: { target: "10", latest: "9", attempts: 2 },
    });
    const failing = indexer([{ slot: 9 }, { error: -32603 }]).indexer;
    await expect(
      failing.getMerkleProofs(TREE, [LEAF], atSlot(10n, ONE_RETRY)),
    ).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 2, lastCause: { category: "indexer" } },
    });
  });
});

describe("a poll's deadline", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("bounds a slot poll as a whole, its waits included", async () => {
    const { indexer: client, fetch } = indexer(Array.from({ length: 6 }, () => ({ slot: 9 })));
    let settled: unknown = "pending";
    void client
      .getMerkleProofs(TREE, [LEAF], atSlot(10n, createIndexerPollConfig(5, 1_000n, 1_000n)), {
        timeoutMs: 1_500,
      })
      .then(
        (value) => (settled = value),
        (error: unknown) => (settled = error),
      );
    await vi.advanceTimersByTimeAsync(1_501);
    expect(settled).toMatchObject({
      code: "CLIENT_TIMEOUT",
      details: { method: "getMerkleProofs", retryable: true },
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe("pollUntil", () => {
  const transient = (): ClientError =>
    new ClientError("CLIENT_INDEXER", { details: { method: "read", retryable: true } });

  /** Runs the poll over `script`, one entry per attempt, accepting `true`. */
  async function poll(script: readonly (boolean | ClientError)[]) {
    let calls = 0;
    const result = await pollUntil(
      async () => {
        const next = script[calls++];
        if (next === undefined) throw new Error("unscripted attempt");
        if (next instanceof ClientError) throw next;
        return next;
      },
      (accepted) => accepted,
      { config: ONE_RETRY },
    ).catch((cause: unknown) => cause);
    return { result, calls };
  }

  it("retries a transient failure", async () => {
    expect(await poll([transient(), true])).toEqual({ result: true, calls: 2 });
  });

  it("ends at once on a permanent failure", async () => {
    const permanent = new ClientError("CLIENT_INDEXER", {
      details: { method: "read", retryable: false },
    });
    expect(await poll([permanent, true])).toEqual({ result: permanent, calls: 1 });
  });

  it("carries the final attempt's failure, never one the indexer answered after", async () => {
    expect((await poll([false, transient()])).result).toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 2, lastCause: { category: "indexer" } },
    });
    const recovered = (await poll([transient(), false])).result;
    expect(recovered).toMatchObject({ code: "CLIENT_POLL_TIMED_OUT", details: { attempts: 2 } });
    expect((recovered as ClientError).details).not.toHaveProperty("lastCause");
  });
});
