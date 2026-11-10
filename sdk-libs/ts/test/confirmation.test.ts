import { getBase58Decoder, signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SprClient } from "../src/client/client.js";
import { ClientError } from "../src/client/error.js";
import { createIndexerPollConfig } from "../src/client/retry.js";

const SIGNATURE = signature(getBase58Decoder().decode(new Uint8Array(64).fill(7)));
const ONE_RETRY = createIndexerPollConfig(1, 0n, 0n);
const SLOW = Object.freeze({ poll: createIndexerPollConfig(5, 1_000n, 1_000n) });

const landed = (commitment: string, err = "null"): string =>
  `{"slot":42,"confirmations":null,"err":${err},"confirmationStatus":"${commitment}","status":null}`;
const CONFIRMED = landed("confirmed");
const UNSEEN = "null";
/** A JSON-RPC error code in place of a status. */
const rpcError = (code: number): string => `error:${String(code)}`;

/**
 * A client whose Solana RPC answers each `getSignatureStatuses` with the next
 * of `statuses`, raw JSON as a node sends it, and whose indexer has not
 * indexed the transaction.
 */
function confirming(statuses: readonly string[]) {
  const reads = { rpc: 0, indexer: 0 };
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const request = JSON.parse(String(init?.body)) as Readonly<{ id: unknown }>;
    const id = JSON.stringify(request.id);
    if (new URL(String(input)).port === "8784") {
      reads.indexer += 1;
      return Response.json({
        jsonrpc: "2.0",
        id: request.id,
        result: { context: { slot: 1, blockTime: 0 }, transactions: [] },
      });
    }
    const status = statuses[reads.rpc++];
    if (status === undefined) throw new Error("unscripted status read");
    const answer = status.startsWith("error:")
      ? `"error":{"code":${status.slice(6)},"message":"server text"}`
      : `"result":{"context":{"slot":1},"value":[${status}]}`;
    return new Response(`{"jsonrpc":"2.0","id":${id},${answer}}`, {
      headers: { "content-type": "application/json" },
    });
  });
  const client = new SprClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
    indexerUrl: "http://127.0.0.1:8784",
    proverUrl: "http://127.0.0.1:3001",
    proofDataSource: "client",
    fetch,
    indexerConfig: { poll: ONE_RETRY },
  });
  return { client, reads };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("transaction confirmation", () => {
  it.each([
    [
      '{"InstructionError":[1,{"Custom":6001}]}',
      {
        error: "InstructionError",
        instructionIndex: 1,
        instructionError: "Custom",
        customCode: 6001,
      },
    ],
    [
      '{"InstructionError":[0,"InvalidArgument"]}',
      { error: "InstructionError", instructionIndex: 0, instructionError: "InvalidArgument" },
    ],
    ['"InsufficientFundsForFee"', { error: "InsufficientFundsForFee" }],
    ['{"InsufficientFundsForRent":{"account_index":2}}', { error: "InsufficientFundsForRent" }],
    ['"not an error name"', { error: "unknown" }],
  ])(
    "returns the chain's error %s once the transaction reaches the commitment",
    async (err, chain) => {
      const { client, reads } = confirming([landed("processed", err), landed("confirmed", err)]);
      const error = await client.confirmTransaction(SIGNATURE).catch((cause: unknown) => cause);
      expect(error).toBeInstanceOf(ClientError);
      if (!(error instanceof ClientError)) return;
      expect(error.code).toBe("CLIENT_TRANSACTION_FAILED");
      expect(error.details).toEqual({ signature: SIGNATURE, ...chain });
      expect(reads.rpc).toBe(2);
    },
  );

  it("asks again after a failed status read", async () => {
    const { client, reads } = confirming([rpcError(-32005), CONFIRMED]);
    await expect(client.confirmTransaction(SIGNATURE)).resolves.toBe(42n);
    expect(reads.rpc).toBe(2);
  });

  it("ends at once on an RPC without the status method", async () => {
    const { client, reads } = confirming([rpcError(-32601), CONFIRMED]);
    await expect(client.confirmTransaction(SIGNATURE)).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getSignatureStatuses" },
    });
    expect(reads.rpc).toBe(1);
  });

  it("classifies an exhausted wait by its final read", async () => {
    await expect(
      confirming([UNSEEN, rpcError(-32005)]).client.confirmTransaction(SIGNATURE),
    ).rejects.toMatchObject({
      code: "CLIENT_POLL_TIMED_OUT",
      details: { attempts: 2, lastCause: { category: "rpc" } },
    });
    await expect(
      confirming([rpcError(-32005), UNSEEN]).client.confirmTransaction(SIGNATURE),
    ).rejects.toMatchObject({
      code: "CLIENT_RPC",
      details: { method: "getSignatureStatuses", reason: "signature not confirmed" },
    });
  });

  it("reports a confirmed transaction the indexer does not show as landed", async () => {
    const { client, reads } = confirming([CONFIRMED]);
    const error = await client
      .confirmPrivateTransaction(SIGNATURE)
      .catch((cause: unknown) => cause);
    expect(error).toMatchObject({
      code: "CLIENT_TRANSACTION_NOT_INDEXED",
      details: { signature: SIGNATURE },
      cause: { category: "client", code: "CLIENT_INDEXER_TIMEOUT" },
    });
    expect(reads.indexer).toBe(2);
  });

  it("bounds the whole wait by the caller's deadline", async () => {
    vi.useFakeTimers();
    const { client, reads } = confirming(Array.from({ length: 6 }, () => UNSEEN));
    let settled: unknown = "pending";
    void client.confirmTransaction(SIGNATURE, SLOW, { timeoutMs: 1_500 }).then(
      (value) => (settled = value),
      (error: unknown) => (settled = error),
    );
    await vi.advanceTimersByTimeAsync(1_501);
    expect(settled).toMatchObject({
      code: "CLIENT_TIMEOUT",
      details: { method: "confirmTransaction", retryable: true },
    });
    expect(reads.rpc).toBe(2);
  });

  it("spends one deadline across confirmation and indexing", async () => {
    vi.useFakeTimers();
    const { client, reads } = confirming([UNSEEN, CONFIRMED]);
    let settled: unknown = "pending";
    void client.confirmPrivateTransaction(SIGNATURE, SLOW, { timeoutMs: 1_500 }).then(
      (value) => (settled = value),
      (error: unknown) => (settled = error),
    );
    await vi.advanceTimersByTimeAsync(1_501);
    expect(settled).toMatchObject({
      code: "CLIENT_TRANSACTION_NOT_INDEXED",
      details: { signature: SIGNATURE },
      cause: { category: "client", code: "CLIENT_TIMEOUT" },
    });
    expect(reads).toEqual({ rpc: 2, indexer: 1 });
  });
});
