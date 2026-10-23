import { signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";
import vectors from "../../../test-vectors/private_transaction_confirmation.json" with { type: "json" };
import { ClientError, ZolanaClient } from "../src/client/index.js";
import { wireDecoder } from "../src/interface/decode.js";

const SIGNATURE = signature("1".repeat(64));
const OTHER_SIGNATURE = signature("1".repeat(63) + "2");
type Round = (typeof vectors)[number]["rounds"][number];
const DEFAULT_ROUND: Round = {
  status: "absent",
  failed: false,
  height: 101,
  slot: 100,
  indexerSlot: 100,
  indexed: false,
  indexerError: false,
};

function harness(
  rounds: readonly Round[],
  options: Readonly<{
    hang?: string;
    wrongSignature?: boolean;
    malformedHeight?: boolean;
    malformedIndexer?: boolean;
  }> = {},
) {
  let reads = 0;
  const methods: string[] = [];
  const signals: AbortSignal[] = [];
  const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
    const decode = wireDecoder((path) => new Error(`invalid test request ${path}`));
    const request = decode.record(JSON.parse(String(init?.body)), "request");
    const method = decode.string(request["method"], "method");
    methods.push(method);
    if (init?.signal) signals.push(init.signal);
    if (method === "getSignatureStatuses") reads++;
    const round = rounds[Math.min(reads - 1, rounds.length - 1)];
    if (round === undefined) throw new Error("request without a fixture round");
    if (options.hang === method) return new Promise<Response>(() => {});
    let result: unknown;
    switch (method) {
      case "getSignatureStatuses": {
        if (round.status === "rpcError")
          throw new TypeError("secret server error with api-key=hidden");
        const status =
          round.status === "absent"
            ? null
            : {
                slot: 42,
                confirmations: 0,
                err: round.failed ? "InsufficientFundsForFee" : null,
                ...(round.status === "missing" ? {} : { confirmationStatus: round.status }),
              };
        result = {
          context: { slot: round.slot },
          value: round.status === "invalid" ? [] : [status],
        };
        break;
      }
      case "getBlockHeight":
        result = options.malformedHeight ? -1 : round.height;
        expect(request["params"]).toEqual([{ commitment: "confirmed" }]);
        break;
      case "getSlot":
        result = round.slot;
        expect(request["params"]).toEqual([{ commitment: "confirmed" }]);
        break;
      case "getShieldedTransactionsBySignature":
        if (options.malformedIndexer) return reply(request["id"], { context: { slot: 100 } });
        if (round.indexerError)
          return reply(request["id"], undefined, { code: -32603, message: "secret body" });
        result = {
          context: { blockTime: 0, slot: round.indexerSlot },
          transactions: round.indexed
            ? [
                {
                  eventIndex: 0,
                  transaction: {
                    slot: 42,
                    txSignature: options.wrongSignature ? OTHER_SIGNATURE : SIGNATURE,
                    eventIndex: 0,
                    outputSlots: [],
                    messages: [],
                    nullifiers: [],
                    proofless: false,
                  },
                },
              ]
            : [],
        };
        break;
      default:
        throw new Error(`recovery must not invoke ${method}`);
    }
    return reply(request["id"], result);
  });
  const client = new ZolanaClient({
    solanaRpcUrl: "https://rpc.example.test",
    indexerUrl: "https://indexer.example.test",
    proofDataSource: "client",
    fetch,
    indexerConfig: { poll: { numRetries: rounds.length - 1, delayMs: 0n, maxDelayMs: 0n } },
  });
  return { client, methods, signals, reads: () => reads };
}

function reply(id: unknown, result: unknown, error?: unknown): Response {
  return new Response(
    JSON.stringify({ id, jsonrpc: "2.0", ...(error === undefined ? { result } : { error }) }),
    {
      headers: { "content-type": "application/json" },
    },
  );
}

async function outcome(operation: Promise<void>): Promise<string> {
  try {
    await operation;
    return "indexed";
  } catch (error) {
    if (!(error instanceof ClientError)) throw error;
    expect(JSON.stringify(error)).not.toContain("secret");
    switch (error.code) {
      case "CLIENT_TRANSACTION_EXPIRED":
        return "expired";
      case "CLIENT_TRANSACTION_NOT_INDEXED":
        return "notIndexed";
      case "CLIENT_TRANSACTION_OUTCOME_UNKNOWN":
        return "unknown";
      case "CLIENT_RPC":
        expect(error.details).toMatchObject({ reason: "transaction failed" });
        return "failed";
      default:
        throw error;
    }
  }
}

afterEach(() => vi.useRealTimers());

describe("private confirmation and recovery", () => {
  it.each(vectors)("matches Rust: $name", async (vector) => {
    const fixture = harness(vector.rounds);
    const height =
      vector.lastValidBlockHeight === null ? undefined : BigInt(vector.lastValidBlockHeight);
    await expect(
      outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, height)),
    ).resolves.toBe(vector.outcome);
    expect(fixture.reads()).toBe(vector.rounds.length);
    expect(fixture.methods).not.toContain("sendTransaction");
  });

  it("uses recovery for confirmPrivateTransaction when the RPC cache has evicted the signature", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }]);
    await fixture.client.confirmPrivateTransaction(SIGNATURE);
    expect(fixture.methods).toEqual(["getSignatureStatuses", "getShieldedTransactionsBySignature"]);
  });

  it("rejects an indexer event for a different signature", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }], { wrongSignature: true });
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "unknown",
    );
  });

  it("does not treat malformed block height as expiry", async () => {
    const fixture = harness([DEFAULT_ROUND], { malformedHeight: true });
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "unknown",
    );
    expect(fixture.methods).toEqual(["getSignatureStatuses", "getBlockHeight"]);
  });

  it.each([
    ["getSignatureStatuses", "unknown"],
    ["getShieldedTransactionsBySignature", "notIndexed"],
  ])("bounds a hung %s request and preserves evidence", async (hang, expected) => {
    vi.useFakeTimers();
    const fixture = harness([{ ...DEFAULT_ROUND, status: "confirmed" }], { hang });
    const result = outcome(
      fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, { timeoutMs: 10 }),
    );
    await vi.advanceTimersByTimeAsync(10);
    await expect(result).resolves.toBe(expected);
    expect(fixture.signals.at(-1)?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("bounds a hung request with the default overall deadline", async () => {
    vi.useFakeTimers();
    const fixture = harness([DEFAULT_ROUND], { hang: "getSignatureStatuses" });
    const result = outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n));
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(result).resolves.toBe("unknown");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("caller cancellation aborts a hung adapter and is never reported as expiry", async () => {
    const fixture = harness([DEFAULT_ROUND], { hang: "getSignatureStatuses" });
    const controller = new AbortController();
    const result = fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, {
      signal: controller.signal,
    });
    const assertion = expect(result).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
    controller.abort();
    await assertion;
    expect(fixture.methods).toEqual(["getSignatureStatuses"]);
    expect(fixture.signals.at(-1)?.aborted).toBe(true);
  });

  it("stops on a malformed indexer answer without claiming absence", async () => {
    const fixture = harness([DEFAULT_ROUND, DEFAULT_ROUND], { malformedIndexer: true });
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "unknown",
    );
    expect(fixture.reads()).toBe(1);
    expect(
      fixture.methods.filter((method) => method === "getShieldedTransactionsBySignature"),
    ).toHaveLength(1);
  });

  it("confirmTransaction does not report an unconfirmed failure as final", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "processed", failed: true }]);
    await expect(fixture.client.confirmTransaction(SIGNATURE)).rejects.toMatchObject({
      code: "CLIENT_RPC",
      details: { reason: "signature not confirmed" },
    });
    expect(fixture.methods).toEqual(["getSignatureStatuses"]);
  });

  it("validates heights and deadlines before I/O", async () => {
    const fixture = harness([DEFAULT_ROUND]);
    for (const height of [-1n, 1n << 64n]) {
      await expect(
        fixture.client.waitForPrivateTransaction(SIGNATURE, height),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_CONFIG" });
    }
    await expect(
      fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, { timeoutMs: 0 }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_CONTEXT" });
    expect(fixture.methods).toEqual([]);
  });
});
