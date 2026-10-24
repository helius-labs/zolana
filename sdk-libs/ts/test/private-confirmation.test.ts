import { signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";
import vectors from "../../../test-vectors/private_transaction_confirmation.json" with { type: "json" };
import transactionErrors from "../../../test-vectors/solana_transaction_errors.json" with { type: "json" };
import { ClientError, ZolanaClient } from "../src/client/index.js";
import { isRetryable, retryCause, waitForProjection } from "../src/client/retry.js";
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

/**
 * Solana and the indexer are asked at once and the status no more once it is
 * confirmed, so each side counts its own rounds: the expiry read follows the
 * status read of its round. Requests are recorded and asserted by the test,
 * because a failed `expect` inside the mocked fetch would only look like an
 * RPC failure to the code under test.
 */
function harness(
  rounds: readonly Round[],
  options: Readonly<{
    hang?: string;
    wrongSignature?: boolean;
    malformedHeight?: boolean;
    malformedIndexer?: boolean;
    fatalIndexer?: boolean;
    transactionError?: unknown;
    statusAwaitsIndexer?: boolean;
  }> = {},
) {
  let statusReads = 0;
  let indexerReads = 0;
  let indexerAsked: () => void = () => {};
  const indexerRequested = new Promise<void>((resolve) => {
    indexerAsked = resolve;
  });
  const methods: string[] = [];
  const requests: { method: string; params: unknown }[] = [];
  const signals = new Map<string, AbortSignal>();
  const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
    const decode = wireDecoder((path) => new Error(`invalid test request ${path}`));
    const request = decode.record(JSON.parse(String(init?.body)), "request");
    const method = decode.string(request["method"], "method");
    methods.push(method);
    requests.push({ method, params: request["params"] });
    if (init?.signal) signals.set(method, init.signal);
    if (method === "getSignatureStatuses") statusReads++;
    if (method === "getShieldedTransactionsBySignature") {
      indexerReads++;
      indexerAsked();
    }
    const reads = method === "getShieldedTransactionsBySignature" ? indexerReads : statusReads;
    const round = rounds[Math.min(reads - 1, rounds.length - 1)];
    if (round === undefined) throw new Error(`${method} without a fixture round`);
    if (options.hang === method) return new Promise<Response>(() => {});
    let result: unknown;
    switch (method) {
      case "getSignatureStatuses": {
        if (options.statusAwaitsIndexer) await indexerRequested;
        if (round.status === "rpcError")
          throw new TypeError("secret server error with api-key=hidden");
        const status =
          round.status === "absent"
            ? null
            : {
                slot: 42,
                confirmations: 0,
                err: round.failed ? (options.transactionError ?? "InsufficientFundsForFee") : null,
                ...(round.status === "missing" ? {} : { confirmationStatus: round.status }),
              };
        result = {
          context: { slot: round.slot },
          value: round.status === "invalid" ? [] : [status],
        };
        break;
      }
      case "getEpochInfo":
        result = {
          epoch: 0,
          slotIndex: round.slot,
          slotsInEpoch: 432_000,
          absoluteSlot: round.slot,
          blockHeight: options.malformedHeight ? -1 : round.height,
          transactionCount: null,
        };
        break;
      case "getShieldedTransactionsBySignature":
        if (options.malformedIndexer) return reply(request["id"], { context: { slot: 100 } });
        if (options.fatalIndexer)
          return reply(request["id"], undefined, { code: -32000, message: "secret body" });
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
  return {
    client,
    methods,
    requests,
    signals,
    statusReads: () => statusReads,
    indexerReads: () => indexerReads,
  };
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
      case "CLIENT_TRANSACTION_FAILED":
        expect(error.details).toMatchObject({ signature: SIGNATURE });
        return "failed";
      default:
        throw error;
    }
  }
}

async function rejection(operation: Promise<unknown>): Promise<unknown> {
  return operation.then(
    () => undefined,
    (cause: unknown) => cause,
  );
}

function sorted(methods: readonly string[]): string[] {
  return [...methods].sort();
}

afterEach(() => vi.useRealTimers());

describe("legacy error compatibility", () => {
  it("retains indexer timeout construction, details and retry classification", () => {
    const legacy = new ClientError("CLIENT_INDEXER_TIMEOUT", {
      details: { signature: SIGNATURE, attempts: 2, expectedTags: 1 },
    });
    expect(new ClientError("CLIENT_INDEXER_TIMEOUT").code).toBe("CLIENT_INDEXER_TIMEOUT");
    expect(legacy.details).toEqual({ signature: SIGNATURE, attempts: 2, expectedTags: 1 });
    expect(isRetryable(legacy)).toBe(true);
    expect(retryCause(legacy)).toEqual({ category: "indexerTimeout" });
    expect(
      new ClientError("CLIENT_POLL_TIMED_OUT", {
        details: { attempts: 2, lastCause: { category: "indexerTimeout" } },
      }).details,
    ).toEqual({ attempts: 2, lastCause: { category: "indexerTimeout" } });
  });
});

describe("private confirmation and recovery", () => {
  it.each(vectors)("matches Rust: $name", async (vector) => {
    const fixture = harness(vector.rounds);
    const height =
      vector.lastValidBlockHeight === null ? undefined : BigInt(vector.lastValidBlockHeight);
    await expect(
      outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, height)),
    ).resolves.toBe(vector.outcome);
    expect(fixture.indexerReads()).toBe(vector.rounds.length);
    expect(fixture.methods).not.toContain("sendTransaction");
  });

  it("reads expiry from one confirmed bank and statuses beyond the recent cache", async () => {
    const fixture = harness([DEFAULT_ROUND]);
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "expired",
    );
    expect(fixture.requests).toContainEqual({
      method: "getSignatureStatuses",
      params: [[SIGNATURE], { searchTransactionHistory: true }],
    });
    expect(fixture.requests).toContainEqual({
      method: "getEpochInfo",
      params: [{ commitment: "confirmed" }],
    });
    expect(fixture.methods).not.toContain("getBlockHeight");
    expect(fixture.methods).not.toContain("getSlot");
  });

  it("uses recovery for confirmPrivateTransaction when the RPC cache has evicted the signature", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }]);
    await fixture.client.confirmPrivateTransaction(SIGNATURE);
    expect(sorted(fixture.methods)).toEqual([
      "getShieldedTransactionsBySignature",
      "getSignatureStatuses",
    ]);
  });

  it("asks Solana and the indexer in the same round", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "confirmed", indexed: true }], {
      statusAwaitsIndexer: true,
    });
    await expect(
      outcome(
        fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, { timeoutMs: 1_000 }),
      ),
    ).resolves.toBe("indexed");
  });

  it("does not ask for the status again once it is confirmed", async () => {
    const confirmed = { ...DEFAULT_ROUND, status: "confirmed" };
    const fixture = harness([confirmed, confirmed, confirmed]);
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "notIndexed",
    );
    expect(fixture.statusReads()).toBe(1);
    expect(fixture.indexerReads()).toBe(3);
  });

  it("reports a confirmed failure with the chain's error, not as a retryable RPC blip", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "finalized", failed: true }], {
      transactionError: { InstructionError: [0, { Custom: 7001 }] },
    });
    const error = await rejection(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n));
    expect(error).toMatchObject({
      code: "CLIENT_TRANSACTION_FAILED",
      details: {
        signature: SIGNATURE,
        transactionError: '{"InstructionError":[0,{"Custom":7001}]}',
      },
    });
    expect(isRetryable(error)).toBe(false);
  });

  it("never carries free text from a transaction error", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "confirmed", failed: true }], {
      transactionError: "secret text with spaces",
    });
    await expect(outcome(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n))).resolves.toBe(
      "unknown",
    );
  });

  it.each(transactionErrors)(
    "decodes Rust's transaction error encoding: %j",
    async (transactionError) => {
      const fixture = harness([{ ...DEFAULT_ROUND, status: "finalized", failed: true }], {
        transactionError,
      });
      await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject(
        {
          code: "CLIENT_TRANSACTION_FAILED",
          details: {
            signature: SIGNATURE,
            transactionError:
              typeof transactionError === "string"
                ? transactionError
                : JSON.stringify(transactionError),
          },
        },
      );
      expect(fixture.methods).not.toContain("sendTransaction");
    },
  );

  it.each([
    false,
    0,
    [],
    "SecretToken123",
    { ApiKey: "SecretToken123" },
    {},
    { InstructionError: [0, { BorshIoError: "SecretToken123" }] },
    { InstructionError: [0, "SecretToken123"] },
    { InstructionError: [0, { Custom: "7001" }] },
    { InstructionError: [0, { Custom: -1 }] },
    { InstructionError: [0, { Custom: 1.5 }] },
    { InstructionError: [0, { Custom: 4_294_967_296 }] },
    { InstructionError: [256, "InvalidArgument"] },
    { InstructionError: [0, null] },
    { InstructionError: [0] },
    { InstructionError: [0, "InvalidArgument", "SecretToken123"] },
    { InstructionError: [0, { Custom: 1, ApiKey: "SecretToken123" }] },
    { DuplicateInstruction: 256 },
    { InsufficientFundsForRent: { account_index: "0" } },
    { InsufficientFundsForRent: { account_index: 0, ApiKey: "SecretToken123" } },
    { ProgramExecutionTemporarilyRestricted: { account_index: -1 } },
    { AlreadyProcessed: null },
    { DuplicateInstruction: 0, ApiKey: "SecretToken123" },
  ])("rejects malformed transaction errors without exposing them: %j", async (transactionError) => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "finalized", failed: true }], {
      transactionError,
    });
    const error = await rejection(fixture.client.confirmTransaction(SIGNATURE));
    expect(error).toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { method: "getSignatureStatuses", path: "err" },
    });
    expect(JSON.stringify(error)).not.toContain("SecretToken123");
    expect(fixture.methods).toEqual(["getSignatureStatuses"]);
    await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject({
      code: "CLIENT_TRANSACTION_OUTCOME_UNKNOWN",
      details: { causeCode: "CLIENT_INVALID_RPC_RESPONSE" },
    });
    expect(fixture.methods).not.toContain("sendTransaction");
    expect(fixture.methods).not.toContain("getEpochInfo");
  });

  it("reports a confirmed chain failure immediately and aborts a hung indexer", async () => {
    vi.useFakeTimers();
    const fixture = harness([{ ...DEFAULT_ROUND, status: "finalized", failed: true }], {
      hang: "getShieldedTransactionsBySignature",
    });
    const controller = new AbortController();
    const observed = vi.fn();
    const result = rejection(
      fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, {
        timeoutMs: 60_000,
        signal: controller.signal,
      }),
    ).then(observed);
    try {
      // Flush requests without reaching the wait's deadline.
      await vi.advanceTimersByTimeAsync(1);
      expect(observed).toHaveBeenCalledWith(
        expect.objectContaining({
          code: "CLIENT_TRANSACTION_FAILED",
          details: { signature: SIGNATURE, transactionError: "InsufficientFundsForFee" },
        }),
      );
      expect(fixture.signals.get("getShieldedTransactionsBySignature")?.aborted).toBe(true);
      expect(fixture.indexerReads()).toBe(1);
      expect(fixture.statusReads()).toBe(1);
      expect(fixture.methods).not.toContain("sendTransaction");
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      controller.abort();
      await result;
    }
  });

  it("confirmTransaction reports a confirmed failure the same way", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "confirmed", failed: true }]);
    await expect(fixture.client.confirmTransaction(SIGNATURE)).rejects.toMatchObject({
      code: "CLIENT_TRANSACTION_FAILED",
      details: { signature: SIGNATURE, transactionError: "InsufficientFundsForFee" },
    });
    expect(fixture.requests).toEqual([{ method: "getSignatureStatuses", params: [[SIGNATURE]] }]);
  });

  it("rejects an indexer event for a different signature", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }, DEFAULT_ROUND], {
      wrongSignature: true,
    });
    await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { method: "getShieldedTransactionsBySignature" },
    });
    expect(fixture.indexerReads()).toBe(1);
  });

  it("does not treat malformed block height as expiry", async () => {
    const fixture = harness([DEFAULT_ROUND], { malformedHeight: true });
    await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject({
      code: "CLIENT_TRANSACTION_OUTCOME_UNKNOWN",
      details: { causeCode: "CLIENT_INVALID_RPC_RESPONSE" },
    });
    expect(sorted(fixture.methods)).toEqual([
      "getEpochInfo",
      "getShieldedTransactionsBySignature",
      "getSignatureStatuses",
    ]);
  });

  it("does not report an RPC outage as indexer lag", async () => {
    const fixture = harness([{ ...DEFAULT_ROUND, status: "rpcError" }]);
    const error = await rejection(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n));
    expect(error).toMatchObject({
      code: "CLIENT_TRANSACTION_OUTCOME_UNKNOWN",
      details: { causeCode: "CLIENT_RPC" },
    });
    expect(JSON.stringify(error)).not.toContain("secret");
  });

  it("returns an indexer error that waiting cannot fix as itself", async () => {
    const fixture = harness([DEFAULT_ROUND, DEFAULT_ROUND], { fatalIndexer: true });
    await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject({
      code: "CLIENT_INDEXER",
      details: { method: "getShieldedTransactionsBySignature", retryable: false },
    });
    expect(fixture.indexerReads()).toBe(1);
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
    expect(fixture.signals.get(hang)?.aborted).toBe(true);
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

  it.each([false, true])(
    "retains indexed success at the deadline when an RPC read hangs (wrong signature: %s)",
    async (wrongSignature) => {
      vi.useFakeTimers();
      const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }], {
        hang: "getSignatureStatuses",
        wrongSignature,
      });
      const result = outcome(
        fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, { timeoutMs: 10 }),
      );
      await vi.advanceTimersByTimeAsync(10);
      await expect(result).resolves.toBe(wrongSignature ? "unknown" : "indexed");
      expect(fixture.signals.get("getSignatureStatuses")?.aborted).toBe(true);
      expect(fixture.methods).not.toContain("sendTransaction");
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it("does not turn caller cancellation into indexed success", async () => {
    vi.useFakeTimers();
    const fixture = harness([{ ...DEFAULT_ROUND, indexed: true }], {
      hang: "getSignatureStatuses",
    });
    const controller = new AbortController();
    const result = rejection(
      fixture.client.waitForPrivateTransaction(SIGNATURE, 100n, undefined, {
        signal: controller.signal,
        timeoutMs: 10,
      }),
    );
    await vi.advanceTimersByTimeAsync(1);
    controller.abort();
    await expect(result).resolves.toMatchObject({ code: "CLIENT_ABORTED" });
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
    expect(fixture.methods).not.toContain("getEpochInfo");
    expect(fixture.signals.get("getSignatureStatuses")?.aborted).toBe(true);
  });

  it("stops on a malformed indexer answer without claiming absence", async () => {
    const fixture = harness([DEFAULT_ROUND, DEFAULT_ROUND], { malformedIndexer: true });
    await expect(fixture.client.waitForPrivateTransaction(SIGNATURE, 100n)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { method: "getShieldedTransactionsBySignature" },
    });
    expect(fixture.indexerReads()).toBe(1);
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

describe("projection deadline", () => {
  const NOT_READY: ReadonlySet<"CLIENT_INDEXER_PROOF_DATA_NOT_READY"> = new Set([
    "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
  ]);
  const POLL = { numRetries: 3, delayMs: 0n, maxDelayMs: 0n };

  it("passes through a timeout that a request raised on its own timer", async () => {
    const proverTimeout = new ClientError("CLIENT_TIMEOUT", {
      details: { method: "prove", retryable: true },
    });
    await expect(
      waitForProjection(() => Promise.reject(proverTimeout), NOT_READY, undefined, POLL, 60_000),
    ).rejects.toBe(proverTimeout);
  });

  it("reports its own deadline as the last projection error", async () => {
    vi.useFakeTimers();
    const notReady = new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
    let reads = 0;
    const result = waitForProjection(
      () => (reads++ === 0 ? Promise.reject(notReady) : new Promise<never>(() => {})),
      NOT_READY,
      undefined,
      POLL,
      10,
    );
    const assertion = expect(result).rejects.toBe(notReady);
    await vi.advanceTimersByTimeAsync(10);
    await assertion;
  });
});
