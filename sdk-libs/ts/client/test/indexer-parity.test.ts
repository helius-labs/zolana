import { ZolanaApi } from "@zolana/api";
import { base64String } from "@zolana/indexer-api";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { afterEach, describe, expect, it, vi } from "vitest";

import rpcFixture from "../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import {
  ClientError,
  type GetByTagsRequest,
  type IndexerRpcConfig,
  ZolanaIndexer,
} from "../src/index.js";
import { bytes } from "./helpers/prover-vectors.js";

const HASH = "1".repeat(32);
const TREE = HASH as Address;
const SIGNATURE = "1".repeat(64) as Signature;
const ZERO = new Uint8Array(32) as Bytes32;
const POLL: IndexerRpcConfig = {
  waitForIndexer: true,
  poll: { numRetries: 2, delayMs: 5n, maxDelayMs: 5n },
};
type IndexerMethod =
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByTags"
  | "getMerkleProofs"
  | "getNonInclusionProofs";

function envelope(result: unknown): Response {
  return Response.json({ id: "test-account", jsonrpc: "2.0", result });
}

function base64(bytes: Uint8Array): string {
  return base64String(bytes);
}

function outputSlot(): Record<string, unknown> {
  const fixture = rpcFixture.expected.indexer.tagQueries;
  return {
    view_tag: HASH,
    output_context: { hash: HASH, tree: TREE, leaf_index: 3 },
    payload: base64(bytes(fixture.outputPayloadBytes)),
  };
}

function merkleProof(): Record<string, unknown> {
  return {
    leaf: HASH,
    merkle_context: { tree_type: 1, tree: TREE },
    path: [HASH],
    leaf_index: 3,
    root: HASH,
    root_seq: 4,
    root_index: 5,
  };
}

function nonInclusionProof(): Record<string, unknown> {
  return {
    leaf: HASH,
    merkle_context: { tree_type: 1, tree: TREE },
    path: [HASH],
    root: HASH,
    root_seq: 4,
    root_index: 5,
    low_element: HASH,
    low_element_index: 1,
    high_element: HASH,
    high_element_index: 2,
  };
}

function tagResponse(
  kind: "matches" | "transactions",
  point = base64(bytes(rpcFixture.expected.indexer.tagQueries.txViewingPkBytes)),
): Record<string, unknown> {
  const fixture = rpcFixture.expected.indexer.tagQueries;
  const shared = {
    slot: 7,
    tx_signature: SIGNATURE,
    tx_viewing_pk: point,
    salt: base64(bytes(fixture.saltBytes)),
  };
  return kind === "matches"
    ? {
        context: { block_time: 42 },
        matches: [{ ...shared, output_slot: outputSlot() }],
        next_cursor: base64(bytes(fixture.nextCursorBytes)),
      }
    : {
        context: { block_time: 42 },
        transactions: [
          {
            ...shared,
            output_slots: [outputSlot()],
            messages: [{ view_tag: HASH, payload: base64(bytes(fixture.messagePayloadBytes)) }],
            nullifiers: [HASH],
            proofless: false,
          },
        ],
        next_cursor: base64(bytes(fixture.nextCursorBytes)),
      };
}

function request(): GetByTagsRequest {
  return { tags: [ZERO], cursor: Uint8Array.of(1, 2), limit: 10 };
}

function firstMatch(): Record<string, unknown> {
  const matches = tagResponse("matches")["matches"];
  if (!Array.isArray(matches) || typeof matches[0] !== "object" || matches[0] === null) {
    throw new Error("test response has no match");
  }
  return matches[0] as Record<string, unknown>;
}

function invoke(
  indexer: ZolanaIndexer,
  method: IndexerMethod,
  config?: IndexerRpcConfig,
): Promise<unknown> {
  switch (method) {
    case "getEncryptedUtxosByTags":
      return indexer.getEncryptedUtxosByTags(request(), config);
    case "getShieldedTransactionsByTags":
      return indexer.getShieldedTransactionsByTags(request(), config);
    case "getMerkleProofs":
      return indexer.getMerkleProofs(TREE, [ZERO], config);
    case "getNonInclusionProofs":
      return indexer.getNonInclusionProofs(TREE, [ZERO], config);
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ZolanaIndexer parity", () => {
  it("converts non-empty tag responses into ordered owned SDK values", async () => {
    const fixture = rpcFixture.expected.indexer.tagQueries;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((input) =>
        Promise.resolve(
          envelope(
            String(input).includes("encrypted")
              ? tagResponse("matches")
              : tagResponse("transactions"),
          ),
        ),
      ),
    });
    const indexer = new ZolanaIndexer(api);
    const encrypted = await indexer.getEncryptedUtxosByTags(request());
    const transactions = await indexer.getShieldedTransactionsByTags(request());

    expect(encrypted.nextCursor).toEqual(bytes(fixture.nextCursorBytes));
    expect(encrypted.matches[0]?.outputSlot).toEqual({
      viewTag: ZERO,
      outputContext: { hash: ZERO, tree: TREE, leafIndex: 3n },
      payload: bytes(fixture.outputPayloadBytes),
    });
    expect(encrypted.matches[0]?.txViewingPk?.toBytes()).toEqual(bytes(fixture.txViewingPkBytes));
    expect(encrypted.matches[0]?.salt).toEqual(bytes(fixture.saltBytes));
    expect(transactions.transactions[0]?.messages[0]).toEqual({
      viewTag: ZERO,
      data: bytes(fixture.messagePayloadBytes),
    });
    expect(transactions.transactions[0]?.nullifiers).toEqual([ZERO]);
    expect(transactions.transactions[0]?.txViewingPublicKey?.toBytes()).toEqual(
      bytes(fixture.txViewingPkBytes),
    );
    const slot = transactions.transactions[0]?.outputSlots[0];
    if (slot === undefined) throw new Error("converted transaction has no output");
    slot.viewTag[0] = 9;
    expect(slot.outputContext.hash[0]).toBe(0);
  });

  it("round-trips cursor bytes and defensively copies request values", async () => {
    let body: Record<string, unknown> | undefined;
    const fetchMock: typeof fetch = (_input, init) => {
      if (typeof init?.body !== "string") throw new Error("request body is not a string");
      body = JSON.parse(init.body) as Record<string, unknown>;
      return Promise.resolve(envelope(tagResponse("matches")));
    };
    const tag = new Uint8Array(32) as Bytes32;
    const cursor = Uint8Array.of(1, 2);
    const pending = new ZolanaIndexer(
      new ZolanaApi({ url: "https://indexer.example.test", fetch: fetchMock }),
    ).getEncryptedUtxosByTags({ tags: [tag], cursor, limit: 10 });
    tag.fill(9);
    cursor.fill(9);
    const response = await pending;

    expect(body?.["params"]).toEqual({ tags: [HASH], cursor: "AQI=", limit: 10 });
    expect(response.nextCursor).toEqual(Uint8Array.of(6, 7));
  });

  it("preserves tag-query response order", async () => {
    const match = firstMatch();
    const transactionResponse = tagResponse("transactions");
    const transactions = transactionResponse["transactions"];
    if (!Array.isArray(transactions) || typeof transactions[0] !== "object") {
      throw new Error("test response has no transaction");
    }
    const transaction = transactions[0] as Record<string, unknown>;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn((input) =>
        Promise.resolve(
          String(input).includes("encrypted")
            ? envelope({
                context: { block_time: 42 },
                matches: [match, { ...match, slot: 8 }],
                next_cursor: null,
              })
            : envelope({
                context: { block_time: 42 },
                transactions: [transaction, { ...transaction, slot: 8 }],
                next_cursor: null,
              }),
        ),
      ),
    });
    const indexer = new ZolanaIndexer(api);

    expect(
      (await indexer.getEncryptedUtxosByTags(request())).matches.map(({ slot }) => slot),
    ).toEqual([7n, 8n]);
    expect(
      (await indexer.getShieldedTransactionsByTags(request())).transactions.map(({ slot }) => slot),
    ).toEqual([7n, 8n]);
  });

  it.each([
    "getEncryptedUtxosByTags",
    "getShieldedTransactionsByTags",
    "getMerkleProofs",
    "getNonInclusionProofs",
  ] as const)("%s makes exactly one request by default", async (method) => {
    let calls = 0;
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example.test",
        fetch: vi.fn(() => {
          calls++;
          if (method === "getEncryptedUtxosByTags") {
            return Promise.resolve(envelope(tagResponse("matches")));
          }
          if (method === "getShieldedTransactionsByTags") {
            return Promise.resolve(envelope(tagResponse("transactions")));
          }
          return Promise.resolve(envelope({ context: { block_time: 1 }, proofs: [] }));
        }),
      }),
    );

    await invoke(indexer, method);
    expect(calls).toBe(1);
  });

  it.each([
    "getEncryptedUtxosByTags",
    "getShieldedTransactionsByTags",
    "getMerkleProofs",
    "getNonInclusionProofs",
  ] as const)("%s makes exactly one request when waiting is disabled", async (method) => {
    let calls = 0;
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example.test",
        fetch: vi.fn(() => {
          calls++;
          if (method === "getEncryptedUtxosByTags") {
            return Promise.resolve(envelope(tagResponse("matches")));
          }
          if (method === "getShieldedTransactionsByTags") {
            return Promise.resolve(envelope(tagResponse("transactions")));
          }
          return Promise.resolve(envelope({ context: { block_time: 1 }, proofs: [] }));
        }),
      }),
    );

    await invoke(indexer, method, {
      waitForIndexer: false,
      poll: { numRetries: 100, delayMs: 1n, maxDelayMs: 1n },
    });
    expect(calls).toBe(1);
  });

  it.each([
    "getEncryptedUtxosByTags",
    "getShieldedTransactionsByTags",
    "getMerkleProofs",
    "getNonInclusionProofs",
  ] as const)("%s polls against one captured target and stops when caught up", async (method) => {
    vi.useFakeTimers();
    vi.setSystemTime(100_000);
    let calls = 0;
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: vi.fn(() => {
        calls++;
        if (calls === 1) vi.setSystemTime(200_000);
        const blockTime = calls === 1 ? 99 : 100;
        if (method === "getEncryptedUtxosByTags") {
          return Promise.resolve(
            envelope({ ...tagResponse("matches"), context: { block_time: blockTime } }),
          );
        }
        if (method === "getShieldedTransactionsByTags") {
          return Promise.resolve(
            envelope({ ...tagResponse("transactions"), context: { block_time: blockTime } }),
          );
        }
        return Promise.resolve(
          envelope({
            context: { block_time: blockTime },
            proofs: [method === "getMerkleProofs" ? merkleProof() : nonInclusionProof()],
          }),
        );
      }),
    });
    const indexer = new ZolanaIndexer(api);
    const pending = invoke(indexer, method, POLL);
    const resolution = expect(pending).resolves.toBeDefined();
    await vi.runAllTimersAsync();
    await resolution;
    expect(calls).toBe(2);
  });

  it.each([
    new Uint8Array(33),
    Uint8Array.of(...new Uint8Array(32)),
    Uint8Array.of(...new Uint8Array(34)),
    Uint8Array.of(
      2,
      ...Uint8Array.from(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff".match(/../gu) ?? [],
        (value) => Number.parseInt(value, 16),
      ),
    ),
  ])("rejects malformed compressed P256 bytes", async (point) => {
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example.test",
        fetch: vi.fn(() => Promise.resolve(envelope(tagResponse("matches", base64(point))))),
      }),
    );

    await expect(indexer.getEncryptedUtxosByTags(request())).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: {
        method: "getEncryptedUtxosByTags",
        path: "$.matches[0].tx_viewing_pk",
      },
    });
  });

  it.each([
    [
      "short salt",
      {
        ...tagResponse("matches"),
        matches: [{ ...firstMatch(), salt: "AA==" }],
      },
    ],
    [
      "extended salt",
      {
        ...tagResponse("matches"),
        matches: [
          {
            ...firstMatch(),
            salt: base64(new Uint8Array(17)),
          },
        ],
      },
    ],
    [
      "malformed hash",
      {
        ...tagResponse("matches"),
        matches: [
          {
            ...firstMatch(),
            output_slot: { ...outputSlot(), view_tag: "1" },
          },
        ],
      },
    ],
    ["malformed cursor", { ...tagResponse("matches"), next_cursor: "!" }],
  ])("rejects %s at the client boundary", async (_name, result) => {
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example.test",
        fetch: vi.fn(() => Promise.resolve(envelope(result))),
      }),
    );
    await expect(indexer.getEncryptedUtxosByTags(request())).rejects.toBeInstanceOf(ClientError);
  });

  it.each([
    "getEncryptedUtxosByTags",
    "getShieldedTransactionsByTags",
    "getMerkleProofs",
    "getNonInclusionProofs",
  ] as const)("%s translates schema failures with a safe path", async (method) => {
    const result =
      method === "getEncryptedUtxosByTags"
        ? { context: { block_time: "private" }, matches: [] }
        : method === "getShieldedTransactionsByTags"
          ? { context: { block_time: "private" }, transactions: [] }
          : { context: { block_time: "private" }, proofs: [] };
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example.test",
        fetch: vi.fn(() => Promise.resolve(envelope(result))),
      }),
    );

    await expect(invoke(indexer, method)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { method, path: "$.context.block_time" },
      cause: { category: "external", code: "API_INVALID_RESULT" },
    });
  });

  it.each([
    "getEncryptedUtxosByTags",
    "getShieldedTransactionsByTags",
    "getMerkleProofs",
    "getNonInclusionProofs",
  ] as const)(
    "%s translates transport failures without retaining response data",
    async (method) => {
      const secret = "api-key-private-payload";
      const indexer = new ZolanaIndexer(
        new ZolanaApi({
          url: "https://indexer.example.test",
          apiKey: secret,
          fetch: vi.fn(() => Promise.reject(new Error(secret))),
        }),
      );
      const error: unknown = await invoke(indexer, method).catch((cause: unknown) => cause);

      expect(error).toEqual(
        expect.objectContaining({
          code: "CLIENT_REQUEST",
          details: { method, retryable: true },
          cause: { category: "external", code: "API_REQUEST" },
        }),
      );
      expect(JSON.stringify(error)).not.toContain(secret);
    },
  );

  it("preserves abort and timeout as typed client failures", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    controller.abort();
    const fetchMock: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      });
    const api = new ZolanaApi({
      url: "https://indexer.example.test",
      fetch: fetchMock,
    });
    const indexer = new ZolanaIndexer(api);

    await expect(
      indexer.getMerkleProofs(TREE, [ZERO], undefined, { signal: controller.signal }),
    ).rejects.toEqual(expect.objectContaining({ code: "CLIENT_ABORTED" }));
    const pending = indexer.getNonInclusionProofs(TREE, [ZERO], undefined, { timeoutMs: 5 });
    const rejection = expect(pending).rejects.toEqual(
      expect.objectContaining({
        code: "CLIENT_TIMEOUT",
        details: { method: "getNonInclusionProofs", retryable: true },
      }),
    );
    await vi.advanceTimersByTimeAsync(5);
    await rejection;
  });
});
