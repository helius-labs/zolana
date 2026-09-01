import { describe, expect, it, vi } from "vitest";

import { ApiError, ZolanaApi } from "../../src/api/index.js";

const HASH = "11111111111111111111111111111111";
const SIGNATURE = "1".repeat(64);
const REQUEST = { treeAccount: HASH, leaves: [HASH] } as never;
const RESULT = { context: { blockTime: 0, slot: 1 }, proofs: [] };

function success(result: unknown = RESULT): Response {
  return new Response(
    JSON.stringify({
      id: "test-account",
      jsonrpc: "2.0",
      result,
    }),
    { headers: { "content-type": "application/json; charset=utf-8" } },
  );
}

async function expectApiError(promise: Promise<unknown>, code: string): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe(code);
    return error as ApiError;
  }
  throw new Error("expected API call to fail");
}

describe("transport configuration", () => {
  it("uses the explicitly injected fetch and preserves safe query parameters", async () => {
    const injected = vi.fn<typeof globalThis.fetch>(() => Promise.resolve(success()));
    const api = new ZolanaApi({
      url: new URL("https://rpc.example.test/root/?tenant=one"),
      apiKey: "test-key",
      fetch: injected,
    });

    await api.getMerkleProofs(REQUEST);

    expect(injected).toHaveBeenCalledOnce();
    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/root/getMerkleProofs?tenant=one&api-key=test-key",
    );
    expect(injected.mock.calls[0]?.[1]?.redirect).toBe("error");
  });

  it("preserves query parameters from a shared endpoint", async () => {
    const injected = vi.fn<typeof globalThis.fetch>(() => Promise.resolve(success()));
    const api = new ZolanaApi({
      url: "https://gateway.example/zolana?api-key=k%2B1&tenant=alpha",
      fetch: injected,
    });

    await api.getMerkleProofs(REQUEST);

    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://gateway.example/zolana/getMerkleProofs?tenant=alpha&api-key=k%2B1",
    );
  });

  it("copies URL configuration before use", async () => {
    const url = new URL("https://rpc.example.test/first");
    const injected = vi.fn<typeof globalThis.fetch>(() => Promise.resolve(success()));
    const api = new ZolanaApi({ url, fetch: injected });
    url.pathname = "/second";

    await api.getMerkleProofs(REQUEST);

    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/first/getMerkleProofs",
    );
  });

  it("looks up every indexed event by transaction signature", async () => {
    const injected = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        success({
          context: { blockTime: 0, slot: 1 },
          transactions: [
            {
              eventIndex: 1,
              transaction: {
                slot: 2,
                txSignature: SIGNATURE,
                txViewingPk: null,
                salt: null,
                outputSlots: [],
                messages: [],
                nullifiers: [],
                proofless: false,
              },
            },
          ],
        }),
      ),
    );
    const api = new ZolanaApi({ url: "https://rpc.example.test", fetch: injected });

    const response = await api.getShieldedTransactionsBySignature({
      txSignature: SIGNATURE as never,
    });

    expect(response.transactions[0]?.eventIndex).toBe(1);
    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/getShieldedTransactionsBySignature",
    );
    expect(JSON.parse(String(injected.mock.calls[0]?.[1]?.body))).toMatchObject({
      params: { txSignature: SIGNATURE },
    });
  });

  it("encodes paginated nullifier lookups with the dedicated wire method", async () => {
    const injected = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        success({
          context: { blockTime: 0, slot: 1 },
          transactions: [],
          next: { slot: 9, signature: SIGNATURE },
        }),
      ),
    );
    const api = new ZolanaApi({ url: "https://rpc.example.test", fetch: injected });

    const response = await api.getShieldedTransactionsByNullifiers({
      nullifiers: [HASH],
      since: { slot: 7n, signature: SIGNATURE },
      limit: 1000n,
    } as never);

    expect(response.next).toEqual({ slot: 9n, signature: SIGNATURE });
    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/getShieldedTransactionsByNullifiers",
    );
    expect(JSON.parse(String(injected.mock.calls[0]?.[1]?.body))).toMatchObject({
      method: "getShieldedTransactionsByNullifiers",
      params: { nullifiers: [HASH], since: { slot: 7, signature: SIGNATURE }, limit: 1000 },
    });
  });

  it.each([
    [{ url: "not a url" }, "url"],
    [{ url: "file:///tmp/indexer" }, "url"],
    [{ url: "https://user:secret@rpc.example.test" }, "url"],
    [{ url: "https://rpc.example.test/#fragment" }, "url"],
    [{ url: "https://rpc.example.test?api-key=one&api-key=two" }, "apiKey"],
    [{ url: "https://rpc.example.test?api-key=one", apiKey: "two" }, "apiKey"],
    [{ url: "https://rpc.example.test", apiKey: "" }, "apiKey"],
    [{ url: "https://rpc.example.test", apiKey: "line\nbreak" }, "apiKey"],
  ])("rejects invalid URL or API-key configuration", (config, field) => {
    try {
      new ZolanaApi(config);
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).code).toBe("API_INVALID_CONFIG");
      expect((error as ApiError).details?.["field"]).toBe(field);
      return;
    }
    throw new Error("expected API configuration to fail");
  });

  it("rejects malformed timeouts before fetch", async () => {
    const injected = vi.fn(() => Promise.resolve(success()));
    const api = new ZolanaApi({ url: "https://rpc.example.test", fetch: injected });

    const error = await expectApiError(
      api.getMerkleProofs(REQUEST, { timeoutMs: 0 }),
      "API_INVALID_CONTEXT",
    );

    expect(error.details).toEqual({ field: "timeoutMs", method: "getMerkleProofs" });
    expect(injected).not.toHaveBeenCalled();
  });
});

describe("abort and timeout composition", () => {
  it("rejects an already-aborted signal before fetch", async () => {
    const controller = new AbortController();
    controller.abort();
    const injected = vi.fn(() => Promise.resolve(success()));
    const api = new ZolanaApi({ url: "https://rpc.example.test", fetch: injected });

    const error = await expectApiError(
      api.getMerkleProofs(REQUEST, { signal: controller.signal }),
      "API_ABORTED",
    );

    expect(error.details?.["retryable"]).toBe(false);
    expect(injected).not.toHaveBeenCalled();
  });

  it("composes a caller abort with the fetch signal", async () => {
    const controller = new AbortController();
    const api = new ZolanaApi({
      url: "https://rpc.example.test",
      fetch: (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => {
              reject(new Error("aborted"));
            },
            { once: true },
          );
        }),
    });

    const pending = api.getMerkleProofs(REQUEST, { signal: controller.signal });
    controller.abort();
    const error = await expectApiError(pending, "API_ABORTED");

    expect(error.details?.["retryable"]).toBe(false);
  });

  it("classifies an elapsed timeout as retryable", async () => {
    vi.useFakeTimers();
    try {
      const api = new ZolanaApi({
        url: "https://rpc.example.test",
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              "abort",
              () => {
                reject(new Error("timeout"));
              },
              { once: true },
            );
          }),
      });

      const pending = api.getMerkleProofs(REQUEST, { timeoutMs: 25 });
      const failure = expectApiError(pending, "API_TIMEOUT");
      await vi.advanceTimersByTimeAsync(25);
      const error = await failure;

      expect(error.details?.["retryable"]).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("classifies transport failures as retryable without retaining their cause", async () => {
    const secret = "transport-secret";
    const api = new ZolanaApi({
      url: "https://rpc.example.test",
      fetch: () => Promise.reject(new Error(secret)),
    });

    const error = await expectApiError(api.getMerkleProofs(REQUEST), "API_REQUEST");

    expect(error.details?.["retryable"]).toBe(true);
    expect(error.cause).toBeUndefined();
    expect(JSON.stringify(error)).not.toContain(secret);
  });
});

// The transport rewrites before parsing and the codec decides afterwards, so
// these two have to agree per field about which ones can carry a string. The
// bodies are raw text because `JSON.stringify` would round the literal under
// test before the transport ever saw it.
describe("integers past the safe-integer bound", () => {
  function respondWith(body: string): ZolanaApi {
    return new ZolanaApi({
      url: "https://rpc.example.test",
      fetch: () =>
        Promise.resolve(
          new Response(body, { headers: { "content-type": "application/json; charset=utf-8" } }),
        ),
    });
  }

  function merkleProofsBody(leafIndex: string, rootSeq: string): string {
    return `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"blockTime":0,"slot":1},"proofs":[{"leaf":"${HASH}","merkleContext":{"treeType":0,"tree":"${HASH}"},"path":["${HASH}"],"leafIndex":${leafIndex},"root":"${HASH}","rootSeq":${rootSeq},"rootIndex":0}]}}`;
  }

  it("reads a u64 above the safe-integer bound without losing precision", async () => {
    const rootSeq = (1n << 60n) + 7n;
    const api = respondWith(merkleProofsBody("0", rootSeq.toString()));

    const response = await api.getMerkleProofs(REQUEST);

    expect(response.proofs[0]?.rootSeq).toBe(rootSeq);
  });

  it("leaves a safe integer and a negative block time as they were sent", async () => {
    const body = `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"blockTime":-1700000000,"slot":1},"proofs":[{"leaf":"${HASH}","merkleContext":{"treeType":0,"tree":"${HASH}"},"path":["${HASH}"],"leafIndex":9007199254740991,"root":"${HASH}","rootSeq":0,"rootIndex":0}]}}`;
    const api = respondWith(body);

    const response = await api.getMerkleProofs(REQUEST);

    expect(response.proofs[0]?.leafIndex).toBe(9_007_199_254_740_991n);
    expect(response.context.blockTime).toBe(-1_700_000_000n);
  });

  it("refuses an unsafe number on a capped field as a number, not a quoted string", async () => {
    // One past MAX_SAFE_INTEGER: the transport must leave it unquoted so the
    // decoder's precision-loss refusal fires on a number, not on a string type.
    const api = respondWith(merkleProofsBody("9007199254740992", "0"));

    const error = await expectApiError(api.getMerkleProofs(REQUEST), "API_INVALID_RESULT");

    expect(error.details?.["path"]).toBe("$.proofs[0].leafIndex");
    expect(error.details?.["schemaCode"]).toBe("INDEXER_SCHEMA_INVALID_INTEGER");
  });

  it("does not rewrite a digit run inside a string payload", async () => {
    const payload = "99999999999999999999";
    const body = `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"blockTime":0,"slot":1},"matches":[{"slot":0,"txSignature":"${SIGNATURE}","outputSlot":{"viewTag":"${HASH}","outputContext":{"hash":"${HASH}","tree":"${HASH}","leafIndex":0},"payload":"${payload}"}}]}}`;
    const api = respondWith(body);

    const response = await api.getEncryptedUtxosByTags({ tags: [HASH] } as never);

    expect(response.matches[0]?.outputSlot.payload).toBe(payload);
  });
});
