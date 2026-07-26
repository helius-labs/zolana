import { describe, expect, it, vi } from "vitest";

import { ApiError, ZolanaApi } from "../src/index.js";

const HASH = "11111111111111111111111111111111";
const SIGNATURE = "1".repeat(64);
const REQUEST = { treeAccount: HASH, leaves: [HASH] } as never;
const RESULT = { context: { block_time: 0 }, proofs: [] };

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
    const injected = vi.fn(() => Promise.resolve(success()));
    const api = new ZolanaApi({
      url: new URL("https://rpc.example.test/root/?tenant=one"),
      apiKey: "test-key",
      fetch: injected,
    });

    await api.getMerkleProofs(REQUEST);

    expect(injected).toHaveBeenCalledOnce();
    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/root/get_merkle_proofs?tenant=one&api-key=test-key",
    );
  });

  it("copies URL configuration before use", async () => {
    const url = new URL("https://rpc.example.test/first");
    const injected = vi.fn(() => Promise.resolve(success()));
    const api = new ZolanaApi({ url, fetch: injected });
    url.pathname = "/second";

    await api.getMerkleProofs(REQUEST);

    expect(String(injected.mock.calls[0]?.[0])).toBe(
      "https://rpc.example.test/first/get_merkle_proofs",
    );
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

    expect(error.details).toEqual({ field: "timeoutMs", method: "get_merkle_proofs" });
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
    return `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"block_time":0},"proofs":[{"leaf":"${HASH}","merkle_context":{"tree_type":0,"tree":"${HASH}"},"path":["${HASH}"],"leaf_index":${leafIndex},"root":"${HASH}","root_seq":${rootSeq},"root_index":0}]}}`;
  }

  it("reads a u64 above the safe-integer bound without losing precision", async () => {
    const rootSeq = (1n << 60n) + 7n;
    const api = respondWith(merkleProofsBody("0", rootSeq.toString()));

    const response = await api.getMerkleProofs(REQUEST);

    expect(response.proofs[0]?.rootSeq).toBe(rootSeq);
  });

  it("leaves a safe integer and a negative block time as they were sent", async () => {
    const body = `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"block_time":-1700000000},"proofs":[{"leaf":"${HASH}","merkle_context":{"tree_type":0,"tree":"${HASH}"},"path":["${HASH}"],"leaf_index":9007199254740991,"root":"${HASH}","root_seq":0,"root_index":0}]}}`;
    const api = respondWith(body);

    const response = await api.getMerkleProofs(REQUEST);

    expect(response.proofs[0]?.leafIndex).toBe(9_007_199_254_740_991n);
    expect(response.context.blockTime).toBe(-1_700_000_000n);
  });

  it("refuses an oversized value on a field the tree height caps, quoted or not", async () => {
    const api = respondWith(merkleProofsBody((1n << 60n).toString(), "0"));

    const error = await expectApiError(api.getMerkleProofs(REQUEST), "API_INVALID_RESULT");

    expect(error.details?.["path"]).toBe("$.proofs[0].leaf_index");
  });

  it("does not rewrite a digit run inside a string payload", async () => {
    const payload = "99999999999999999999";
    const body = `{"id":"test-account","jsonrpc":"2.0","result":{"context":{"block_time":0},"matches":[{"slot":0,"tx_signature":"${SIGNATURE}","output_slot":{"view_tag":"${HASH}","output_context":{"hash":"${HASH}","tree":"${HASH}","leaf_index":0},"payload":"${payload}"}}]}}`;
    const api = respondWith(body);

    const response = await api.getEncryptedUtxosByTags({ tags: [HASH] } as never);

    expect(response.matches[0]?.outputSlot.payload).toBe(payload);
  });
});
