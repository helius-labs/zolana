import { describe, expect, it } from "vitest";

import { ApiError, ZolanaApi } from "../src/index.js";

const HASH = "11111111111111111111111111111111";
const REQUEST = { treeAccount: HASH, leaves: [HASH] } as never;
const SECRET = "never-expose-this-api-key-or-body";

function apiFor(response: Response): ZolanaApi {
  return new ZolanaApi({
    url: `https://rpc.example.test?api-key=${SECRET}`,
    fetch: () => Promise.resolve(response),
  });
}

function envelope(value: Readonly<Record<string, unknown>>): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
}

async function apiError(response: Response, code: string): Promise<ApiError> {
  try {
    await apiFor(response).getMerkleProofs(REQUEST);
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe(code);
    expect(JSON.stringify(error)).not.toContain(SECRET);
    expect(String(error)).not.toContain(SECRET);
    return error as ApiError;
  }
  throw new Error("expected API call to fail");
}

describe("HTTP and body failures", () => {
  it.each([
    [400, false],
    [408, true],
    [425, true],
    [429, true],
    [500, true],
    [503, true],
  ])("classifies HTTP %i retry safety", async (status, retryable) => {
    const error = await apiError(
      new Response(`${SECRET}-${"x".repeat(200)}`, {
        status,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
      "API_HTTP",
    );

    expect(error.details).toEqual({
      method: "get_merkle_proofs",
      status,
      retryable,
      bodyBytes: SECRET.length + 1 + 200,
      contentType: "text",
    });
  });

  it("rejects successful text bodies without exposing them", async () => {
    const error = await apiError(
      new Response(SECRET, {
        headers: { "content-type": `text/${SECRET}` },
      }),
      "API_INVALID_CONTENT_TYPE",
    );

    expect(error.details?.["bodyBytes"]).toBe(SECRET.length);
  });

  it("rejects malformed JSON without exposing it", async () => {
    await apiError(
      new Response(`{"secret":"${SECRET}"`, {
        headers: { "content-type": "application/json" },
      }),
      "API_INVALID_JSON",
    );
  });

  it("rejects invalid UTF-8", async () => {
    await apiError(
      new Response(new Uint8Array([0xc3, 0x28]), {
        headers: { "content-type": "application/json" },
      }),
      "API_INVALID_TEXT",
    );
  });

  it("rejects oversized bodies before retaining them", async () => {
    const limit = 10 * 1024 * 1024;
    const error = await apiError(
      new Response("{}", {
        headers: {
          "content-length": String(limit + 1),
          "content-type": "application/json",
        },
      }),
      "API_RESPONSE_TOO_LARGE",
    );

    expect(error.details).toEqual({
      method: "get_merkle_proofs",
      bodyBytes: limit + 1,
      maxBodyBytes: limit,
      retryable: false,
    });
  });
});

describe("JSON-RPC envelope failures", () => {
  it("redacts JSON-RPC messages and ignores error data", async () => {
    const error = await apiError(
      envelope({
        id: "test-account",
        jsonrpc: "2.0",
        error: { code: -32_000, message: SECRET, data: { reflected: SECRET } },
      }),
      "API_JSON_RPC",
    );

    expect(error.details).toEqual({
      method: "get_merkle_proofs",
      retryable: false,
      rpcCode: -32_000,
      rpcMessage: { type: "string", length: SECRET.length },
    });
  });

  it("detects an omitted result", async () => {
    await apiError(
      envelope({
        id: "test-account",
        jsonrpc: "2.0",
      }),
      "API_MISSING_RESULT",
    );
  });

  it.each([
    { id: "wrong", jsonrpc: "2.0", result: { context: { block_time: 0 }, proofs: [] } },
    {
      id: "test-account",
      jsonrpc: "1.0",
      result: { context: { block_time: 0 }, proofs: [] },
    },
    {
      id: "test-account",
      jsonrpc: "2.0",
      result: { context: { block_time: 0 }, proofs: [] },
      error: { code: 1 },
    },
    {
      id: "test-account",
      jsonrpc: "2.0",
      result: { context: { block_time: 0 }, proofs: [] },
      extra: true,
    },
    { id: "test-account", jsonrpc: "2.0", error: "bad" },
    { id: "test-account", jsonrpc: "2.0", error: { code: 1.5 } },
    { id: "test-account", jsonrpc: "2.0", error: { message: 7 } },
    [],
    null,
  ])("rejects malformed or mismatched envelopes", async (value) => {
    await apiError(
      new Response(JSON.stringify(value), {
        headers: { "content-type": "application/json" },
      }),
      "API_INVALID_ENVELOPE",
    );
  });

  it("wraps strict response-schema errors with safe path metadata", async () => {
    const error = await apiError(
      envelope({
        id: "test-account",
        jsonrpc: "2.0",
        result: {
          context: { block_time: 0 },
          proofs: [{ [SECRET]: true }],
        },
      }),
      "API_INVALID_RESULT",
    );

    expect(error.details).toEqual({
      method: "get_merkle_proofs",
      retryable: false,
      schemaCode: "INDEXER_SCHEMA_UNKNOWN_FIELD",
    });
    expect(error.cause).toBeUndefined();
  });

  it("rejects malformed requests before fetch with safe schema metadata", async () => {
    let fetched = false;
    const api = new ZolanaApi({
      url: `https://rpc.example.test?api-key=${SECRET}`,
      fetch: () => {
        fetched = true;
        return Promise.resolve(new Response());
      },
    });

    try {
      await api.getMerkleProofs({ treeAccount: SECRET, leaves: [HASH] } as never);
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).code).toBe("API_INVALID_REQUEST");
      expect((error as ApiError).details).toEqual({
        method: "get_merkle_proofs",
        retryable: false,
        schemaCode: "INDEXER_SCHEMA_INVALID_ADDRESS",
        path: "$.tree_account",
      });
      expect(JSON.stringify(error)).not.toContain(SECRET);
      expect(fetched).toBe(false);
      return;
    }
    throw new Error("expected request validation to fail");
  });

  it("retains cursor paths on schema failures", async () => {
    const api = new ZolanaApi({
      url: `https://rpc.example.test?api-key=${SECRET}`,
      fetch: () => Promise.resolve(new Response()),
    });
    try {
      await api.getShieldedTransactionsByTags({
        tags: [HASH],
        cursor: "not-base64!",
      } as never);
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).code).toBe("API_INVALID_REQUEST");
      expect((error as ApiError).details).toEqual({
        method: "get_shielded_transactions_by_tags",
        retryable: false,
        schemaCode: "INDEXER_SCHEMA_INVALID_BASE64",
        path: "$.cursor",
      });
      return;
    }
    throw new Error("expected request validation to fail");
  });
});
