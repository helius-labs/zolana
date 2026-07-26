import { DEFAULT_TREE_ADDRESS } from "@zolana/interface";
import { IndexerSchemaError, base64String, hash, limit } from "@zolana/indexer-api";
import { describe, expect, it } from "vitest";

import { ApiError, ZolanaApi } from "../src/index.js";
import {
  type JsonValue,
  type SemanticRequest,
  type TransportCaseName,
  type TransportSuccess,
  loadTransportFixture,
} from "./fixture.js";

const fixture = loadTransportFixture();
const inputs = fixture.inputs;
const successCases = fixture.expected.successes;
const numericResponseFields = new Set([
  "block_time",
  "high_element_index",
  "leaf_index",
  "low_element_index",
  "root_seq",
  "seq",
  "slot",
]);

interface CapturedCall {
  readonly request: SemanticRequest;
  readonly response: unknown;
}

function isJsonArray(value: JsonValue): value is readonly JsonValue[] {
  return Array.isArray(value);
}

function jsonResponse(result: JsonValue): Response {
  return new Response(
    JSON.stringify({
      id: "test-account",
      jsonrpc: "2.0",
      result: wireResponse(result),
    }),
    { headers: { "content-type": "application/json" } },
  );
}

function wireResponse(value: JsonValue, field = ""): unknown {
  if (isJsonArray(value)) return value.map((entry) => wireResponse(entry, field));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, wireResponse(entry, key)]),
    );
  }
  if (typeof value === "string" && numericResponseFields.has(field)) return Number(value);
  return value;
}

function normalizeResponse(value: unknown): JsonValue {
  if (typeof value === "bigint") return value.toString();
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (Array.isArray(value)) return value.map(normalizeResponse);
  if (typeof value !== "object") throw new Error("decoded response is not JSON-compatible");
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key.replaceAll(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`),
      normalizeResponse(entry),
    ]),
  );
}

function invoke(api: ZolanaApi, name: TransportCaseName): Promise<unknown> {
  switch (name) {
    case "encrypted-utxos":
      return api.getEncryptedUtxosByTags({
        tags: [hash(inputs.tag)],
        cursor: base64String(inputs.cursor),
        limit: limit(BigInt(inputs.optionalLimit)),
      });
    case "shielded-transactions":
      return api.getShieldedTransactionsByTags({ tags: [hash(inputs.tag)] });
    case "merkle-proofs":
      return api.getMerkleProofs({
        treeAccount: DEFAULT_TREE_ADDRESS,
        leaves: [hash(inputs.leaf)],
      });
    case "non-inclusion-proofs":
      return api.getNonInclusionProofs({
        treeAccount: DEFAULT_TREE_ADDRESS,
        leaves: [hash(inputs.leaf)],
      });
    case "nullifier-queue-default":
      return api.getNullifierQueueElements({
        treeAccount: DEFAULT_TREE_ADDRESS,
        limit: limit(BigInt(inputs.queueLimit)),
      });
    case "nullifier-queue-explicit":
      return api.getNullifierQueueElements({
        treeAccount: DEFAULT_TREE_ADDRESS,
        startSeq: BigInt(inputs.explicitStartSeq),
        limit: limit(BigInt(inputs.queueExplicitLimit)),
      });
  }
}

async function captureCall(vector: TransportSuccess): Promise<CapturedCall> {
  let captured: SemanticRequest | undefined;
  const api = new ZolanaApi({
    url: "https://rpc.example.test/base",
    fetch: (input, init) => {
      if (typeof init?.body !== "string") throw new Error("expected a string request body");
      const url = new URL(
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
      );
      captured = {
        body: JSON.parse(init.body) as Readonly<Record<string, JsonValue>>,
        contentType: new Headers(init.headers).get("content-type") ?? "",
        method: init.method ?? "",
        path: url.pathname,
        query: url.search.slice(1),
      };
      return Promise.resolve(jsonResponse(vector.response));
    },
  });
  const response = await invoke(api, vector.case);
  if (captured === undefined) throw new Error("request was not captured");
  return { request: captured, response };
}

function responseObject(value: JsonValue): Readonly<Record<string, JsonValue>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("normalized response must be an object");
  }
  return value;
}

function responseArray(
  value: Readonly<Record<string, JsonValue>>,
  field: string,
): readonly JsonValue[] {
  const entries = value[field];
  if (entries === undefined || !isJsonArray(entries)) {
    throw new Error(`normalized response ${field} must be an array`);
  }
  return entries;
}

function expectNonEmptyResponse(name: TransportCaseName, response: JsonValue): void {
  const value = responseObject(response);
  switch (name) {
    case "encrypted-utxos":
      expect(responseArray(value, "matches")).not.toHaveLength(0);
      return;
    case "shielded-transactions":
      expect(responseArray(value, "transactions")).not.toHaveLength(0);
      return;
    case "merkle-proofs":
    case "non-inclusion-proofs":
      expect(responseArray(value, "proofs")).not.toHaveLength(0);
      return;
    case "nullifier-queue-default":
    case "nullifier-queue-explicit":
      expect(responseArray(value, "elements")).not.toHaveLength(0);
  }
}

async function caughtApiError(api: ZolanaApi, name: TransportCaseName): Promise<ApiError> {
  try {
    await invoke(api, name);
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected API call to fail");
}

describe("Rust transport fixture", () => {
  it("uses the public tree address", () => {
    expect(inputs.treeAccount).toBe(DEFAULT_TREE_ADDRESS);
  });

  it.each(successCases)("matches the $case request and decoded response", async (vector) => {
    const actual = await captureCall(vector);
    const normalized = normalizeResponse(actual.response);

    expect(actual.request).toEqual(vector.request);
    expect(normalized).toEqual(vector.response);
    expectNonEmptyResponse(vector.case, normalized);
  });

  it("maps the shared Rust limit rejections to the public scalar error", () => {
    expect(fixture.expected.errors.invalidOptionalLimit.kind).toBe("InvalidRequest");
    expect(fixture.expected.errors.invalidRequiredLimit.kind).toBe("InvalidRequest");
    for (const value of [0n, 1001n]) {
      try {
        limit(value);
      } catch (error) {
        expect(error).toBeInstanceOf(IndexerSchemaError);
        expect((error as IndexerSchemaError).code).toBe("INDEXER_SCHEMA_INVALID_LIMIT");
        continue;
      }
      throw new Error(`expected limit ${value.toString()} to fail`);
    }
  });

  it("maps the shared Rust HTTP error", async () => {
    const rust = fixture.expected.errors.http.error;
    const api = new ZolanaApi({
      url: "https://rpc.example.test/base",
      fetch: () =>
        Promise.resolve(
          new Response(rust.body, {
            status: rust.status,
            headers: { "content-type": "text/plain" },
          }),
        ),
    });
    const error = await caughtApiError(api, "merkle-proofs");

    expect(rust.kind).toBe("Response");
    expect(error.code).toBe("API_HTTP");
    expect(error.details?.["status"]).toBe(rust.status);
  });

  it("maps the shared Rust JSON-RPC error", async () => {
    const rust = fixture.expected.errors.jsonRpc.error;
    const api = new ZolanaApi({
      url: "https://rpc.example.test/base",
      fetch: () =>
        Promise.resolve(
          new Response(
            JSON.stringify({
              id: "test-account",
              jsonrpc: "2.0",
              error: { code: rust.code, message: rust.message },
            }),
            { headers: { "content-type": "application/json" } },
          ),
        ),
    });
    const error = await caughtApiError(api, "non-inclusion-proofs");

    expect(rust.kind).toBe("JsonRpc");
    expect(error.code).toBe("API_JSON_RPC");
    expect(error.details?.["rpcCode"]).toBe(rust.code);
  });

  it("maps the shared Rust missing-result error", async () => {
    const rust = fixture.expected.errors.missingResult.error;
    const api = new ZolanaApi({
      url: "https://rpc.example.test/base",
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ id: "test-account", jsonrpc: "2.0" }), {
            headers: { "content-type": "application/json" },
          }),
        ),
    });
    const error = await caughtApiError(api, "nullifier-queue-explicit");

    expect(rust.kind).toBe("MissingResult");
    expect(error.code).toBe("API_MISSING_RESULT");
  });
});
