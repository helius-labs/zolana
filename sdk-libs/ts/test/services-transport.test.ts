import { describe, expect, it } from "vitest";

import { postJsonRpc } from "../src/services/jsonrpc.js";
import { composeSignal } from "../src/services/signal.js";
import { TransportFailure, checkedEndpoint, httpJson } from "../src/services/transport.js";

function jsonResponse(body: string, init: ResponseInit = {}): Response {
  return new Response(body, {
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function fetchReturning(response: Response): typeof globalThis.fetch {
  return () => Promise.resolve(response);
}

function call(fetch: typeof globalThis.fetch, overrides: Record<string, unknown> = {}) {
  return postJsonRpc({
    fetch,
    url: new URL("https://indexer.example/rpc"),
    rpcMethod: "getThing",
    params: {},
    id: "call-1",
    maxRequestBytes: 1024,
    maxResponseBytes: 1024,
    ...overrides,
  });
}

async function failureOf(promise: Promise<unknown>): Promise<TransportFailure> {
  const error = await promise.then(
    () => undefined,
    (cause: unknown) => cause,
  );
  expect(error).toBeInstanceOf(TransportFailure);
  return error as TransportFailure;
}

describe("checkedEndpoint", () => {
  it("admits plain HTTP only when the policy names it", () => {
    expect(() => checkedEndpoint("http://ring.example", { field: "url" })).toThrowError(
      expect.objectContaining({ kind: "config", facts: { field: "url", protocol: "http:" } }),
    );
    expect(
      checkedEndpoint("http://ring.example", { field: "url", allowInsecureHttp: true }).protocol,
    ).toBe("http:");
  });

  it("rejects credentials and fragments", () => {
    for (const url of ["https://user:pw@x.example", "https://x.example/#frag"]) {
      expect(() => checkedEndpoint(url, { field: "url" })).toThrowError(
        expect.objectContaining({ kind: "config" }),
      );
    }
  });
});

describe("postJsonRpc envelope validation", () => {
  it("returns the result and keeps unsafe integers exact", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: "call-1", result: null }).replace(
      "null",
      '{"rootSeq":18446744073709551615}',
    );
    const result = (await call(fetchReturning(jsonResponse(body)))) as { rootSeq: unknown };
    expect(result.rootSeq).toBe("18446744073709551615");
  });

  it("refuses an envelope answering a different id", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: "other", result: {} });
    const failure = await failureOf(call(fetchReturning(jsonResponse(body))));
    expect(failure.kind).toBe("envelope");
  });

  it("surfaces a server error without its text", async () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: "call-1",
      error: { code: -32000, message: "secret detail" },
    });
    const failure = await failureOf(call(fetchReturning(jsonResponse(body))));
    expect(failure.kind).toBe("rpc");
    expect(failure.facts).toEqual({
      retryable: false,
      rpcCode: -32000,
      rpcMessage: { type: "string", length: 13 },
    });
    expect(JSON.stringify(failure.facts)).not.toContain("secret");
  });

  it("refuses an envelope that omits its result", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: "call-1" });
    const failure = await failureOf(call(fetchReturning(jsonResponse(body))));
    expect(failure.kind).toBe("missingResult");
  });

  it("refuses an oversized request body before fetch", async () => {
    let fetched = false;
    const failure = await failureOf(
      call(
        () => {
          fetched = true;
          return Promise.resolve(jsonResponse("{}"));
        },
        { params: { pad: "x".repeat(2048) } },
      ),
    );
    expect(failure.kind).toBe("requestTooLarge");
    expect(fetched).toBe(false);
  });

  it("classifies an elapsed timeout as retryable", async () => {
    const never: typeof globalThis.fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new Error("aborted"));
        });
      });
    const failure = await failureOf(
      postJsonRpc(
        {
          fetch: never,
          url: new URL("https://indexer.example/rpc"),
          rpcMethod: "getThing",
          params: {},
          id: "call-1",
          maxRequestBytes: 1024,
          maxResponseBytes: 1024,
        },
        { timeoutMs: 5 },
      ),
    );
    expect(failure.kind).toBe("timeout");
    expect(failure.facts).toEqual({ retryable: true });
  });
});

describe("httpJson", () => {
  function composed() {
    return composeSignal(undefined);
  }

  it("marks server statuses retryable and client statuses not", async () => {
    for (const [status, retryable] of [
      [500, true],
      [429, true],
      [400, false],
    ] as const) {
      const failure = await failureOf(
        httpJson({
          fetch: fetchReturning(jsonResponse("{}", { status })),
          url: new URL("https://x.example"),
          body: "{}",
          composed: composed(),
          maxResponseBytes: 1024,
        }),
      );
      expect(failure.kind).toBe("http");
      expect(failure.facts["status"]).toBe(status);
      expect(failure.facts["retryable"]).toBe(retryable);
    }
  });

  it("refuses a response above the byte cap", async () => {
    const failure = await failureOf(
      httpJson({
        fetch: fetchReturning(jsonResponse('{"pad":"' + "x".repeat(64) + '"}')),
        url: new URL("https://x.example"),
        body: "{}",
        composed: composed(),
        maxResponseBytes: 16,
      }),
    );
    expect(failure.kind).toBe("responseTooLarge");
    expect(failure.facts["maxBodyBytes"]).toBe(16);
  });

  it("refuses a non-JSON content type", async () => {
    const failure = await failureOf(
      httpJson({
        fetch: fetchReturning(new Response("<html>", { headers: { "content-type": "text/html" } })),
        url: new URL("https://x.example"),
        body: "{}",
        composed: composed(),
        maxResponseBytes: 1024,
      }),
    );
    expect(failure.kind).toBe("contentType");
    expect(failure.facts["contentType"]).toBe("text");
  });
});
