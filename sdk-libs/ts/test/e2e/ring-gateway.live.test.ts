// Opt in with RING_GATEWAY_URL and RING_GATEWAY_API_KEY against an isolated gateway.
// All five POST routes must be enabled and preserve the method path upstream.
import { beforeAll, describe, expect, it } from "vitest";

import { RingRpc } from "../../src/ring/index.js";
import { requiredEnv } from "./ring-live-helpers.js";

describe.skipIf(process.env["RING_GATEWAY_URL"] === undefined)("ring gateway", () => {
  let endpoint: URL;
  let apiKey: string;
  let client: RingRpc;

  beforeAll(() => {
    endpoint = new URL(requiredEnv("RING_GATEWAY_URL"));
    apiKey = requiredEnv("RING_GATEWAY_API_KEY");
    client = new RingRpc(endpoint, { apiKey });
  });

  async function post(method: string, body: string) {
    const url = new URL(endpoint);
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}/${method}`;
    url.searchParams.set("api-key", apiKey);
    return fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: AbortSignal.timeout(10_000),
      redirect: "error",
    });
  }

  it("serves the SDK with either supported key source", async () => {
    const health = await client.health({ timeoutMs: 10_000 });
    const keyed = new URL(endpoint);
    keyed.searchParams.set("api-key", apiKey);
    const fromUrl = new RingRpc(keyed);
    expect(await fromUrl.health({ timeoutMs: 10_000 })).toEqual(health);
    expect(new URL(fromUrl.url).searchParams.has("api-key")).toBe(false);
  });

  it("refuses missing and unknown gateway credentials before RPC dispatch", async () => {
    for (const rpc of [
      new RingRpc(endpoint),
      new RingRpc(endpoint, { apiKey: "00000000-0000-4000-8000-000000000000" }),
    ]) {
      await expect(rpc.health({ timeoutMs: 10_000 })).rejects.toMatchObject({
        code: "RING_RPC_TRANSPORT",
        details: { status: 401 },
      });
    }
  });

  it.each(["ringStatus", "ringDeposits", "createAuditorKey", "getDecryptedTransactions"])(
    "dispatches %s to its handler, which validates its parameters",
    async (method) => {
      const response = await post(
        method,
        JSON.stringify({ jsonrpc: "2.0", id: "route", method, params: {} }),
      );
      expect(response.status).toBe(200);
      const body: unknown = await response.json();
      expect(body).toMatchObject({ jsonrpc: "2.0", id: "route", error: { code: -32602 } });
    },
  );

  it.each(["ringStatus", "ringDeposits", "createAuditorKey", "getDecryptedTransactions"])(
    "refuses %s on the health route before dispatch",
    async (method) => {
      const response = await post(
        "health",
        JSON.stringify({ jsonrpc: "2.0", id: "mismatch", method, params: {} }),
      );
      expect(response.status).toBe(200);
      const body: unknown = await response.json();
      expect(body).toEqual({
        jsonrpc: "2.0",
        id: "mismatch",
        error: { code: -32601, message: "the method does not match the request path" },
      });
    },
  );

  it.each([
    '[{"jsonrpc":"2.0","id":1,"method":"health"}]',
    '{"jsonrpc":"2.0","id":1,"method":"health","method":"getDecryptedTransactions"}',
    '{"jsonrpc":"2.0","id":1,"method":"getDecryptedTransactions","method":"health"}',
    '{"jsonrpc":"2.0","id":1,"id":2,"method":"health"}',
    "not JSON",
  ])("refuses ambiguous or malformed bodies (%s)", async (request) => {
    const response = await post("health", request);
    expect(response.status).toBe(200);
    const body: unknown = await response.json();
    expect(body).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32601, message: "the method does not match the request path" },
    });
  });
});
