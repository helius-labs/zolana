import {
  address,
  blockhash,
  getBase64EncodedWireTransaction,
  getBase58Decoder,
  signature,
} from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientError, ZolanaClient } from "../src/client/index.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";

const RPC_URL = "https://rpc.example.com/zolana";
const ACCOUNT = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
const SIGNATURE = signature(getBase58Decoder().decode(new Uint8Array(64).fill(7)));

/** Raw JSON results, so integers above 2^53 reach the client unrounded. */
const RESULTS: Readonly<Record<string, string>> = {
  getLatestBlockhash: `{"context":{"slot":1},"value":{"blockhash":"${SYSTEM_PROGRAM}","lastValidBlockHeight":9007199254740993}}`,
  getBalance: `{"context":{"slot":1},"value":18446744073709551615}`,
  getSlot: "42",
  getAccountInfo: `{"context":{"slot":1},"value":null}`,
  getSignatureStatuses: `{"context":{"slot":1},"value":[{"slot":42,"confirmations":null,"err":null,"confirmationStatus":"finalized","status":{"Ok":null}}]}`,
  sendTransaction: `"${SIGNATURE}"`,
};

interface SeenRequest {
  readonly url: string;
  readonly method: unknown;
  readonly body: string;
  readonly headers: Headers;
}

function jsonRpcRequest(body: string): Readonly<{ id: unknown; method: unknown }> {
  const value: unknown = JSON.parse(body);
  if (typeof value !== "object" || value === null || !("id" in value) || !("method" in value)) {
    throw new Error("not a JSON-RPC request");
  }
  return { id: value.id, method: value.method };
}

/** A Solana RPC endpoint behind `fetch` that answers `RESULTS`, after `rateLimited` 429s. */
function solanaRpcFetch(rateLimited = 0) {
  const seen: SeenRequest[] = [];
  let refusals = rateLimited;
  // A browser's `fetch` throws unless called without a receiver or on the global.
  const fetch = vi.fn<typeof globalThis.fetch>(function (this: unknown, input, init) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    const body = String(init?.body);
    const request = jsonRpcRequest(body);
    seen.push({
      url: String(input),
      method: request.method,
      body,
      headers: new Headers(init?.headers),
    });
    if (refusals > 0) {
      refusals -= 1;
      return Promise.resolve(new Response("rate limited", { status: 429 }));
    }
    const result = typeof request.method === "string" ? RESULTS[request.method] : undefined;
    if (result === undefined) throw new Error(`unexpected method ${String(request.method)}`);
    return Promise.resolve(
      new Response(`{"jsonrpc":"2.0","id":${JSON.stringify(request.id)},"result":${result}}`, {
        headers: { "content-type": "application/json" },
      }),
    );
  });
  return { fetch, seen };
}

function rpcClient(fetch?: typeof globalThis.fetch): ZolanaClient {
  return new ZolanaClient({
    solanaRpcUrl: RPC_URL,
    proofDataSource: "client",
    ...(fetch === undefined ? {} : { fetch }),
    indexerConfig: { poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n } },
  });
}

async function clientErrorOf(pending: Promise<unknown>): Promise<ClientError> {
  try {
    await pending;
  } catch (error) {
    if (error instanceof ClientError) return error;
    throw error;
  }
  throw new Error("expected a ClientError");
}

function refusedGlobalFetch() {
  const global = vi.fn<typeof globalThis.fetch>(() => {
    throw new Error("global fetch called");
  });
  vi.stubGlobal("fetch", global);
  return global;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Solana RPC through the configured fetch", () => {
  it("sends every client RPC call through the configured fetch", async () => {
    const global = refusedGlobalFetch();
    const { fetch, seen } = solanaRpcFetch();
    const client = rpcClient(fetch);

    const latest = await client.getLatestBlockhash();
    const balance = await client.getBalance(ACCOUNT);
    const slot = await client.getSlot();
    const account = await client.getAccount(ACCOUNT);
    const landed = await client.confirmTransaction(SIGNATURE);
    const transaction = compileUnsignedTransaction({
      feePayer: ACCOUNT,
      computeUnitLimit: 200_000,
      instructions: [{ programAddress: SYSTEM_PROGRAM }],
      lifetime: { blockhash: blockhash(SYSTEM_PROGRAM), lastValidBlockHeight: 1n },
    });
    const sent = await client.solanaRpc
      .sendTransaction(getBase64EncodedWireTransaction(transaction), { encoding: "base64" })
      .send();

    expect(latest.lastValidBlockHeight).toBe(9_007_199_254_740_993n);
    expect(balance).toBe(18_446_744_073_709_551_615n);
    expect(slot).toBe(42n);
    expect(account).toBeUndefined();
    expect(landed).toBe(42n);
    expect(sent).toBe(SIGNATURE);
    expect(seen.map((request) => request.method)).toEqual([
      "getLatestBlockhash",
      "getBalance",
      "getSlot",
      "getAccountInfo",
      "getSignatureStatuses",
      "sendTransaction",
    ]);
    for (const request of seen) {
      expect(request.url).toBe(RPC_URL);
      expect(request.headers.get("content-type")).toBe("application/json; charset=utf-8");
      expect(request.headers.get("accept")).toBe("application/json");
    }
    expect(global).not.toHaveBeenCalled();
  });

  it("lets a fetch wrapper retry a rate-limited signature status poll", async () => {
    refusedGlobalFetch();
    const { fetch: upstream, seen } = solanaRpcFetch(1);
    const retrying: typeof globalThis.fetch = async (input, init) => {
      const response = await upstream(input, init);
      return response.status === 429 ? upstream(input, init) : response;
    };

    await expect(rpcClient(retrying).confirmTransaction(SIGNATURE)).resolves.toBe(42n);
    expect(seen.map((request) => request.method)).toEqual([
      "getSignatureStatuses",
      "getSignatureStatuses",
    ]);
    expect(seen[1]?.body).toBe(seen[0]?.body);
  });

  it("fails a rate-limited call with the same error as Kit's default transport", async () => {
    refusedGlobalFetch();
    const configured = solanaRpcFetch(1);
    const custom = await clientErrorOf(rpcClient(configured.fetch).getSlot());
    vi.stubGlobal("fetch", solanaRpcFetch(1).fetch);
    const byDefault = await clientErrorOf(rpcClient().getSlot());

    expect(configured.seen.map((request) => request.method)).toEqual(["getSlot"]);
    expect(custom.code).toBe("CLIENT_RPC");
    expect(custom.details).toEqual({ method: "getSlot" });
    expect([custom.code, custom.details, custom.cause]).toEqual([
      byDefault.code,
      byDefault.details,
      byDefault.cause,
    ]);
  });

  it("aborts the configured fetch when the caller aborts", async () => {
    refusedGlobalFetch();
    const fetch = vi.fn<typeof globalThis.fetch>(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), {
            once: true,
          });
        }),
    );
    const controller = new AbortController();
    const pending = rpcClient(fetch).getSlot({ signal: controller.signal });
    pending.catch(() => undefined);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    controller.abort();

    await expect(pending).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
  });

  it("keeps Kit's default transport on the global fetch when none is configured", async () => {
    const { fetch, seen } = solanaRpcFetch();
    vi.stubGlobal("fetch", fetch);

    await expect(rpcClient().getSlot()).resolves.toBe(42n);
    expect(seen.map((request) => request.method)).toEqual(["getSlot"]);
    expect(seen[0]?.url).toBe(RPC_URL);
    expect(seen[0]?.headers.get("solana-client")).toMatch(/^js\//u);
  });
});
