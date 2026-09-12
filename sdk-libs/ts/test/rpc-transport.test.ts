import {
  address,
  blockhash,
  createDefaultRpcTransport,
  createSolanaRpcFromTransport,
  type RpcTransport,
} from "@solana/kit";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import { runKitRpc } from "../src/client/kit.js";
import { buildRingLookupTableTransaction, fetchRingLookupTable } from "../src/ring/lookup-table.js";

const OWNER = address("11111111111111111111111111111111");
const endpoints = {
  solanaRpcUrl: "https://rpc.example",
  indexerUrl: "https://indexer.example",
  proverUrl: "https://prover.example",
};
beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof globalThis.fetch>(() => new Promise<never>(() => {})),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("routes Solana calls through an explicitly configured RPC transport", async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
    const request: unknown = JSON.parse(String(init?.body));
    if (!request || typeof request !== "object" || !("id" in request))
      throw new Error("Missing request id");
    return Response.json({
      jsonrpc: "2.0",
      id: request.id,
      result: { context: { slot: 2 }, value: 42 },
    });
  });
  vi.stubGlobal("fetch", fetch);
  const config = {
    ...endpoints,
    solanaRpcTransport: createDefaultRpcTransport({ url: "https://custom-rpc.example" }),
  };
  const client = new ZolanaClient(config);
  expect(await client.getBalance(OWNER)).toBe(42n);
  expect(String(fetch.mock.calls[0]?.[0])).toBe("https://custom-rpc.example");
});

it("bounds raw RPC calls even when the transport ignores cancellation", async () => {
  vi.useFakeTimers();
  let observed: AbortSignal | undefined;
  const transport = vi.fn((request: Parameters<RpcTransport>[0]) => {
    observed = request.signal;
    return new Promise<never>(() => {});
  });
  const config = { ...endpoints, solanaRpcTransport: transport, solanaRpcRequestTimeoutMs: 25 };
  const client = new ZolanaClient(config);
  const pending = client.solanaRpc.getBalance(OWNER).send();
  let failure: unknown;
  const completion = pending.catch((error: unknown) => {
    failure = error;
  });
  await vi.advanceTimersByTimeAsync(25);
  expect(failure).toMatchObject({ code: "CLIENT_TIMEOUT" });
  await completion;
  expect(transport).toHaveBeenCalledOnce();
  expect(observed?.aborted).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

it("cancels a client read even when the transport never settles", async () => {
  const controller = new AbortController();
  let observed: AbortSignal | undefined;
  const transport = vi.fn((request: Parameters<RpcTransport>[0]) => {
    observed = request.signal;
    return new Promise<never>(() => {});
  });
  const config = { ...endpoints, solanaRpcTransport: transport };
  const client = new ZolanaClient(config);
  const pending = client.getBalance(OWNER, { signal: controller.signal });
  const completion = pending.catch((error: unknown) => error);
  await vi.waitFor(() => expect(transport).toHaveBeenCalledOnce());
  controller.abort();
  expect(await completion).toMatchObject({ code: "CLIENT_ABORTED" });
  expect(observed?.aborted).toBe(true);
});

it.each([0, -1, NaN, Infinity, 2_147_483_648])(
  "rejects an invalid RPC request timeout (%s)",
  (timeout) => {
    const config = { ...endpoints, solanaRpcRequestTimeoutMs: timeout };
    expect(() => new ZolanaClient(config)).toThrow("CLIENT_INVALID_CONFIG");
  },
);

it("applies the default 30-second timeout to native RPC requests", async () => {
  vi.useFakeTimers();
  const client = new ZolanaClient(endpoints);
  const completion = client.solanaRpc
    .getBalance(OWNER)
    .send()
    .catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(30_000);
  expect(await completion).toMatchObject({
    code: "CLIENT_TIMEOUT",
    details: { method: "getBalance" },
  });
  expect(globalThis.fetch).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

it("honors a shorter context deadline and reports timeout rather than cancellation", async () => {
  vi.useFakeTimers();
  const client = new ZolanaClient(endpoints);
  const completion = client.getBalance(OWNER, { timeoutMs: 10 }).catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(10);
  expect(await completion).toMatchObject({ code: "CLIENT_TIMEOUT" });
  expect(globalThis.fetch).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

it("does not send an already-cancelled RPC call", async () => {
  const client = new ZolanaClient(endpoints);
  await expect(
    client.solanaRpc.getBalance(OWNER).send({ abortSignal: AbortSignal.abort() }),
  ).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it("keeps another caller alive when a coalesced request is cancelled", async () => {
  vi.useFakeTimers();
  const response = Promise.withResolvers<Response>();
  let requestId: unknown;
  let networkSignal: AbortSignal | null | undefined;
  const fetch = vi.fn<typeof globalThis.fetch>((_input, init) => {
    const request: unknown = JSON.parse(String(init?.body));
    if (!request || typeof request !== "object" || !("id" in request))
      throw new Error("Missing request id");
    requestId = request.id;
    networkSignal = init?.signal;
    return response.promise;
  });
  vi.stubGlobal("fetch", fetch);
  const client = new ZolanaClient(endpoints);
  const controller = new AbortController();
  const first = client
    .getBalance(OWNER, { signal: controller.signal })
    .catch((error: unknown) => error);
  const second = client.getBalance(OWNER);
  await vi.advanceTimersByTimeAsync(0);
  expect(fetch).toHaveBeenCalledOnce();
  controller.abort();
  expect(await first).toMatchObject({ code: "CLIENT_ABORTED" });
  expect(networkSignal?.aborted).toBe(false);
  response.resolve(
    Response.json({ jsonrpc: "2.0", id: requestId, result: { context: { slot: 2 }, value: 42 } }),
  );
  expect(await second).toBe(42n);
  expect(vi.getTimerCount()).toBe(0);
});

it("rejects a late successful response after cancellation without retrying", async () => {
  const controller = new AbortController();
  const fetch = vi.fn<typeof globalThis.fetch>(async (_input, init) => {
    const request: unknown = JSON.parse(String(init?.body));
    if (!request || typeof request !== "object" || !("id" in request))
      throw new Error("Missing request id");
    controller.abort();
    return Response.json({
      jsonrpc: "2.0",
      id: request.id,
      result: { context: { slot: 2 }, value: 42 },
    });
  });
  vi.stubGlobal("fetch", fetch);
  const client = new ZolanaClient(endpoints);
  await expect(client.getBalance(OWNER, { signal: controller.signal })).rejects.toMatchObject({
    code: "CLIENT_ABORTED",
  });
  expect(fetch).toHaveBeenCalledOnce();
});

it("cleans up when an RPC implementation aborts and throws synchronously", async () => {
  vi.useFakeTimers();
  const controller = new AbortController();
  const operation = vi.fn(() => {
    controller.abort();
    throw new Error("transport failed");
  });
  await expect(
    runKitRpc("getSlot", { signal: controller.signal, timeoutMs: 20 }, operation),
  ).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
  expect(operation).toHaveBeenCalledOnce();
  expect(vi.getTimerCount()).toBe(0);
});

it("cancels ring table reads with an injected RPC that ignores cancellation", async () => {
  vi.useFakeTimers();
  let observed: AbortSignal | undefined;
  const transport = vi.fn((request: Parameters<RpcTransport>[0]) => {
    observed = request.signal;
    return new Promise<never>(() => {});
  });
  const client = {
    tree: OWNER,
    commitment: "confirmed",
    solanaRpc: createSolanaRpcFromTransport(transport),
  } as const;
  const completion = fetchRingLookupTable(
    { client, ringProgramId: OWNER, address: OWNER },
    { timeoutMs: 25 },
  ).catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(25);
  expect(await completion).toMatchObject({ code: "CLIENT_TIMEOUT" });
  expect(transport).toHaveBeenCalledOnce();
  expect(observed?.aborted).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

it("stops a ring table build while waiting for its finalized slot", async () => {
  vi.useFakeTimers();
  let observed: AbortSignal | undefined;
  const transport = vi.fn((request: Parameters<RpcTransport>[0]) => {
    observed = request.signal;
    return new Promise<never>(() => {});
  });
  const client = {
    tree: OWNER,
    commitment: "confirmed",
    solanaRpc: createSolanaRpcFromTransport(transport),
    getLatestBlockhash: vi.fn(async () => ({
      blockhash: blockhash("11111111111111111111111111111111"),
      lastValidBlockHeight: 5n,
    })),
  } as const;
  const controller = new AbortController();
  const completion = buildRingLookupTableTransaction(
    { client, ringProgramId: OWNER, feePayer: OWNER },
    { signal: controller.signal },
  ).catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(0);
  expect(transport).toHaveBeenCalledOnce();
  controller.abort();
  expect(await completion).toMatchObject({
    code: "RING_BUILD_LOOKUP_TABLE",
    causeCode: "CLIENT_ABORTED",
  });
  expect(observed?.aborted).toBe(true);
  expect(transport).toHaveBeenCalledOnce();
});
