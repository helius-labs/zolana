import { describe, expect, it, vi } from "vitest";

import { ZolanaApi } from "../src/api/index.js";
import { RingRpc } from "../src/ring/rpc.js";
import { ProverClient } from "../src/client/prover/client.js";
import { ZolanaClient } from "../src/client/index.js";

const clients = [
  {
    name: "RingRpc",
    code: "RING_RPC_CONFIG",
    create: (url: string, fetch: typeof globalThis.fetch, apiKey?: string) =>
      new RingRpc(url, { fetch, ...(apiKey === undefined ? {} : { apiKey }) }),
  },
  {
    name: "ZolanaApi",
    code: "API_INVALID_CONFIG",
    create: (url: string, fetch: typeof globalThis.fetch, apiKey?: string) =>
      new ZolanaApi({ url, fetch, ...(apiKey === undefined ? {} : { apiKey }) }),
  },
];

describe.each(clients)("$name gateway configuration", ({ create, code }) => {
  it.each([
    { query: "", key: "" },
    { query: "", key: "key\nvalue" },
    { query: "", key: "k".repeat(4097) },
    { query: "?api-key=one", key: "two" },
    { query: "?api-key=one&api%2Dkey=two", key: undefined },
    { query: "?api-key=", key: undefined },
    { query: "?api-key=key%00value", key: undefined },
  ])("rejects invalid or ambiguous key sources ($query)", ({ query, key }) => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create(`https://gateway.example${query}`, fetch, key)).toThrow(
      expect.objectContaining({ code, details: { field: "apiKey" } }),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["\uD800", "\uDC00", "secret\uD800key", "\uDC00\uD800"])(
    "rejects an unpaired surrogate before any request (%j)",
    (key) => {
      const fetch = vi.fn<typeof globalThis.fetch>();
      expect(() => create("https://gateway.example", fetch, key)).toThrow(
        expect.objectContaining({ code, details: { field: "apiKey" } }),
      );
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("accepts well-formed Unicode without rejecting surrogate pairs", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create("https://gateway.example", fetch, "key-🔑-é")).not.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe.each([
  ...clients,
  {
    name: "ProverClient",
    code: "CLIENT_INVALID_CONFIG",
    create: (url: string, fetch: typeof globalThis.fetch) =>
      new ProverClient({ url, fetch, tee: false }),
  },
])("$name gateway URL", ({ create, code }) => {
  it.each(["%ED%A0%80", "%FF", "%", "%C0%AF", "", "key%00value"])(
    "rejects a malformed encoded URL key before any request (%s)",
    (key) => {
      const fetch = vi.fn<typeof globalThis.fetch>();
      expect(() => create(`https://gateway.example?api-key=${key}`, fetch)).toThrow(
        expect.objectContaining({ code, details: { field: "apiKey" } }),
      );
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("refuses duplicate keys including encoded parameter names", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create("https://gateway.example?api-key=one&api%2Dkey=two", fetch)).toThrow(
      expect.objectContaining({ code, details: { field: "apiKey" } }),
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});

it("rejects malformed prover credentials through the public client before a request", () => {
  const fetch = vi.fn<typeof globalThis.fetch>();
  expect(
    () =>
      new ZolanaClient({
        solanaRpcUrl: "https://rpc.example",
        indexerUrl: "https://indexer.example",
        proverUrl: "https://prover.example?api-key=%FF",
        proverTee: false,
        fetch,
      }),
  ).toThrow(
    expect.objectContaining({ code: "CLIENT_INVALID_CONFIG", details: { field: "proverUrl" } }),
  );
  expect(fetch).not.toHaveBeenCalled();
});
