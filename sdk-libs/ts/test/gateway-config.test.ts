import { describe, expect, it, vi } from "vitest";

import { ZolanaApi } from "../src/api/index.js";
import { RingRpc } from "../src/ring/rpc.js";

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

  it.each(["%ED%A0%80", "%FF", "%", "%C0%AF"])(
    "rejects a malformed encoded URL key before any request (%s)",
    (key) => {
      const fetch = vi.fn<typeof globalThis.fetch>();
      expect(() => create(`https://gateway.example?api-key=${key}`, fetch)).toThrow(
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
