import { describe, expect, it, vi } from "vitest";
import { address } from "@solana/kit";
import { ZolanaIndexer } from "../src/client/indexer.js";
import { atSlot, createIndexerPollConfig } from "../src/client/retry.js";
import { ZolanaApi } from "../src/api/index.js";
import { hash, limit } from "../src/indexer/scalars.js";
import {
  checkedPaginationToken,
  comparePaginationTokens,
} from "../src/interface/pagination-token.js";
import { copyBytes } from "../src/interface/internal.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  nextPageToken,
  requiredContextSlot,
  validateIndexedPage,
  validatePage,
} from "../src/interface/page.js";
import { ringReadAttestation } from "../src/ring/rpc.js";

const signature = "1".repeat(64);
const token = `1:7:${signature}`;
const tag = hash("1".repeat(32));
const context = { blockTime: 0, slot: 100 };
const event = {
  slot: 7,
  txSignature: signature,
  eventIndex: 0,
  outputSlots: [],
  messages: [],
  nullifiers: [],
  proofless: true,
};
const item = { slot: 7, signature, events: [event, { ...event, eventIndex: 1 }] };

function apiFor(result: unknown) {
  const fetch = vi.fn<typeof globalThis.fetch>(async () =>
    Response.json({ jsonrpc: "2.0", id: "test-account", result }),
  );
  return { api: new ZolanaApi({ url: "https://indexer.example", fetch }), fetch };
}

describe("transaction pagination", () => {
  it("uses the Rust token vector, including the full u64 slot range", () => {
    expect(checkedPaginationToken(token)).toBe(token);
    const maximum = `1:18446744073709551615:${signature}`;
    expect(checkedPaginationToken(maximum)).toBe(maximum);
    expect(comparePaginationTokens(token, maximum)).toBeLessThan(0);
    for (const invalid of [
      `1:07:${signature}`,
      `2:7:${signature}`,
      `1:18446744073709551616:${signature}`,
      `${token}:extra`,
      "1:7:invalid",
      { slot: 7, signature },
    ]) {
      expect(() => checkedPaginationToken(invalid)).toThrow("invalid pagination token");
    }
  });

  it("rejects malformed request tokens and filters before sending a request", async () => {
    const { api, fetch } = apiFor(null);
    await expect(
      api.getShieldedTransactionsByTags({ tags: [tag], paginationToken: `1:07:${signature}` }),
    ).rejects.toMatchObject({ code: "API_INVALID_REQUEST" });
    await expect(
      api.getShieldedTransactionsByTags({
        tags: [tag],
        filters: { slot: { gt: 1n << 60n } },
      }),
    ).rejects.toMatchObject({ code: "API_INVALID_REQUEST" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("counts whole transactions and sends the token, filters and freshness independently", async () => {
    const { api, fetch } = apiFor({ context, items: [item], paginationToken: token });
    const page = await api.getShieldedTransactionsByTags({
      tags: [tag],
      paginationToken: `1:6:${signature}`,
      limit: limit(1n),
      filters: { slot: { gt: 5n, lte: 90n } },
      minContextSlot: 100n,
    });
    expect(page.items).toHaveLength(1);
    expect(page.items[0]?.events).toHaveLength(2);
    expect(page.paginationToken).toBe(token);
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body)).params).toMatchObject({
      paginationToken: `1:6:${signature}`,
      limit: 1,
      filters: { slot: { gt: 5, lte: 90 } },
      minContextSlot: 100,
    });
  });

  it("ends the history with a null token, including on an empty page", async () => {
    const { api } = apiFor({ context, items: [], paginationToken: null });
    const page = await api.getShieldedTransactionsByNullifiers({
      nullifiers: [tag],
      paginationToken: token,
      filters: { slot: { gt: 50n } },
    });
    expect(page).toMatchObject({ context: { slot: 100n }, items: [], paginationToken: null });
  });

  it.each([
    { items: [item, item] },
    { items: [{ ...item, events: [{ ...event, slot: 8 }] }] },
    { items: [{ ...item, events: [event, event] }] },
    { items: [], paginationToken: token },
    { paginationToken: `1:8:${signature}` },
    { paginationToken: `1:6:${signature}` },
    { items: [{ ...item, slot: 4, events: [{ ...event, slot: 4 }] }] },
    { context: { ...context, slot: 99 } },
    { cursor: token },
    { hasMore: false },
  ])("rejects a page inconsistent with its request: %j", async (change) => {
    const { api } = apiFor({ context, items: [item], paginationToken: null, ...change });
    await expect(
      api.getShieldedTransactionsByTags({
        tags: [tag],
        paginationToken: `1:2:${signature}`,
        limit: limit(1n),
        filters: { slot: { gte: 5n } },
        minContextSlot: 100n,
      }),
    ).rejects.toMatchObject({ code: "API_INVALID_RESULT" });
  });

  it("rejects a snapshot behind the request token or the slot filter", () => {
    const page = { context: { slot: 9n }, items: [], paginationToken: null };
    expect(requiredContextSlot({ paginationToken: `1:12:${signature}` })).toBe(12n);
    expect(requiredContextSlot({ filters: { slot: { gt: 10n } } })).toBe(10n);
    expect(requiredContextSlot({ filters: { slot: { gte: 10n } } })).toBe(9n);
    expect(requiredContextSlot({ filters: { slot: { gte: 0n } } })).toBeUndefined();
    expect(() => validatePage(page, { filters: { slot: { gte: 10n } } })).not.toThrow();
    expect(() => validatePage(page, { filters: { slot: { gt: 10n } } })).toThrow();
    expect(() => validatePage(page, { paginationToken: `1:10:${signature}` })).toThrow();
  });

  it("lets a ring page carry a token past its last item, but not an indexer page", () => {
    const page = {
      context: { slot: 9n },
      items: [{ slot: 3n, signature }],
      paginationToken: `1:5:${signature}`,
    };
    expect(() => validatePage(page)).not.toThrow();
    expect(() => validatePage({ ...page, items: [] })).not.toThrow();
    expect(() => validateIndexedPage(page)).toThrow();
    expect(() => validateIndexedPage({ ...page, items: [] })).toThrow();
    expect(() =>
      validateIndexedPage({ ...page, paginationToken: `1:3:${signature}` }),
    ).not.toThrow();
    expect(() => validatePage({ ...page, paginationToken: `1:2:${signature}` })).toThrow();
  });

  it("stops at a null token and rejects repeated, backward, and malformed tokens", () => {
    for (const next of [token, `1:6:${signature}`, "invalid", undefined]) {
      expect(() =>
        nextPageToken({ paginationToken: next } as { paginationToken: string | null }, token),
      ).toThrow();
    }
    const next = `1:8:${signature}`;
    expect(nextPageToken({ paginationToken: next }, token)).toBe(next);
    expect(nextPageToken({ paginationToken: null }, token)).toBeNull();
  });

  it.each([false, true])(
    "retries a minimum-slot error only with an explicit wait: %s",
    async (wait) => {
      let calls = 0;
      const fetch = vi.fn<typeof globalThis.fetch>(async () => {
        calls++;
        return Response.json({
          jsonrpc: "2.0",
          id: "test-account",
          ...(calls === 1
            ? {
                error: {
                  code: -32016,
                  message: "Minimum context slot has not been reached",
                  data: { contextSlot: 99 },
                },
              }
            : { result: { context, items: [], paginationToken: null } }),
        });
      });
      const indexer = new ZolanaIndexer(new ZolanaApi({ url: "https://indexer.example", fetch }));
      const read = indexer.getShieldedTransactionsByTags(
        { tags: [copyBytes(new Uint8Array(32), 32, "tag") as Bytes32], minContextSlot: 100n },
        wait ? atSlot(100n, createIndexerPollConfig(1, 0n, 0n)) : undefined,
      );
      if (wait) {
        await expect(read).resolves.toMatchObject({
          context: { slot: 100n },
          paginationToken: null,
        });
      } else {
        await expect(read).rejects.toMatchObject({ code: "CLIENT_INDEXER" });
      }
      expect(fetch).toHaveBeenCalledTimes(wait ? 2 : 1);
    },
  );

  it("rejects malformed client filters before sending a request", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const indexer = new ZolanaIndexer(new ZolanaApi({ url: "https://indexer.example", fetch }));
    const tags = [copyBytes(new Uint8Array(32), 32, "tag") as Bytes32];
    for (const filters of [
      { slot: { eq: 1n } },
      { blockTime: { gt: 1n } },
      { slot: { gt: 1 } },
      { slot: { lt: -1n } },
    ]) {
      expect(() => indexer.getShieldedTransactionsByTags({ tags, filters } as never)).toThrowError(
        expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }),
      );
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("binds the freshness gate and the slot filter in the Ring RPC signature", () => {
    const input = {
      ringProgramId: address("1".repeat(32)),
      timestamp: 1n,
      nonce: copyBytes(new Uint8Array(32), 32, "nonce") as Bytes32,
      paginationToken: token,
      limit: 1,
    };
    const first = ringReadAttestation({ ...input, minContextSlot: 100n });
    const second = ringReadAttestation({ ...input, minContextSlot: 101n });
    const filtered = ringReadAttestation({ ...input, filters: { slot: { gt: 100n } } });
    expect(first).not.toEqual(second);
    expect(filtered).not.toEqual(ringReadAttestation(input));
    expect(new TextDecoder().decode(first)).toContain(
      `pagination-token: ${token}\nslot-gt: \nslot-gte: \nslot-lt: \nslot-lte: \nmin-context-slot: 100`,
    );
  });
});
