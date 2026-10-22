import { describe, expect, it, vi } from "vitest";
import { address } from "@solana/kit";
import { ZolanaApi } from "../src/api/index.js";
import { hash, limit } from "../src/indexer/scalars.js";
import { checkedCursor, compareCursors } from "../src/interface/cursor.js";
import { ringReadAttestation } from "../src/ring/rpc.js";

const signature = "1".repeat(64);
const cursor = `1:7:${signature}`;
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
  it("uses the Rust cursor vector, including the full u64 slot range", () => {
    expect(checkedCursor(cursor)).toBe(cursor);
    const maximum = `1:18446744073709551615:${signature}`;
    expect(checkedCursor(maximum)).toBe(maximum);
    expect(compareCursors(cursor, maximum)).toBeLessThan(0);
    for (const invalid of [
      `1:07:${signature}`,
      `2:7:${signature}`,
      `1:18446744073709551616:${signature}`,
      `${cursor}:extra`,
      "1:7:invalid",
      { slot: 7, signature },
    ]) {
      expect(() => checkedCursor(invalid)).toThrow("invalid pagination cursor");
    }
  });

  it("rejects malformed request cursors before sending a request", async () => {
    const { api, fetch } = apiFor(null);
    await expect(
      api.getShieldedTransactionsByTags({ tags: [tag], after: `1:07:${signature}` }),
    ).rejects.toMatchObject({ code: "API_INVALID_REQUEST" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("counts whole transactions and sends freshness independently from after", async () => {
    const { api, fetch } = apiFor({ context, items: [item], cursor, hasMore: true });
    const page = await api.getShieldedTransactionsByTags({
      tags: [tag],
      after: `1:6:${signature}`,
      limit: limit(1n),
      minContextSlot: 100n,
    });
    expect(page.items).toHaveLength(1);
    expect(page.items[0]?.events).toHaveLength(2);
    expect(page.hasMore).toBe(true);
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body)).params).toMatchObject({
      after: `1:6:${signature}`,
      limit: 1,
      minContextSlot: 100,
    });
  });

  it("keeps a terminal checkpoint on an empty page", async () => {
    const { api } = apiFor({ context, items: [], cursor, hasMore: false });
    const page = await api.getShieldedTransactionsByNullifiers({
      nullifiers: [tag],
      after: cursor,
      minContextSlot: 100n,
    });
    expect(page).toMatchObject({ items: [], cursor, hasMore: false });
  });

  it.each([
    { items: [item, item] },
    { items: [{ ...item, events: [{ ...event, slot: 8 }] }] },
    { items: [{ ...item, events: [event, event] }] },
    { cursor: null, hasMore: true },
    { cursor: `1:6:${signature}` },
    { context: { ...context, slot: 99 } },
    { next: cursor },
    { latest: cursor },
  ])("rejects inconsistent pages before returning a checkpoint: %j", async (change) => {
    const { api } = apiFor({ context, items: [item], cursor, hasMore: false, ...change });
    await expect(
      api.getShieldedTransactionsByTags({
        tags: [tag],
        after: `1:6:${signature}`,
        limit: limit(1n),
        minContextSlot: 100n,
      }),
    ).rejects.toMatchObject({ code: "API_INVALID_RESULT" });
  });

  it("binds the freshness gate in the Ring RPC signature", () => {
    const input = {
      ringProgramId: address("1".repeat(32)),
      timestamp: 1n,
      nonce: hashNonce(),
      after: cursor,
      limit: 1,
    };
    const first = ringReadAttestation({ ...input, minContextSlot: 100n });
    const second = ringReadAttestation({ ...input, minContextSlot: 101n });
    expect(first).not.toEqual(second);
    expect(new TextDecoder().decode(first)).toContain(`after: ${cursor}\nmin-context-slot: 100`);
  });
});

function hashNonce() {
  // A fixed-length nonce is constructed by the same checked primitive as production requests.
  return nonceBytes(new Uint8Array(32));
}
import { copyBytes } from "../src/interface/internal.js";
import type { Bytes32 } from "../src/interface/types.js";
function nonceBytes(value: Uint8Array): Bytes32 {
  return copyBytes(value, 32, "nonce") as Bytes32;
}
