import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  encodeRingsByTagsRequest,
} from "../src/indexer/codec.js";
import { hash } from "../src/indexer/scalars.js";

// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("rings-by-tags request encoding", () => {
  // The encoder rebuilds the wire object field by field from an allowlist, so a
  // field that is typed but not listed is dropped in silence: the caller asks
  // for one ring and is served every ring.
  it("carries the ring filter onto the wire", () => {
    expect(encodeRingsByTagsRequest({ tags: [TAG], ringProgramId: RING })).toEqual({
      tags: [TAG],
      ringProgramId: RING,
    });
  });

  it("omits the ring filter when unset", () => {
    expect(encodeRingsByTagsRequest({ tags: [TAG] })).toEqual({ tags: [TAG] });
  });

  it("rejects a ring filter that is not an address", () => {
    expect(() =>
      encodeRingsByTagsRequest({
        tags: [TAG],
        ringProgramId: "not-an-address" as ReturnType<typeof address>,
      }),
    ).toThrow();
  });
});

describe("shielded transactions by tags response", () => {
  const page = { context: { blockTime: 1, slot: 2 }, transactions: [], nextCursor: null };

  it("accepts the scan position newer indexers report, and pages without it", () => {
    expect(decodeShieldedTransactionsResponse(page)).toEqual({
      context: { blockTime: 1n, slot: 2n },
      transactions: [],
    });
    expect(decodeShieldedTransactionsResponse({ ...page, scannedThrough: "AQID" })).toEqual({
      context: { blockTime: 1n, slot: 2n },
      transactions: [],
      scannedThrough: "AQID",
    });
    expect(() => decodeShieldedTransactionsResponse({ ...page, extra: 1 })).toThrow();
    expect(
      decodeEncryptedUtxosResponse({
        context: page.context,
        matches: [],
        nextCursor: null,
        scannedThrough: "AQID",
      }),
    ).toEqual({ context: { blockTime: 1n, slot: 2n }, matches: [], scannedThrough: "AQID" });
  });
});
