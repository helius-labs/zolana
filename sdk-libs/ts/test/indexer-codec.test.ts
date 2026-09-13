import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  encodeRingsByTagsRequest,
  decodeRingHeadRegisterProof,
  encodeRingHeadProofRequest,
} from "../src/indexer/codec.js";
import { hash } from "../src/indexer/scalars.js";
import { ZolanaApi } from "../src/api/index.js";
import { ZolanaIndexer } from "../src/client/indexer.js";
import type { Bytes32 } from "../src/interface/types.js";

// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("compressed head proof wire", () => {
  const response = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    member: TAG,
    nextIndex: 1,
    lowMember: TAG,
    lowNext: TAG,
    lowNullifier: TAG,
    lowIndex: 0,
    lowProof: Array.from({ length: 40 }, () => TAG),
    newProof: Array.from({ length: 40 }, () => TAG),
  };

  it("keeps the full forty-bit cursor exact and requires both complete paths", () => {
    expect(
      encodeRingHeadProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: 1n << 40n,
      }),
    ).toMatchObject({ expectedNextIndex: 2 ** 40 });
    expect(decodeRingHeadRegisterProof(response)).toMatchObject({ nextIndex: 1n, lowIndex: 0n });
    for (const changed of [
      { lowProof: response.lowProof.slice(1) },
      { newProof: [] },
      { lowIndex: 1 },
      { nextIndex: 2 ** 40 + 1 },
      { extra: true },
    ])
      expect(() => decodeRingHeadRegisterProof({ ...response, ...changed })).toThrow();
    expect(() =>
      encodeRingHeadProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: (1n << 40n) + 1n,
      }),
    ).toThrow();
  });

  it("distinguishes every typed head RPC failure and rejects a response for another root", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    const request = {
      ringProgramId: RING,
      member: zero,
      expectedRoot: zero,
      expectedNextIndex: 1n,
    };
    for (const [rpcCode, code] of [
      [-32070, "CLIENT_HEAD_MAP_OUT_OF_SYNC"],
      [-32071, "CLIENT_HEAD_ROOT_CHANGED"],
      [-32072, "CLIENT_HEAD_MEMBER_UNREGISTERED"],
      [-32073, "CLIENT_HEAD_MEMBER_ALREADY_REGISTERED"],
    ] as const) {
      const indexer = new ZolanaIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async () =>
            Response.json({
              jsonrpc: "2.0",
              id: "test-account",
              error: { code: rpcCode, message: "private server diagnostics" },
            }),
        }),
      );
      await expect(indexer.getRingHeadRegisterProof(request)).rejects.toMatchObject({ code });
    }
    const wrongRoot = new Uint8Array(32) as Bytes32;
    wrongRoot[31] = 1;
    const indexer = new ZolanaIndexer(
      new ZolanaApi({
        url: "https://indexer.example",
        fetch: async () =>
          Response.json({
            jsonrpc: "2.0",
            id: "test-account",
            result: { ...response, root: hash(wrongRoot) },
          }),
      }),
    );
    await expect(indexer.getRingHeadRegisterProof(request)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
    });
  });
});

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
