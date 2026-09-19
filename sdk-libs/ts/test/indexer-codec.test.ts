import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  encodeRingsByTagsRequest,
} from "../src/indexer/codec.js";
import { treeAddress } from "../src/interface/pda/index.js";
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

describe("Photon tree metadata", () => {
  const output = {
    viewTag: TAG,
    outputContext: { hash: TAG, tree: treeAddress(7), treeId: 7, leafIndex: 3 },
    payload: "",
  };
  const match = { slot: 1, txSignature: "1".repeat(64), outputSlot: output };
  const transaction = {
    slot: 1,
    txSignature: match.txSignature,
    outputSlots: [output],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
  const context = { blockTime: 0, slot: 1 };

  it("decodes tree identity and append suggestions on every response shape", () => {
    const page = { context, matches: [match], outputTreeId: 9 };
    const before = structuredClone(page);
    const decoded = decodeEncryptedUtxosResponse(page);
    expect(decoded.outputTreeId).toBe(9);
    expect(decoded.matches[0]?.outputSlot.outputContext).toEqual({
      hash: TAG,
      tree: treeAddress(7),
      treeId: 7,
      leafIndex: 3n,
    });
    expect(page).toEqual(before);
    expect(
      decodeShieldedTransactionsResponse({ context, transactions: [transaction], outputTreeId: 0 })
        .outputTreeId,
    ).toBe(0);
    expect(
      decodeShieldedTransactionsBySignatureResponse({
        context,
        transactions: [{ eventIndex: 0, transaction }],
        outputTreeId: 65535,
      }).outputTreeId,
    ).toBe(65535);
    expect(
      decodeEncryptedUtxosResponse({ context, matches: [], outputTreeId: null }).outputTreeId,
    ).toBeUndefined();
  });

  it.each([-1, 65536, 1.5, "7"])("rejects malformed tree IDs: %s", (treeId) => {
    const page = {
      context,
      matches: [
        { ...match, outputSlot: { ...output, outputContext: { ...output.outputContext, treeId } } },
      ],
    };
    const before = structuredClone(page);
    expect(() => decodeEncryptedUtxosResponse(page)).toThrowError(
      expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
    );
    expect(page).toEqual(before);
    expect(() =>
      decodeEncryptedUtxosResponse({ context, matches: [], outputTreeId: treeId }),
    ).toThrowError(expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }));
    expect(() =>
      decodeShieldedTransactionsResponse({ context, transactions: [], outputTreeId: treeId }),
    ).toThrowError(expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }));
    expect(() =>
      decodeShieldedTransactionsBySignatureResponse({
        context,
        transactions: [],
        outputTreeId: treeId,
      }),
    ).toThrowError(expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }));
  });

  it("rejects missing IDs and tree addresses that disagree with their IDs", () => {
    const missing = { hash: TAG, tree: treeAddress(7), leafIndex: 3 };
    for (const { outputContext, code } of [
      { outputContext: missing, code: "INDEXER_SCHEMA_INVALID_INTEGER" },
      { outputContext: { ...missing, treeId: 8 }, code: "INDEXER_SCHEMA_INVALID_TREE" },
    ]) {
      const page = { context, matches: [{ ...match, outputSlot: { ...output, outputContext } }] };
      const before = structuredClone(page);
      expect(() => decodeEncryptedUtxosResponse(page)).toThrowError(
        expect.objectContaining({ code }),
      );
      expect(page).toEqual(before);
    }
  });
});
