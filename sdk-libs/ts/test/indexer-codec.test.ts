import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  encodeRingsByTagsRequest,
  decodeRingKeyRegistryEntry,
  decodeRingKeyRegistryRegisterProof,
  decodeRingSpendRecordResponse,
  encodeRingMemberProofRequest,
} from "../src/indexer/codec.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { hash } from "../src/indexer/scalars.js";
import { ZolanaApi } from "../src/api/index.js";
import { ZolanaIndexer } from "../src/client/indexer.js";
import type { Bytes32 } from "../src/interface/types.js";

// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("ring spend record wire", () => {
  const output = {
    viewTag: TAG,
    outputContext: { hash: TAG, tree: treeAddress(7), treeId: 7, leafIndex: 3 },
    payload: "",
  };
  const transaction = {
    slot: 1,
    txSignature: "1".repeat(64),
    outputSlots: [output],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
  const found = {
    context: { slot: 1, blockTime: 2 },
    record: { transaction, outputIndex: 0 },
  };

  it("accepts an unregistered member and requires the record output to exist", () => {
    expect(decodeRingSpendRecordResponse({ ...found, record: null })).toEqual({
      context: { slot: 1n, blockTime: 2n },
      record: null,
    });
    expect(decodeRingSpendRecordResponse(found).record?.outputIndex).toBe(0);
    for (const changed of [
      { record: { transaction, outputIndex: 1 } },
      { record: { transaction } },
      { record: undefined },
      { extra: true },
    ])
      expect(() => decodeRingSpendRecordResponse({ ...found, ...changed })).toThrow();
  });

  it("sends only the ring and member and converts the record transaction", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    const requests: unknown[] = [];
    const indexerFor = (result: unknown) =>
      new ZolanaIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async (_url, init) => {
            requests.push(JSON.parse(String(init?.body)).params);
            return Response.json({ jsonrpc: "2.0", id: "test-account", result });
          },
        }),
      );
    const request = { ringProgramId: RING, member: zero };
    await expect(
      indexerFor({ ...found, record: null }).getRingSpendRecord(request),
    ).resolves.toMatchObject({ record: null });
    const lookup = await indexerFor(found).getRingSpendRecord(request);
    expect(lookup.record?.outputIndex).toBe(0);
    expect(lookup.record?.transaction.outputSlots[0]?.outputContext.tree).toBe(treeAddress(7));
    expect(requests).toEqual([
      { ringProgramId: RING, member: TAG },
      { ringProgramId: RING, member: TAG },
    ]);
  });

  it("bounds the key registry cursor at forty bits", () => {
    expect(
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: 1n << 40n,
      }),
    ).toMatchObject({ expectedNextIndex: 2 ** 40 });
    expect(() =>
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: (1n << 40n) + 1n,
      }),
    ).toThrow();
  });
});

describe("key registry wire", () => {
  const proof = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    member: TAG,
    nextIndex: 1,
    lowMember: TAG,
    lowNext: TAG,
    lowKeyHash: TAG,
    lowIndex: 0,
    lowProof: Array.from({ length: 40 }, () => TAG),
    newProof: Array.from({ length: 40 }, () => TAG),
  };
  const entry = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    member: TAG,
    nextIndex: 2,
    next: TAG,
    index: 1,
    ephPk: Buffer.from(
      "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5",
      "hex",
    ).toString("base64"),
    ciphertext: Buffer.alloc(32, 7).toString("base64"),
    proof: Array.from({ length: 40 }, () => TAG),
  };

  it("names the predecessor key hash and keeps the entry inside the cursor", () => {
    expect(decodeRingKeyRegistryRegisterProof(proof)).toMatchObject({ lowIndex: 0n });
    expect(() => decodeRingKeyRegistryRegisterProof({ ...proof, lowKey: TAG })).toThrow();
    expect(decodeRingKeyRegistryEntry(entry)).toMatchObject({ index: 1n, nextIndex: 2n });
    for (const changed of [{ index: 0 }, { index: 2 }, { proof: [] }, { ephPk: 3 }])
      expect(() => decodeRingKeyRegistryEntry({ ...entry, ...changed })).toThrow();
  });

  it("distinguishes every typed registry RPC failure and rejects a malformed entry", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    const request = {
      ringProgramId: RING,
      member: zero,
      expectedRoot: zero,
      expectedNextIndex: 2n,
    };
    const indexerFor = (body: Readonly<Record<string, unknown>>) =>
      new ZolanaIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async () => Response.json({ jsonrpc: "2.0", id: "test-account", ...body }),
        }),
      );
    for (const [rpcCode, code] of [
      [-32074, "CLIENT_KEY_REGISTRY_OUT_OF_SYNC"],
      [-32075, "CLIENT_KEY_REGISTRY_ROOT_CHANGED"],
      [-32076, "CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED"],
      [-32077, "CLIENT_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED"],
      [-32078, "CLIENT_SPEND_RECORD_OUT_OF_SYNC"],
    ] as const) {
      const indexer = indexerFor({ error: { code: rpcCode, message: "private diagnostics" } });
      await expect(indexer.getRingKeyRegistryEntry(request)).rejects.toMatchObject({ code });
      await expect(indexer.getRingKeyRegistryRegisterProof(request)).rejects.toMatchObject({
        code,
      });
    }
    const decoded = await indexerFor({ result: entry }).getRingKeyRegistryEntry(request);
    expect(decoded.ephemeralPublicKey.toBytes()[0]).toBe(0x02);
    expect(decoded.ciphertext).toEqual(new Uint8Array(32).fill(7));
    for (const changed of [
      { ciphertext: Buffer.alloc(31, 7).toString("base64") },
      { ephPk: Buffer.alloc(33, 9).toString("base64") },
      { nextIndex: 3 },
    ])
      await expect(
        indexerFor({ result: { ...entry, ...changed } }).getRingKeyRegistryEntry(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
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
