import { transactionItems, outputItems } from "./helpers/pages.js";
import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  encodeRingsByNullifiersRequest,
  encodeRingsByTagsRequest,
  decodeUserRecordsResponse,
  encodeUserRecordsRequest,
} from "../src/indexer/codec.js";
import { MAX_USER_RECORD_OWNERS } from "../src/interface/indexer-limits.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { hash } from "../src/indexer/scalars.js";
import { SprApi } from "../src/api/index.js";
import { SprIndexer } from "../src/client/indexer.js";
import { X25519Keypair } from "../src/keypair/x25519.js";

// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("user records wire", () => {
  const OTHER = treeAddress(7);
  // A compressed P-256 point.
  const P256 = Buffer.from(
    "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5",
    "hex",
  ).toString("base64");
  const X25519 = Buffer.from(
    X25519Keypair.fromBytes(new Uint8Array(32).fill(7)).publicKey().toBytes(),
  ).toString("base64");
  const record = {
    owner: RING,
    nullifierPubkey: TAG,
    viewingPubkey: X25519,
    mergeEncryption: 1,
  };
  const page = { context: { slot: 77, blockTime: 2 }, records: [record, null] };

  it("reads an unregistered owner as null and refuses a record it cannot fully decode", () => {
    expect(decodeUserRecordsResponse(page)).toEqual({
      context: { slot: 77n, blockTime: 2n },
      records: [
        { owner: RING, nullifierPubkey: TAG, viewingPubkey: X25519, mergeEncryption: 1 },
        null,
      ],
    });
    for (const changed of [
      { records: [{ ...record, bump: 1 }] },
      { records: [{ ...record, ownerP256: null }] },
      { records: [{ ...record, mergeEncryption: true }] },
      { records: [{ ...record, mergeEncryption: 2 }] },
      { records: [{ ...record, mergeEncryption: -1 }] },
      { records: [{ ...record, mergingEnabled: true }] },
      { records: [{ ...record, nullifierPubkey: P256 }] },
      { records: [{ owner: RING }] },
      { records: [undefined] },
      { records: null },
      { extra: true },
    ])
      expect(() => decodeUserRecordsResponse({ ...page, ...changed })).toThrow();
  });

  it("names between one and one hundred canonical owners", () => {
    const owners = (count: number) => Array.from({ length: count }, () => RING);
    expect(encodeUserRecordsRequest({ owners: [RING, OTHER] })).toEqual({ owners: [RING, OTHER] });
    expect(encodeUserRecordsRequest({ owners: owners(MAX_USER_RECORD_OWNERS) })).toMatchObject({
      owners: expect.any(Array),
    });
    expect(() => encodeUserRecordsRequest({ owners: [] })).toThrow();
    expect(() =>
      encodeUserRecordsRequest({ owners: owners(MAX_USER_RECORD_OWNERS + 1) }),
    ).toThrow();
    expect(() =>
      encodeUserRecordsRequest({ owners: ["not-an-address" as ReturnType<typeof address>] }),
    ).toThrow();
  });

  it("keeps request order through the client and correlates every record with its owner", async () => {
    const requests: unknown[] = [];
    const indexerFor = (result: unknown) =>
      new SprIndexer(
        new SprApi({
          url: "https://indexer.example",
          fetch: async (_url, init) => {
            requests.push(JSON.parse(String(init?.body)).params);
            return Response.json({ jsonrpc: "2.0", id: "test-account", result });
          },
        }),
      );

    const lookup = await indexerFor(page).getUserRecords([RING, OTHER]);
    expect(requests).toEqual([{ owners: [RING, OTHER] }]);
    expect(lookup.context).toEqual({ slot: 77n, blockTime: 2n });
    expect(lookup.records[0]).toMatchObject({ owner: RING, mergeEncryption: 1 });
    expect(lookup.records[0]?.nullifierPublicKey).toEqual(new Uint8Array(32));
    expect(lookup.records[0]?.viewingPublicKey.toBytes()[0]).toBe(0x04);
    expect(lookup.records[1]).toBeNull();

    // The second record answers for an owner that was not asked second.
    await expect(indexerFor(page).getUserRecords([OTHER, RING])).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { path: "$.records[0].owner" },
    });
    // Fewer records than owners.
    await expect(indexerFor(page).getUserRecords([RING, OTHER, RING])).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { path: "$.records" },
    });
    // A viewing key that is not a point on the curve.
    await expect(
      indexerFor({
        ...page,
        records: [{ ...record, viewingPubkey: Buffer.alloc(33, 9).toString("base64") }, null],
      }).getUserRecords([RING, OTHER]),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });

    // The client boundary refuses an empty, oversized, or malformed owner list
    // before any request is sent, synchronously like every other input check.
    const sent = requests.length;
    const thrown = (run: () => unknown): unknown => {
      try {
        run();
      } catch (error) {
        return error;
      }
      throw new Error("expected the owner list to be refused");
    };
    expect(thrown(() => indexerFor(page).getUserRecords([]))).toMatchObject({
      code: "CLIENT_INVALID_LENGTH",
      details: { field: "owners", expected: 1, actual: 0 },
    });
    expect(
      thrown(() =>
        indexerFor(page).getUserRecords(
          Array.from({ length: MAX_USER_RECORD_OWNERS + 1 }, () => RING),
        ),
      ),
    ).toMatchObject({
      code: "CLIENT_INVALID_LENGTH",
      details: { field: "owners", expected: MAX_USER_RECORD_OWNERS },
    });
    expect(
      thrown(() =>
        indexerFor(page).getUserRecords(["not-an-address" as ReturnType<typeof address>]),
      ),
    ).toMatchObject({ code: "CLIENT_INVALID_FIELD", details: { field: "owners[0]" } });
    expect(requests).toHaveLength(sent);
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

  it("carries the pagination token and every slot bound, and drops an empty filter", () => {
    const paginationToken = `1:7:${"1".repeat(64)}`;
    expect(
      encodeRingsByTagsRequest({
        tags: [TAG],
        paginationToken,
        filters: { slot: { gt: 1n, gte: 2n, lt: 9n, lte: 8n } },
        minContextSlot: 7n,
      }),
    ).toEqual({
      tags: [TAG],
      paginationToken,
      filters: { slot: { gt: 1, gte: 2, lt: 9, lte: 8 } },
      minContextSlot: 7,
    });
    expect(encodeRingsByTagsRequest({ tags: [TAG], filters: { slot: {} } })).toEqual({
      tags: [TAG],
    });
    expect(encodeRingsByNullifiersRequest({ nullifiers: [TAG], filters: {} })).toEqual({
      nullifiers: [TAG],
    });
  });

  it.each([
    ["a non-canonical token", { paginationToken: "1:07:x" }],
    ["an unknown filter", { filters: { blockTime: { gt: 1n } } }],
    ["an unknown slot bound", { filters: { slot: { eq: 1n } } }],
    ["a negative slot bound", { filters: { slot: { gt: -1n } } }],
  ])("rejects %s", (_name, controls) => {
    expect(() => encodeRingsByTagsRequest({ tags: [TAG], ...controls } as never)).toThrow();
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
  const signature = "1".repeat(64);
  const event = {
    slot: 3,
    eventIndex: 0,
    txSignature: signature,
    outputSlots: [],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
  const page = { context: { blockTime: 1, slot: 3 }, data: [], paginationToken: null };

  it("decodes a null token as the end of the history and a token as the next page", () => {
    expect(decodeShieldedTransactionsResponse(page)).toEqual({
      context: { blockTime: 1n, slot: 3n },
      data: transactionItems([]),
      paginationToken: null,
    });
    expect(
      decodeShieldedTransactionsResponse({
        ...page,
        data: transactionItems([event]),
        paginationToken: `1:${3}:${signature}`,
      }).paginationToken,
    ).toBe(`1:${3}:${signature}`);
    expect(
      decodeEncryptedUtxosResponse({ ...page, data: outputItems([]) }).paginationToken,
    ).toBeNull();
  });

  it.each([
    { extra: 1 },
    { cursor: `1:${3}:${signature}` },
    { hasMore: false },
    { paginationToken: undefined },
    { paginationToken: `1:${4}:${signature}` },
    { paginationToken: "invalid" },
  ])("rejects a page with the old or an inconsistent token shape: %j", (change) => {
    expect(() => decodeShieldedTransactionsResponse({ ...page, ...change })).toThrow();
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
    eventIndex: 0,
    txSignature: match.txSignature,
    outputSlots: [output],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
  const context = { blockTime: 0, slot: 1 };

  it("decodes tree identity and append suggestions on every response shape", () => {
    const page = {
      context,
      data: outputItems([match]),
      outputTreeId: 9,
      paginationToken: null,
    };
    const before = structuredClone(page);
    const decoded = decodeEncryptedUtxosResponse(page);
    expect(decoded.outputTreeId).toBe(9);
    expect(decoded.data.flatMap((item) => item.outputs)[0]?.outputSlot.outputContext).toEqual({
      hash: TAG,
      tree: treeAddress(7),
      treeId: 7,
      leafIndex: 3n,
    });
    expect(page).toEqual(before);
    expect(
      decodeShieldedTransactionsResponse({
        context,
        data: transactionItems([transaction]),
        outputTreeId: 0,
        paginationToken: null,
      }).outputTreeId,
    ).toBe(0);
    expect(
      decodeShieldedTransactionsBySignatureResponse({
        context,
        transactions: [{ eventIndex: 0, transaction }],
        outputTreeId: 65535,
      }).outputTreeId,
    ).toBe(65535);
    expect(
      decodeEncryptedUtxosResponse({
        context,
        data: [],
        paginationToken: null,
        outputTreeId: null,
      }).outputTreeId,
    ).toBeUndefined();
  });

  it.each([-1, 65536, 1.5, "7"])("rejects malformed tree IDs: %s", (treeId) => {
    const page = {
      context,
      data: outputItems([
        { ...match, outputSlot: { ...output, outputContext: { ...output.outputContext, treeId } } },
      ]),
      paginationToken: null,
    };
    const before = structuredClone(page);
    expect(() => decodeEncryptedUtxosResponse(page)).toThrowError(
      expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
    );
    expect(page).toEqual(before);
    expect(() =>
      decodeEncryptedUtxosResponse({
        context,
        data: [],
        paginationToken: null,
        outputTreeId: treeId,
      }),
    ).toThrowError(expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }));
    expect(() =>
      decodeShieldedTransactionsResponse({
        context,
        data: [],
        paginationToken: null,
        outputTreeId: treeId,
      }),
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
      const page = {
        context,
        data: outputItems([{ ...match, outputSlot: { ...output, outputContext } }]),
        paginationToken: null,
      };
      const before = structuredClone(page);
      expect(() => decodeEncryptedUtxosResponse(page)).toThrowError(
        expect.objectContaining({ code }),
      );
      expect(page).toEqual(before);
    }
  });
});
