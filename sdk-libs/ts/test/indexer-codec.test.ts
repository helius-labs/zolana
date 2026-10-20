import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  encodeRingsByTagsRequest,
  decodeRingMemberRecord,
  decodeRingMemberRecords,
  decodeRingMemberRegistryRoot,
  decodeUserRecordsResponse,
  encodeRingMemberProofRequest,
  encodeRingMemberRecordsRequest,
  encodeUserRecordsRequest,
} from "../src/indexer/codec.js";
import { MAX_USER_RECORD_OWNERS } from "../src/interface/indexer-limits.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { hash } from "../src/indexer/scalars.js";
import { ZolanaApi } from "../src/api/index.js";
import { ZolanaIndexer } from "../src/client/indexer.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import type { Bytes32 } from "../src/interface/types.js";

// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("ring key registry wire", () => {
  it("bounds the key registry cursor at twenty bits", () => {
    expect(
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: 1n << 20n,
      }),
    ).toMatchObject({ expectedNextIndex: 2 ** 20 });
    expect(() =>
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: (1n << 20n) + 1n,
      }),
    ).toThrow();
  });
});

describe("key registry wire", () => {
  const proof = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    rootIndex: 0,
    nextIndex: 1,
    appendPath: Array.from({ length: 20 }, () => TAG),
  };
  const entry = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    rootIndex: 0,
    nextIndex: 2,
    present: true,
    index: 1,
    path: Array.from({ length: 20 }, () => TAG),
    low: null,
    record: {
      member: TAG,
      next: TAG,
      lists: 0,
      escrowKey: TAG,
      ephPk: Buffer.from(
        "040900000000000000000000000000000000000000000000000000000000000000",
        "hex",
      ).toString("base64"),
      ciphertext: Buffer.alloc(32, 7).toString("base64"),
    },
  };
  it("bounds the root cursor and authenticatable record shape", () => {
    expect(decodeRingMemberRegistryRoot(proof)).toMatchObject({ rootIndex: 0, nextIndex: 1n });
    for (const changed of [{ rootIndex: 32 }, { appendPath: [] }, { nextIndex: 0 }])
      expect(() => decodeRingMemberRegistryRoot({ ...proof, ...changed })).toThrow();
    expect(decodeRingMemberRecord(entry)).toMatchObject({ index: 1n, nextIndex: 2n });
    for (const changed of [
      { index: 0 },
      { index: 2 },
      { path: [] },
      { record: { ...entry.record, ephPk: 3 } },
      { present: false },
    ])
      expect(() => decodeRingMemberRecord({ ...entry, ...changed })).toThrow();
  });

  it("decodes contiguous member pages and rejects gaps", async () => {
    const request = {
      ringProgramId: RING,
      expectedRoot: TAG,
      expectedNextIndex: 2n,
      startIndex: 1n,
      limit: 100,
    };
    expect(encodeRingMemberRecordsRequest(request)).toMatchObject({
      startIndex: 1,
      limit: 100,
    });
    const page = {
      context: entry.context,
      root: TAG,
      rootIndex: 0,
      nextIndex: 2,
      records: [{ index: 1, record: { ...entry.record, ownerPubkey: RING }, path: entry.path }],
      nextLeafIndex: null,
    };
    expect(decodeRingMemberRecords(page).records).toHaveLength(1);
    const indexerFor = (result: unknown) =>
      new ZolanaIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async () => Response.json({ jsonrpc: "2.0", id: "test-account", result }),
        }),
      );
    const decodedPage = await indexerFor(page).getRingMemberRecords({
      ...request,
      expectedRoot: new Uint8Array(32) as Bytes32,
    });
    expect(decodedPage.records[0]?.record.ciphertext).toEqual(new Uint8Array(32).fill(7));
    expect(decodedPage.records[0]?.record.ownerPublicKey).toBe(RING);
    for (const changed of [
      { records: [] },
      { records: [{ ...page.records[0], index: 2 }] },
      { nextLeafIndex: 2 },
      {
        records: [
          { ...page.records[0], record: { ...page.records[0]!.record, ownerPubkey: "bad" } },
        ],
      },
    ])
      await expect(
        indexerFor({ ...page, ...changed }).getRingMemberRecords({
          ...request,
          expectedRoot: new Uint8Array(32) as Bytes32,
        }),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
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
      [-32070, "CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC"],
      [-32071, "CLIENT_MEMBER_REGISTRY_ROOT_CHANGED"],
      [-32072, "CLIENT_MEMBER_REGISTRY_MEMBER_UNREGISTERED"],
      [-32073, "CLIENT_MEMBER_REGISTRY_MEMBER_ALREADY_REGISTERED"],
    ] as const) {
      const indexer = indexerFor({ error: { code: rpcCode, message: "private diagnostics" } });
      await expect(indexer.getRingMemberRecord(request)).rejects.toMatchObject({ code });
      await expect(indexer.getRingMemberRegistryRoot(request)).rejects.toMatchObject({
        code,
      });
    }
    const decoded = await indexerFor({ result: entry }).getRingMemberRecord(request);
    expect(decoded.record!.ephemeralPublicKey!.toBytes()[0]).toBe(0x04);
    expect(decoded.record!.ciphertext).toEqual(new Uint8Array(32).fill(7));
    for (const changed of [
      { record: { ...entry.record, ciphertext: Buffer.alloc(31, 7).toString("base64") } },
      { record: { ...entry.record, ephPk: Buffer.alloc(33, 9).toString("base64") } },
      { nextIndex: 3 },
    ])
      await expect(
        indexerFor({ result: { ...entry, ...changed } }).getRingMemberRecord(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
  });
});

describe("user records wire", () => {
  const OTHER = treeAddress(7);
  // A compressed P-256 point, the same one the key registry entry carries.
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
      new ZolanaIndexer(
        new ZolanaApi({
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
