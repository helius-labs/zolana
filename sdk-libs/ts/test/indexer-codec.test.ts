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
  decodeUserRecordsResponse,
  encodeRingMemberProofRequest,
  encodeUserRecordsRequest,
} from "../src/indexer/codec.js";
import { MAX_USER_RECORD_OWNERS } from "../src/interface/indexer-limits.js";
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
      [-32070, "CLIENT_KEY_REGISTRY_OUT_OF_SYNC"],
      [-32071, "CLIENT_KEY_REGISTRY_ROOT_CHANGED"],
      [-32072, "CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED"],
      [-32073, "CLIENT_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED"],
      [-32074, "CLIENT_SPEND_RECORD_OUT_OF_SYNC"],
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

describe("user records wire", () => {
  const OTHER = treeAddress(7);
  // A compressed P-256 point, the same one the key registry entry carries.
  const P256 = Buffer.from(
    "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5",
    "hex",
  ).toString("base64");
  const record = {
    owner: RING,
    ownerP256: null,
    nullifierPubkey: TAG,
    viewingPubkey: P256,
    mergingEnabled: true,
  };
  const page = { context: { slot: 77, blockTime: 2 }, records: [record, null] };

  it("reads an unregistered owner as null and refuses a record it cannot fully decode", () => {
    expect(decodeUserRecordsResponse(page)).toEqual({
      context: { slot: 77n, blockTime: 2n },
      records: [
        { owner: RING, nullifierPubkey: TAG, viewingPubkey: P256, mergingEnabled: true },
        null,
      ],
    });
    expect(
      decodeUserRecordsResponse({ ...page, records: [{ ...record, ownerP256: P256 }] }).records[0],
    ).toMatchObject({ ownerP256: P256 });
    for (const changed of [
      { records: [{ ...record, bump: 1 }] },
      { records: [{ ...record, mergingEnabled: "yes" }] },
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
    expect(lookup.records[0]).toMatchObject({ owner: RING, mergingEnabled: true });
    expect(lookup.records[0]?.ownerP256).toBeUndefined();
    expect(lookup.records[0]?.nullifierPublicKey).toEqual(new Uint8Array(32));
    expect(lookup.records[0]?.viewingPublicKey.toBytes()[0]).toBe(0x02);
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
