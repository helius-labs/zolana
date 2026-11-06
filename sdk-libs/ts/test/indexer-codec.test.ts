import { transactionItems, outputItems } from "./helpers/pages.js";
import { address, getBase58Decoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeEncryptedUtxosResponse,
  decodeShieldedTransactionsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  encodeRingsByNullifiersRequest,
  encodeRingsByTagsRequest,
  decodeMerkleProofsResponse,
  decodeUserRecordsResponse,
  encodeUserRecordsRequest,
  indexedTransaction,
  knownSchemaPath,
} from "../src/indexer/codec.js";
import { wireDecoder } from "../src/interface/decode.js";
import { MAX_USER_RECORD_OWNERS } from "../src/interface/indexer-limits.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { hash } from "../src/indexer/scalars.js";
import { SprApi } from "../src/api/index.js";
import { SprIndexer } from "../src/client/indexer.js";
import type { Signature } from "../src/interface/types.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";

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
    const decoded = {
      context: { slot: 77n, blockTime: 2n },
      records: [
        { owner: RING, nullifierPubkey: TAG, viewingPubkey: X25519, mergeEncryption: 1 },
        null,
      ],
    };
    expect(decodeUserRecordsResponse(page)).toEqual(decoded);
    // A field this release does not know is ignored, as `spr-indexer-api` does.
    expect(
      decodeUserRecordsResponse({
        ...page,
        context: { ...page.context, extra: 1 },
        records: [{ ...record, bump: 1, ownerP256: null }, null],
        extra: true,
      }),
    ).toEqual(decoded);
    for (const changed of [
      { records: [{ ...record, mergeEncryption: true }] },
      { records: [{ ...record, mergeEncryption: 2 }] },
      { records: [{ ...record, mergeEncryption: -1 }] },
      { records: [{ ...record, mergeEncryption: "1" }] },
      { records: [{ ...record, nullifierPubkey: P256 }] },
      { records: [{ owner: RING }] },
      { records: [undefined] },
      { records: null },
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
    expect(lookup.records[0]?.viewingPublicKey).toEqual(
      new Uint8Array(Buffer.from(X25519, "base64")),
    );
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
    // The registry stores any 33 bytes, so a key off the curve is one owner's
    // own registration: it comes back as registered and the batch still answers.
    const offCurve = new Uint8Array([4, ...new Uint8Array(32).fill(0xff)]);
    const mixed = await indexerFor({
      ...page,
      records: [
        record,
        { ...record, owner: OTHER, viewingPubkey: Buffer.from(offCurve).toString("base64") },
      ],
    }).getUserRecords([RING, OTHER]);
    expect(mixed.records[0]?.viewingPublicKey).toEqual(lookup.records[0]?.viewingPublicKey);
    expect(mixed.records[1]?.viewingPublicKey).toEqual(offCurve);
    expect(() => X25519PublicKey.fromBytes(offCurve)).toThrow();
    // A key of any other length is not a registry record.
    await expect(
      indexerFor({
        ...page,
        records: [{ ...record, viewingPubkey: Buffer.alloc(32, 9).toString("base64") }, null],
      }).getUserRecords([RING, OTHER]),
    ).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: { path: "$.records[0].viewingPubkey" },
    });

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
    { paginationToken: undefined },
    { paginationToken: `1:${4}:${signature}` },
    { paginationToken: "invalid" },
  ])("rejects a page with a missing or inconsistent token: %j", (change) => {
    expect(() => decodeShieldedTransactionsResponse({ ...page, ...change })).toThrow();
  });
});

describe("shielded transactions by signature", () => {
  const base58 = getBase58Decoder();
  const REQUESTED = base58.decode(new Uint8Array(64).fill(7)) as Signature;
  const OTHER = base58.decode(new Uint8Array(64).fill(8));
  const event = (eventIndex: number, change: Record<string, unknown> = {}) => ({
    eventIndex,
    transaction: {
      slot: 5,
      txSignature: REQUESTED,
      eventIndex,
      outputSlots: [],
      messages: [],
      nullifiers: [],
      proofless: false,
      ...change,
    },
  });
  const read = (transactions: readonly unknown[]) =>
    new SprApi({
      url: "https://indexer.example",
      fetch: async () =>
        Response.json({
          jsonrpc: "2.0",
          id: "test-account",
          result: { context: { blockTime: 0, slot: 5 }, transactions },
        }),
    }).getShieldedTransactionsBySignature({ txSignature: REQUESTED });

  it("returns the requested transaction's events in event order", async () => {
    const response = await read([event(0), event(2)]);
    expect(response.transactions.map(({ eventIndex }) => eventIndex)).toEqual([0, 2]);
    expect((await read([])).transactions).toEqual([]);
  });

  it.each([
    ["another transaction's events", [event(0, { txSignature: OTHER })]],
    ["an event index the event does not carry", [event(0, { eventIndex: 1 })]],
    ["an event without its index", [event(0, { eventIndex: null })]],
    ["a repeated event", [event(1), event(1)]],
    ["events out of order", [event(2), event(1)]],
    ["events in different slots", [event(0), event(1, { slot: 4 })]],
    ["a slot past the answer's context", [event(0, { slot: 6 })]],
  ])("refuses %s", async (_name, transactions) => {
    await expect(read(transactions)).rejects.toMatchObject({ code: "API_INVALID_RESULT" });
  });
});

describe("shielded transaction event index", () => {
  const transaction = {
    slot: 1,
    txSignature: "1".repeat(64),
    outputSlots: [],
    messages: [],
    nullifiers: [],
    proofless: false,
  };

  it("reads a null event index as absent, as serde does", () => {
    expect(indexedTransaction({ ...transaction, eventIndex: null }, "$")).not.toHaveProperty(
      "eventIndex",
    );
    expect(indexedTransaction({ ...transaction, eventIndex: 3 }, "$").eventIndex).toBe(3);
    expect(() => indexedTransaction({ ...transaction, eventIndex: -1 }, "$")).toThrowError(
      expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
    );
  });
});

describe("hash scalars", () => {
  // `ParseHashError::WrongSize` for a string that decodes to other than 32
  // bytes, the empty one included; `Invalid` for one outside the alphabet.
  it("report the error Rust's ParseHashError names", () => {
    const code = (value: string) => {
      try {
        hash(value);
      } catch (error) {
        return (error as { code?: unknown }).code;
      }
      return undefined;
    };
    expect(code("")).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    expect(code("1")).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    expect(code("1".repeat(45))).toBe("INDEXER_SCHEMA_HASH_WRONG_SIZE");
    expect(code("0".repeat(32))).toBe("INDEXER_SCHEMA_INVALID_HASH");
    expect(code(TAG)).toBeUndefined();
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

  it("derives the tree account from treeId and does not read the deprecated tree field", () => {
    const pageWith = (outputContext: Record<string, unknown>) => ({
      context,
      data: outputItems([{ ...match, outputSlot: { ...output, outputContext } }]),
      paginationToken: null,
    });
    const decodedTree = (outputContext: Record<string, unknown>) =>
      decodeEncryptedUtxosResponse(pageWith(outputContext)).data[0]?.outputs[0]?.outputSlot
        .outputContext.tree;
    const { tree: _tree, ...withoutTree } = output.outputContext;
    expect(decodedTree(withoutTree)).toBe(treeAddress(7));
    expect(decodedTree({ ...withoutTree, tree: treeAddress(8) })).toBe(treeAddress(7));
    expect(decodedTree({ ...withoutTree, tree: "not-an-address" })).toBe(treeAddress(7));

    const page = pageWith({ hash: TAG, tree: treeAddress(7), leafIndex: 3 });
    const before = structuredClone(page);
    expect(() => decodeEncryptedUtxosResponse(page)).toThrowError(
      expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
    );
    expect(page).toEqual(before);
  });
});

describe("wire integers", () => {
  const proof = {
    leaf: TAG,
    merkleContext: { treeType: 0, tree: RING },
    path: [TAG],
    leafIndex: 0,
    root: TAG,
    rootSeq: 0,
    rootIndex: 0,
  };
  const decode = (change: Record<string, unknown>, at: Record<string, unknown> = {}) =>
    decodeMerkleProofsResponse({
      context: { blockTime: 0, slot: 1, ...at },
      proofs: [{ ...proof, ...change }],
    });
  const U64_MAX = "18446744073709551615";

  // The transport hands a literal past 2^53 over as its exact digits, and every
  // integer field reads it at the full range of its type.
  it("reads the full range of every u64 and i64 field, slots and indexes alike", () => {
    const response = decode(
      { leafIndex: U64_MAX, rootSeq: "9007199254740993" },
      { slot: U64_MAX, blockTime: "-9223372036854775808" },
    );
    expect(response.context).toEqual({
      slot: 18_446_744_073_709_551_615n,
      blockTime: -(1n << 63n),
    });
    expect(response.proofs[0]?.leafIndex).toBe(18_446_744_073_709_551_615n);
    expect(response.proofs[0]?.rootSeq).toBe(9_007_199_254_740_993n);
  });

  it.each([
    ["a quoted safe value", { leafIndex: "7" }],
    ["a leading zero", { leafIndex: "007" }],
    ["a sign on zero", { rootSeq: "-0" }],
    ["an exponent", { rootSeq: "1e20" }],
    ["a number that lost precision", { rootSeq: 2 ** 60 }],
    ["a fraction", { leafIndex: 1.5 }],
    ["a value past u64", { leafIndex: "18446744073709551616" }],
    ["a negative u64", { rootSeq: "-9007199254740993" }],
    ["a u16 past its range", { rootIndex: "9007199254740993" }],
  ])("refuses %s", (_name, change) => {
    expect(() => decode(change)).toThrowError(
      expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
    );
  });

  it("refuses the same spellings for a context slot", () => {
    for (const slot of ["1", "01", 2 ** 60, -1])
      expect(() => decode({}, { slot })).toThrowError(
        expect.objectContaining({ code: "INDEXER_SCHEMA_INVALID_INTEGER" }),
      );
  });
});

describe("the wire decoder's integers", () => {
  it("follow the same rule as the indexer codec", () => {
    const { integer, signedInteger } = wireDecoder(() => new Error("invalid integer"));
    expect(integer(7, "x")).toBe(7n);
    expect(integer("18446744073709551615", "x")).toBe(18_446_744_073_709_551_615n);
    expect(signedInteger(-7, "x")).toBe(-7n);
    for (const value of ["007", "7", "-0", 2 ** 60, 1.5, -1])
      expect(() => integer(value, "x")).toThrow("invalid integer");
  });
});

describe("schema error paths", () => {
  it("keeps a path that names only contract fields and indexes", () => {
    for (const path of [
      "$",
      "$.data[0].events[1].ringProgramId",
      "$.data[0].outputs[0].outputSlot.outputContext.treeId",
      "$.outputTreeId",
      "$.transactions[2].transaction.messages[0].payload",
      "$.filters.slot.gt",
    ])
      expect(knownSchemaPath(path)).toBe(path);
  });

  it("drops a path that names a key the caller or the indexer chose", () => {
    for (const path of [
      "$.filters.slot.eq",
      "$.data[0].secret",
      "$.matches",
      "$['owner']",
      `$${".slot".repeat(60)}`,
    ])
      expect(knownSchemaPath(path)).toBeUndefined();
  });
});
