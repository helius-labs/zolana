import { getAddressDecoder, type Address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import type {
  IndexedShieldedTransaction,
  OutputSlot,
} from "../src/transaction/instructions/transact.js";
import {
  LIST_IDS,
  ListId,
  RingListNamespace,
  decodeListEntry,
  decodeRule,
  decodeRuleTable,
  listSet,
  memberOfAsset,
  memberOfTag,
  readRingEntries,
  readRingEntry,
  referencedLists,
  type ListEntry,
  type Member,
} from "../src/ring/policy.js";
import { RingError } from "../src/ring/error.js";

import { matchesPage, syncReads, transactionsPage } from "./helpers/clients.js";

await initializePoseidon();

const hex = (text: string): Bytes32 => Uint8Array.from(Buffer.from(text, "hex")) as Bytes32;
const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (bytes: Uint8Array): Address => getAddressDecoder().decode(bytes);

/** Rust `Row`. */
function row(
  input: Readonly<{
    subject: number;
    mode: number;
    mask: number;
    alternative?: number;
    guardTag?: number;
    threshold?: bigint;
    reserved?: number;
  }>,
): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[0] = input.reserved ?? 0;
  bytes[19] = input.alternative ?? 0;
  let threshold = input.threshold ?? 0n;
  for (let index = 27; index >= 20; index -= 1) {
    bytes[index] = Number(threshold & 0xffn);
    threshold >>= 8n;
  }
  bytes[28] = input.guardTag ?? 0;
  bytes[29] = input.mask;
  bytes[30] = input.mode;
  bytes[31] = input.subject;
  return bytes as Bytes32;
}

const bit = (id: ListId): number => 1 << (id - 1);
const OUTPUT_OWNER = 1;
const SENDER = 2;
const EXIT = 3;
const ASSET = 4;
const PRESENT = 1;
const ABSENT = 2;

function reason(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof RingError) return String(error.details?.["reason"]);
    throw error;
  }
  throw new Error("expected a RingError");
}

describe("rule rows", () => {
  it("decodes require, forbid, any-of, inline assets and a threshold", () => {
    expect(
      decodeRule(row({ subject: OUTPUT_OWNER, mode: PRESENT, mask: bit(ListId.allow) })),
    ).toEqual({
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.allow], absent: [] },
      guard: { kind: "always" },
    });
    expect(decodeRule(row({ subject: SENDER, mode: ABSENT, mask: bit(ListId.frozen) }))).toEqual({
      subject: "sender",
      source: { kind: "lists", present: [], absent: [ListId.frozen] },
      guard: { kind: "always" },
    });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.approval),
          alternative: bit(ListId.block),
        }),
      ),
    ).toEqual({
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.approval], absent: [ListId.block] },
      guard: { kind: "always" },
    });
    expect(decodeRule(row({ subject: ASSET, mode: PRESENT, mask: 0 }))).toEqual({
      subject: "asset",
      source: { kind: "inlineAssets" },
      guard: { kind: "always" },
    });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.approval),
          guardTag: 1,
          threshold: 2000n,
        }),
      ).guard,
    ).toEqual({ kind: "aboveAmount", amount: 2000n });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.allow),
          guardTag: 2,
        }),
      ).guard,
    ).toEqual({ kind: "aboveAmountByAsset" });
  });

  it("orders a set in slot order", () => {
    expect(listSet(0b1000_0101)).toEqual([ListId.allow, ListId.frozen, ListId.escrow]);
    expect(LIST_IDS).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("refuses every row Rust refuses", () => {
    const allow = bit(ListId.allow);
    const cases: readonly [string, Parameters<typeof row>[0]][] = [
      ["ReservedBytes", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, reserved: 1 }],
      ["UnknownSubject", { subject: 5, mode: PRESENT, mask: allow }],
      ["UnknownSubject", { subject: 0, mode: PRESENT, mask: allow }],
      ["UnknownMode", { subject: OUTPUT_OWNER, mode: 3, mask: allow }],
      ["InlineWithAlternative", { subject: ASSET, mode: PRESENT, mask: 0, alternative: allow }],
      ["InlineAbsent", { subject: ASSET, mode: ABSENT, mask: 0 }],
      [
        "NonCanonicalAlternative",
        { subject: SENDER, mode: ABSENT, mask: allow, alternative: allow },
      ],
      [
        "ThresholdWithoutGuard",
        { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, threshold: 1n },
      ],
      ["UnknownGuardTag", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, guardTag: 3 }],
      ["ExitDestination", { subject: EXIT, mode: PRESENT, mask: allow }],
      ["ListInBothSets", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, alternative: allow }],
      ["InlineNotAsset", { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0 }],
      ["SenderGuard", { subject: SENDER, mode: PRESENT, mask: allow, guardTag: 1, threshold: 5n }],
      ["ZeroThreshold", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, guardTag: 1 }],
      ["PerAssetGuardNotOwner", { subject: ASSET, mode: PRESENT, mask: allow, guardTag: 2 }],
    ];
    for (const [expected, input] of cases) {
      expect(reason(() => decodeRule(row(input)))).toBe(expected);
    }
  });
});

describe("rule tables", () => {
  const requireAllow = row({ subject: OUTPUT_OWNER, mode: PRESENT, mask: bit(ListId.allow) });
  const inline = row({ subject: ASSET, mode: PRESENT, mask: 0 });
  const guardedOwner = row({
    subject: OUTPUT_OWNER,
    mode: PRESENT,
    mask: bit(ListId.approval),
    guardTag: 1,
    threshold: 2000n,
  });
  const perAsset = row({
    subject: OUTPUT_OWNER,
    mode: PRESENT,
    mask: bit(ListId.allow),
    guardTag: 2,
  });
  const mint = filled(0x14);

  it("decodes the Go fixture table and names its lists", () => {
    const table = decodeRuleTable({
      rules: [
        requireAllow,
        row({ subject: SENDER, mode: ABSENT, mask: bit(ListId.frozen) }),
        inline,
        guardedOwner,
      ],
      inlineAssets: [mint],
      inlineLimits: [0n],
    });
    expect(table.rules).toHaveLength(4);
    expect(table.rules[3]?.guard).toEqual({ kind: "aboveAmount", amount: 2000n });
    expect(referencedLists(table.rules)).toEqual([ListId.allow, ListId.frozen, ListId.approval]);
    expect(decodeRuleTable({ rules: [], inlineAssets: [], inlineLimits: [] }).rules).toEqual([]);
    const limited = decodeRuleTable({
      rules: [perAsset],
      inlineAssets: [mint],
      inlineLimits: [2000n],
    });
    expect(limited.rules[0]?.guard).toEqual({ kind: "aboveAmountByAsset" });
    expect(limited.inlineLimits).toEqual([2000n]);
  });

  it("refuses every table Rust refuses", () => {
    const sender = (id: ListId): Bytes32 => row({ subject: SENDER, mode: PRESENT, mask: bit(id) });
    const cases: readonly [
      string,
      {
        rules: readonly Bytes32[];
        inlineAssets: readonly Bytes32[];
        inlineLimits: readonly bigint[];
      },
    ][] = [
      [
        "TooManyRules",
        {
          rules: Array.from({ length: 17 }, () => requireAllow),
          inlineAssets: [],
          inlineLimits: [],
        },
      ],
      [
        "TooManyInlineAssets",
        {
          rules: [inline],
          inlineAssets: Array.from({ length: 9 }, () => mint),
          inlineLimits: Array.from({ length: 9 }, () => 0n),
        },
      ],
      ["ZeroInlineAsset", { rules: [inline], inlineAssets: [filled(0)], inlineLimits: [0n] }],
      [
        "DuplicateRule",
        { rules: [requireAllow, requireAllow], inlineAssets: [], inlineLimits: [] },
      ],
      ["InlineWithoutPool", { rules: [inline], inlineAssets: [], inlineLimits: [] }],
      [
        "PoolWithoutInlineRule",
        { rules: [requireAllow], inlineAssets: [mint], inlineLimits: [0n] },
      ],
      [
        "OwnerGuardWithoutInlineAsset",
        { rules: [guardedOwner], inlineAssets: [], inlineLimits: [] },
      ],
      ["MissingAssetLimit", { rules: [perAsset], inlineAssets: [], inlineLimits: [] }],
      ["MissingAssetLimit", { rules: [perAsset], inlineAssets: [mint], inlineLimits: [0n] }],
      [
        "DuplicateInlineAsset",
        { rules: [perAsset], inlineAssets: [mint, mint], inlineLimits: [1n, 2n] },
      ],
      ["AssetLimitWithoutGuard", { rules: [inline], inlineAssets: [mint], inlineLimits: [1n] }],
      [
        "OwnerGuardWithoutInlineAsset",
        { rules: [guardedOwner, inline], inlineAssets: [mint, mint], inlineLimits: [0n, 0n] },
      ],
      [
        "TooManyAnswers",
        {
          rules: [
            requireAllow,
            ...LIST_IDS.slice(1, 3).map(sender),
            row({ subject: ASSET, mode: PRESENT, mask: bit(ListId.reader) }),
            row({ subject: OUTPUT_OWNER, mode: ABSENT, mask: bit(ListId.block) }),
          ],
          inlineAssets: [],
          inlineLimits: [],
        },
      ],
    ];
    for (const [expected, input] of cases) {
      expect(reason(() => decodeRuleTable(input))).toBe(expected);
    }
  });
});

/** `custom-rings/sdk/tests/go_policy_vectors.rs`. */
const RECORDS_PDA = addressOf(filled(0x11));
const CURATOR_PDA = addressOf(filled(0x12));
const RECIPIENT_TAG = filled(0xa1);
const SENDER_TAG = filled(0xb2);
const BLOCKED_TAG = filled(0xc3);

const ALLOW_PRESENT = {
  seed: "1a226466656865c6abbc97ffe595edd254a69d89071e659fedc495d140b6f00e",
  address: "0ee2aa711dae06d975e5709ed68eafd75cd74070b75859093bb9becf3d2387b0",
  dataHash: "01b623e0a858d61692c7da1d75771d3bf368ef5f8647139f030ed3d281dc1c01",
  utxoHash: "053cce0509ced4cd9c95c0f84c49b6fe40eeadf91d3166c8879db4c0b8df3c65",
  nullifier: "23ea6084012812863119d78a52a0ecdaa1431254e08d0f0d2c95a8accb9f1e68",
};
const BLOCK_CLEARED = {
  address: "2f717b4319dbc570077080cfdf8ddaf15e2357bc6282adbd40940b7455869b7e",
  dataHash: "22c0474e22652fc298f31f82df3e64ea25390b75a37d303605b1d7bd037ef849",
  utxoHash: "1a349272ecf58b247f3c461605e6b354ab316b6afb6e836160491cc0dad408d1",
  nullifier: "0210014fd4163aad3eae789aa5eceb789bcf928c85f23ad9ab897d38e13d70a1",
};
const FROZEN_ADDRESS = "061a65b955d92905ed3ac1ea36026f9171850fdcdb1ff5442fe90402da8b9f58";

function entry(
  listId: ListId,
  member: Member,
  state: ListEntry["state"],
  version: bigint,
): ListEntry {
  return { listId, member, state, version, contentHash: filled(0) };
}

/** Rust `ListEntry::to_output_data`. */
function outputData(value: ListEntry): Uint8Array {
  const bytes = new Uint8Array(79);
  bytes[1] = 74;
  bytes[5] = value.listId;
  bytes.set(value.member, 6);
  bytes[38] = value.state === "active" ? 1 : 2;
  let version = value.version;
  for (let index = 39; index < 47; index += 1) {
    bytes[index] = Number(version & 0xffn);
    version >>= 8n;
  }
  bytes.set(value.contentHash, 47);
  return bytes;
}

describe("entries", () => {
  const owner = RingListNamespace.of(RECORDS_PDA);

  it("derives the owner hash the Go policy fixture pins", () => {
    expect(owner.ownerHash).toEqual(
      hex("1e99b255125d8e5d1a8ee78945c3197b227182301b2c5d263dd5410b5ff476be"),
    );
  });

  it("hashes an active entry as the Go fixture does", () => {
    const active = entry(ListId.allow, memberOfTag(RECIPIENT_TAG), "active", 0n);
    expect(owner.entryHashes(active)).toEqual({
      address: hex(ALLOW_PRESENT.address),
      dataHash: hex(ALLOW_PRESENT.dataHash),
      utxoHash: hex(ALLOW_PRESENT.utxoHash),
      nullifier: hex(ALLOW_PRESENT.nullifier),
    });
  });

  it("hashes a cleared entry as the Go fixture does", () => {
    const cleared = entry(ListId.block, memberOfTag(BLOCKED_TAG), "cleared", 1n);
    expect(owner.entryHashes(cleared)).toEqual({
      address: hex(BLOCK_CLEARED.address),
      dataHash: hex(BLOCK_CLEARED.dataHash),
      utxoHash: hex(BLOCK_CLEARED.utxoHash),
      nullifier: hex(BLOCK_CLEARED.nullifier),
    });
  });

  it("derives a curator owned address", () => {
    const sender = memberOfTag(SENDER_TAG);
    expect(
      RingListNamespace.of(CURATOR_PDA).entryAddress({ listId: ListId.frozen, member: sender }),
    ).toEqual(hex(FROZEN_ADDRESS));
    expect(memberOfAsset(addressOf(filled(0xd4)))).toEqual(
      hex("14a6b5092f941bd4336fe2a25fc617a9515b457e027e0cf5e4867c0858855ec1"),
    );
  });

  it("round trips the published envelope", () => {
    const value = entry(ListId.frozen, memberOfTag(filled(5)), "cleared", 7n);
    expect(decodeListEntry(outputData(value))).toEqual(value);
    const cases: readonly [string, (bytes: Uint8Array) => void][] = [
      ["encoding", (bytes) => (bytes[0] = 1)],
      ["length", (bytes) => (bytes[1] = 73)],
      ["listId", (bytes) => (bytes[5] = 9)],
      ["zeroMember", (bytes) => bytes.fill(0, 6, 38)],
      ["state", (bytes) => (bytes[38] = 3)],
    ];
    for (const [expected, corrupt] of cases) {
      const bytes = outputData(value);
      corrupt(bytes);
      expect(reason(() => decodeListEntry(bytes))).toBe(expected);
    }
    expect(() => decodeListEntry(outputData(value).subarray(0, 78))).toThrow();
    expect(reason(() => memberOfTag(new Uint8Array(31)))).toBe("tagLength");
  });
});

describe("lineage walk", () => {
  const ENTRIES_TREE = addressOf(filled(0x77));
  const OTHER_TREE = addressOf(filled(0x78));
  const owner = RingListNamespace.of(RECORDS_PDA);
  const member = memberOfTag(RECIPIENT_TAG);
  const v0 = entry(ListId.allow, member, "active", 0n);
  const v1 = entry(ListId.allow, member, "cleared", 1n);
  const signature = (text: string): Signature => text as Signature;

  function slot(value: ListEntry, tree = ENTRIES_TREE): OutputSlot {
    return {
      viewTag: filled(0),
      outputContext: { hash: owner.entryHashes(value).utxoHash, tree, leafIndex: 0n },
      payload: outputData(value),
    };
  }

  function spender(
    nullifier: Bytes32,
    slots: readonly OutputSlot[],
    text: string,
  ): IndexedShieldedTransaction {
    return {
      slot: 5n,
      txSignature: signature(text),
      outputSlots: slots,
      messages: [],
      nullifiers: [nullifier],
      proofless: false,
    };
  }

  function indexerOf(transactions: readonly IndexedShieldedTransaction[]) {
    const byNullifiers = vi.fn(async (request: { nullifiers: readonly Bytes32[] }) =>
      transactionsPage({
        transactions: transactions.filter((transaction) =>
          transaction.nullifiers.some((spent) =>
            request.nullifiers.some((asked) => Buffer.from(asked).equals(spent)),
          ),
        ),
        scannedThrough: new Uint8Array([1]),
      }),
    );
    return {
      indexer: syncReads({ getShieldedTransactionsByNullifiers: byNullifiers }),
      byNullifiers,
    };
  }

  const read = (indexer: ReturnType<typeof syncReads>) =>
    readRingEntry({
      indexer,
      entriesTree: ENTRIES_TREE,
      namespace: RECORDS_PDA,
      listId: ListId.allow,
      member,
    });

  it("reads undefined for a pair nobody claimed", async () => {
    const { indexer, byNullifiers } = indexerOf([]);
    await expect(read(indexer)).resolves.toBeUndefined();
    expect(byNullifiers).toHaveBeenCalledTimes(1);
  });

  it("reads the claimed version and then its update", async () => {
    const claim = spender(owner.entryHashes(v0).address, [slot(v0)], "claim");
    const { indexer } = indexerOf([claim]);
    await expect(read(indexer)).resolves.toEqual({
      entry: v0,
      utxoHash: hex(ALLOW_PRESENT.utxoHash),
      nullifier: hex(ALLOW_PRESENT.nullifier),
      txSignature: signature("claim"),
      slot: 5n,
    });
    const update = spender(owner.entryHashes(v0).nullifier, [slot(v1)], "update");
    const walked = indexerOf([claim, update]);
    await expect(read(walked.indexer)).resolves.toMatchObject({ entry: v1, txSignature: "update" });
    expect(walked.byNullifiers).toHaveBeenCalledTimes(3);
  });

  it("refuses a spender that carries no next version in the entries tree", async () => {
    const { indexer } = indexerOf([
      spender(owner.entryHashes(v0).address, [slot(v0, OTHER_TREE)], "x"),
    ]);
    await expect(read(indexer)).rejects.toMatchObject({ code: "RING_ENTRY_LINEAGE_BROKEN" });
  });

  it("refuses a successor whose bytes do not reproduce the leaf", async () => {
    const forged = { ...slot(v0), payload: outputData({ ...v0, version: 3n }) };
    const { indexer } = indexerOf([spender(owner.entryHashes(v0).address, [forged], "x")]);
    await expect(read(indexer)).rejects.toMatchObject({ code: "RING_ENTRY_LINEAGE_BROKEN" });
  });

  it("keeps paging until a page carries scannedThrough", async () => {
    const claim = spender(owner.entryHashes(v0).address, [slot(v0)], "claim");
    const pages = [
      transactionsPage({ nextCursor: new Uint8Array([1]) }),
      transactionsPage({
        transactions: [claim],
        nextCursor: new Uint8Array([2]),
        scannedThrough: new Uint8Array([2]),
      }),
      transactionsPage({ scannedThrough: new Uint8Array([3]) }),
    ];
    const byNullifiers = vi.fn(
      async () => pages.shift() ?? transactionsPage({ scannedThrough: new Uint8Array([9]) }),
    );
    const indexer = syncReads({ getShieldedTransactionsByNullifiers: byNullifiers });
    await expect(read(indexer)).resolves.toMatchObject({ entry: v0 });
    expect(byNullifiers).toHaveBeenCalledTimes(3);
  });

  it("lists every live entry a tag scan names and drops a stray", async () => {
    const blocked = entry(ListId.block, memberOfTag(BLOCKED_TAG), "active", 0n);
    const stray = entry(ListId.frozen, memberOfTag(SENDER_TAG), "active", 0n);
    const claims = [
      spender(owner.entryHashes(v0).address, [slot(v0)], "allow"),
      spender(owner.entryHashes(blocked).address, [slot(blocked)], "block"),
    ];
    const { indexer: walker } = indexerOf(claims);
    const match = (value: ListEntry, tree = ENTRIES_TREE) => ({
      slot: 5n,
      txSignature: signature("any"),
      outputSlot: slot(value, tree),
    });
    const byTags = vi.fn(async () =>
      matchesPage({ matches: [match(v0), match(blocked), match(stray), match(v1, OTHER_TREE)] }),
    );
    const live = await readRingEntries({
      indexer: syncReads({ ...walker, getEncryptedUtxosByTags: byTags }),
      entriesTree: ENTRIES_TREE,
      namespace: RECORDS_PDA,
    });
    expect(live.map((item) => [item.entry.listId, item.txSignature])).toEqual([
      [ListId.allow, "allow"],
      [ListId.block, "block"],
    ]);
    expect(byTags).toHaveBeenCalledWith(
      expect.objectContaining({ tags: [filled(0x11)] }),
      undefined,
      undefined,
    );
  });
});
