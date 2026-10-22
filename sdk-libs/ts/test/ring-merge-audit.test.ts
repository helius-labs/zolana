import { readFileSync } from "node:fs";
import type { Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import vector from "../../../test-vectors/ring-merge-anonymous.json" with { type: "json" };
import type { RingMemberPage, RingMemberPageRequest } from "../src/client/ports.js";
import { fieldAdd, initializePoseidon } from "../src/hasher/index.js";
import { wireDecoder } from "../src/interface/decode.js";
import { encodeBase58 } from "../src/interface/internal.js";
import { ringMemberRegistryPda, treeAddress } from "../src/interface/pda/index.js";
import type { Bytes16, Bytes31, Bytes32, Bytes33, Signature } from "../src/interface/types.js";
import { bigIntToBytes, bytesToBigInt } from "../src/keypair/bytes.js";
import { mergeOutputBlinding, mergeOutputKey } from "../src/keypair/merge/index.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { auditRingMerges, openDisclosedMerge } from "../src/ring/audit-merge.js";
import type { RingMergeDisclosure } from "../src/ring/merge-disclosure.js";
import { escrowKeyHash } from "../src/ring/member-registry.js";
import { memberOfTag } from "../src/ring/policy.js";
import type { TransactionOrigin } from "../src/ring/origin.js";
import { sealNullifierKey } from "../src/ring/register-key.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { poseidon } from "../src/transaction/internal.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { ownerUtxoHash } from "../src/transaction/utxo.js";
import { kitReads, solanaRpcReads, transactionsPage } from "./helpers/clients.js";
import { recordTree, type FixtureRecord } from "./helpers/member-registry.js";
import { memberRegistryData, ownedAccount } from "./helpers/ring-accounts.js";

await initializePoseidon();

const decode = wireDecoder((path) => new Error(`merge fixture ${path}`));
/** The Rust client's confirmed `merge_ring` event, its output opens under no fixture key. */
const fixture = decode.record(
  JSON.parse(
    readFileSync(
      new URL(
        "../../../custom-rings/client/tests/fixtures/confirmed-merge-event.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
  "fixture",
);
const expected = decode.record(fixture["expected"], "expected");
const ring = decode.address(fixture["ring"], "ring");
const SIGNATURE = "5".repeat(87) as Signature;

function bytes(value: unknown): Uint8Array {
  const text = decode.string(value, "hex");
  if (!/^(?:[a-f0-9]{2})*$/u.test(text)) throw new Error("fixture hex");
  return Uint8Array.from(Buffer.from(text, "hex"));
}

function field(value: unknown): Bytes32 {
  const result = bytes(value);
  if (result.length !== 32) throw new Error("fixture field");
  return result as Bytes32;
}

const output = decode.record(decode.list(expected["outputs"], "outputs")[0], "output");
const TREE_ID = Number(decode.integer(output["treeId"], "treeId"));
const UNOPENED: IndexedShieldedTransaction = {
  slot: 7n,
  txSignature: SIGNATURE,
  eventIndex: 0,
  proofless: false,
  ringProgramId: ring,
  nullifiers: decode.list(expected["nullifiersHex"], "nullifiers").map(field),
  messages: [],
  outputSlots: [
    {
      viewTag: field(output["viewTagHex"]),
      payload: bytes(output["payloadHex"]),
      outputContext: {
        hash: field(output["hashHex"]),
        tree: treeAddress(TREE_ID),
        treeId: TREE_ID,
        leafIndex: decode.integer(output["leafIndex"], "leafIndex"),
      },
    },
  ],
};

/** The `RegisterKey` signer of every escrowed fixture record, its member the owner tag. */
const OWNER = encodeBase58(new Uint8Array(32).fill(23));
const OWNER_MEMBER: Bytes32 = memberOfTag(new Uint8Array(32).fill(23));

function memberOf(index: number): Bytes32 {
  const value = new Uint8Array(32);
  value[30] = index >> 8;
  value[31] = index & 0xff;
  return value as Bytes32;
}

/** Every transaction is a confirmed merge of the ring, the binding is the origin tests' concern. */
const MERGES: TransactionOrigin = {
  confirmedTransaction: async (transaction) => ({ kind: "merge", transaction }),
};

/** A ring merge whose output the member's escrowed key opens. */
function escrowedMerge(input: Readonly<{ member: Bytes32; key: NullifierKey }>) {
  const firstNullifier = memberOf(0x77);
  const salt = new Uint8Array(16).fill(3) as Bytes16;
  const ringDataHash = memberOf(0x55);
  const amount = 9n;
  const blinding = mergeOutputBlinding(input.key, firstNullifier);
  const commitment = ownerUtxoHash({
    owner: poseidon([input.member, input.key.publicKey()]),
    asset: SOL_MINT,
    amount,
    blinding,
    treeId: TREE_ID,
    ringDataHash,
    ringProgramId: ring,
  });
  const ciphertext = encryptMergeOutput(
    { amount, mint: SOL_MINT },
    mergeOutputKey(input.key, firstNullifier),
    salt,
  );
  const transaction: IndexedShieldedTransaction = {
    ...UNOPENED,
    txSignature: "6".repeat(87) as Signature,
    nullifiers: [firstNullifier, memberOf(0x78)],
    outputSlots: [
      {
        viewTag: firstNullifier,
        payload: encodeMergeOutputData({ salt, ciphertext, ringDataHash }),
        outputContext: { ...UNOPENED.outputSlots[0]!.outputContext, hash: commitment },
      },
    ],
  };
  return { transaction, commitment, blinding, ringDataHash, amount };
}

async function scanClient(
  input: Readonly<{
    records: readonly FixtureRecord[];
    transactions: readonly IndexedShieldedTransaction[][];
    page?: (page: RingMemberPage, request: RingMemberPageRequest) => RingMemberPage;
    noFrontier?: boolean;
  }>,
) {
  const tree = recordTree(input.records);
  const [registry, bump] = await ringMemberRegistryPda(ring);
  const memberPages = vi.fn(async (request: RingMemberPageRequest): Promise<RingMemberPage> => {
    const end = Math.min(request.startIndex + request.limit, tree.nextIndex);
    const page: RingMemberPage = {
      context: { slot: 7n, blockTime: 1n },
      root: { root: tree.root, rootIndex: 0, applied: 0n, nextIndex: tree.nextIndex },
      records: tree.rows.slice(request.startIndex, end).map((record, offset) => {
        const sealed = input.records.find(
          (entry) => bytesToBigInt(entry.member) === bytesToBigInt(record.member),
        )?.sealed;
        return {
          record,
          path: tree.path(request.startIndex + offset),
          ...(sealed === undefined ? {} : { sealedKey: sealed }),
        };
      }),
      nextLeafIndex: end < tree.nextIndex ? end : undefined,
    };
    return input.page?.(page, request) ?? page;
  });
  const transactionPages = vi.fn(async (request: { cursor?: Uint8Array }) => {
    const at = request.cursor?.[0] ?? 0;
    const last = at + 1 === input.transactions.length;
    return transactionsPage({
      transactions: input.transactions[at] ?? [],
      ...(last
        ? input.noFrontier === true
          ? {}
          : { scannedThrough: Uint8Array.of(at) }
        : { nextCursor: Uint8Array.of(at + 1) }),
    });
  });
  return {
    client: {
      ...kitReads({ solanaRpc: solanaRpcReads({}) }),
      getAccount: async (account: Address) =>
        account === registry
          ? ownedAccount(
              ring,
              memberRegistryData({
                bump,
                history: [{ root: tree.root, applied: 0n, slot: 0n }],
                nextIndex: tree.nextIndex,
              }),
            )
          : undefined,
      getRingMemberRecords: memberPages,
      getShieldedTransactionsByTags: transactionPages,
    },
    memberPages,
    transactionPages,
  };
}

describe("auditRingMerges", () => {
  it("authenticates every registry page at the chain root and keeps an unopened merge", async () => {
    // 101 members and the sentinel need two pages of `MAX_RING_MEMBER_BATCH`.
    const records = Array.from({ length: 101 }, (_, index) => ({
      member: memberOf(index + 1),
      lists: 0n,
    }));
    const auditor = X25519Keypair.generate();
    const { client, memberPages, transactionPages } = await scanClient({
      records,
      transactions: [[UNOPENED], []],
    });
    const result = await auditRingMerges({ client, ringProgramId: ring, auditor, origin: MERGES });
    expect(memberPages).toHaveBeenCalledTimes(2);
    expect(transactionPages).toHaveBeenCalledTimes(2);
    expect(result.opened).toEqual([]);
    expect(result.unresolved).toEqual([
      {
        signature: SIGNATURE,
        eventIndex: 0,
        outputCommitment: UNOPENED.outputSlots[0]!.outputContext.hash,
      },
    ]);
    expect(result.nextCursor).toBeUndefined();
  });

  it("opens a merge with the member's escrowed key and derives its nullifier", async () => {
    const auditor = X25519Keypair.generate();
    const member = OWNER_MEMBER;
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    const sealed = sealNullifierKey(key, auditor.publicKey()).sealed;
    const merge = escrowedMerge({ member, key });
    const { client } = await scanClient({
      records: [
        {
          member,
          lists: 0n,
          escrowKey: escrowKeyHash({ nullifierPk: key.publicKey(), ciphertext: sealed.ciphertext }),
          sealed: {
            owner: OWNER,
            nullifierPk: key.publicKey(),
            ...sealed,
          },
        },
      ],
      transactions: [[merge.transaction, UNOPENED]],
    });
    const result = await auditRingMerges({ client, ringProgramId: ring, auditor, origin: MERGES });
    expect(result.opened).toEqual([
      {
        signature: merge.transaction.txSignature,
        eventIndex: 0,
        outputCommitment: merge.commitment,
        ownerMember: member,
        ownerPublicKey: OWNER,
        mint: SOL_MINT,
        amount: merge.amount,
        blinding: merge.blinding,
        ringDataHash: merge.ringDataHash,
        inputNullifiers: merge.transaction.nullifiers,
        keys: { kind: "escrowed", nullifier: key.nullifier(merge.commitment, merge.blinding) },
      },
    ]);
    expect(result.unresolved.map((entry) => entry.signature)).toEqual([SIGNATURE]);
  });

  it("refuses an escrowed record without its sealed key and a key its escrow key does not bind", async () => {
    const auditor = X25519Keypair.generate();
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(6) as Bytes31);
    const sealed = sealNullifierKey(key, auditor.publicKey()).sealed;
    const escrowKey = escrowKeyHash({
      nullifierPk: key.publicKey(),
      ciphertext: sealed.ciphertext,
    });
    const served = {
      owner: OWNER,
      nullifierPk: key.publicKey(),
      ...sealed,
    };
    for (const [record, reason] of [
      [{ member: OWNER_MEMBER, lists: 0n, escrowKey }, "sealed key"],
      [
        { member: OWNER_MEMBER, lists: 0n, escrowKey: memberOf(0x99), sealed: served },
        "escrow key",
      ],
    ] as const) {
      const { client } = await scanClient({ records: [record], transactions: [[UNOPENED]] });
      await expect(
        auditRingMerges({ client, ringProgramId: ring, auditor, origin: MERGES }),
      ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID", details: { reason } });
    }
  });

  it.each<readonly [string, (page: RingMemberPage) => RingMemberPage]>([
    ["another root", (page) => ({ ...page, root: { ...page.root, root: memberOf(9) } })],
    [
      "a gap in the leaves",
      (page) => ({
        ...page,
        records: page.records.map((row) => ({
          ...row,
          path: { ...row.path, index: row.path.index + 1 },
        })),
      }),
    ],
    ["a short page", (page) => ({ ...page, records: page.records.slice(1) })],
  ])("refuses a registry page with %s before any key opens", async (_name, edit) => {
    const auditor = X25519Keypair.generate();
    const { client } = await scanClient({
      records: [
        { member: memberOf(1), lists: 0n },
        { member: memberOf(2), lists: 0n },
      ],
      transactions: [[UNOPENED]],
      page: edit,
    });
    await expect(
      auditRingMerges({ client, ringProgramId: ring, auditor, origin: MERGES }),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID" });
  });

  it("refuses a terminal history page without a scan frontier and a merge read twice", async () => {
    const auditor = X25519Keypair.generate();
    const records = [{ member: memberOf(1), lists: 0n }];
    const frontier = await scanClient({ records, transactions: [[UNOPENED]], noFrontier: true });
    await expect(
      auditRingMerges({ client: frontier.client, ringProgramId: ring, auditor, origin: MERGES }),
    ).rejects.toMatchObject({ code: "RING_SCAN_FRONTIER_MISSING" });
    const twice = await scanClient({ records, transactions: [[UNOPENED], [UNOPENED]] });
    await expect(
      auditRingMerges({ client: twice.client, ringProgramId: ring, auditor, origin: MERGES }),
    ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE", details: { reason: "duplicate merge" } });
  });
});

describe("openDisclosedMerge (test-vectors/ring-merge-anonymous.json)", () => {
  const hex = <T extends Uint8Array>(value: string, length: number): T => {
    const decoded = Uint8Array.from(Buffer.from(value.replace(/^0x/u, ""), "hex"));
    if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
    return decoded as T;
  };
  const disclosure: RingMergeDisclosure = {
    proof: new Uint8Array(192),
    ephemeralPublicKey: hex<Bytes33>(vector.eph_pk, 33),
    ciphertext: hex<Bytes32>(vector.envelope_ciphertext, 32),
    fields: vector.fields.map((value) => hex<Bytes32>(value, 32)),
  };
  const open = (auditor: X25519Keypair, opened: RingMergeDisclosure) =>
    openDisclosedMerge({
      auditor,
      disclosure: opened,
      salt: hex<Bytes16>(vector.salt, 16),
      width: vector.width,
      ringId: hex<Bytes32>(vector.request.ringProgramId, 32),
      ringDataHash: hex<Bytes32>(vector.request.outputRingDataHash, 32),
      treeId: Number(BigInt(vector.request.outputTreeId)),
      outputCommitment: hex<Bytes32>(vector.request.outputUtxoHash, 32),
    });
  // Field 3 carries plaintext bytes 93..123, the amount ends at byte 103 and the blinding spans 104..135.
  const shifted = (delta: bigint): RingMergeDisclosure => ({
    ...disclosure,
    fields: disclosure.fields.map((value, index) =>
      index === 3 ? (bigIntToBytes(fieldAdd(bytesToBigInt(value), delta)) as Bytes32) : value,
    ),
  });

  it("reproduces the settled commitment from the disclosed opening", () => {
    const auditor = X25519Keypair.fromBytes(hex(vector.auditor_sk, 32));
    try {
      const opening = open(auditor, disclosure);
      expect(opening.amount).toBe(BigInt(vector.amount));
      expect(Buffer.from(opening.outputBlinding).toString("hex")).toBe(
        vector.output_blinding.slice(2),
      );
    } finally {
      auditor.destroy();
    }
  });

  it.each([
    ["amount", 1n << 160n],
    ["blinding", 1n],
  ] as const)("refuses a disclosure with a tampered %s", (_, delta) => {
    const auditor = X25519Keypair.fromBytes(hex(vector.auditor_sk, 32));
    try {
      expect(() => open(auditor, shifted(delta))).toThrow(
        expect.objectContaining({
          code: "RING_AUDIT_MESSAGE",
          details: { reason: "merge disclosure output" },
        }),
      );
    } finally {
      auditor.destroy();
    }
  });

  it("does not open under another auditor key", () => {
    const auditor = X25519Keypair.generate();
    try {
      expect(() => open(auditor, disclosure)).toThrow();
    } finally {
      auditor.destroy();
    }
  });
});
