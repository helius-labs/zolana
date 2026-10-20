import { readFileSync } from "node:fs";
import { getBase58Decoder, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { kitReads, solanaRpcReads, transactionsPage } from "./helpers/clients.js";
import { memberRegistryRootData, registryFixture } from "./helpers/member-registry.js";
import { ownedAccount, ringProgramConfigData } from "./helpers/ring-accounts.js";
import { treeAccount } from "./helpers/tree-account.js";
import { initializePoseidon } from "../src/hasher/index.js";
import { wireDecoder } from "../src/interface/decode.js";
import {
  ringConfigPda,
  ringMemberRegistryRootPda,
  treeAddress,
} from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32, Signature } from "../src/interface/types.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { auditRingMerges } from "../src/ring/audit-merge.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";

await initializePoseidon();
const decode = wireDecoder((path) => new Error(`merge fixture ${path}`));
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
const source = decode.record(fixture["source"], "source");
const expected = decode.record(fixture["expected"], "expected");
const ring = decode.address(fixture["ring"], "ring");
const signature = "5".repeat(87) as Signature;
const bytes = (value: unknown): Uint8Array => {
  const hex = decode.string(value, "hex");
  if (!/^(?:[a-f0-9]{2})*$/u.test(hex)) throw new Error("fixture hex");
  return Uint8Array.from(Buffer.from(hex, "hex"));
};
const field = (value: unknown): Bytes32 => {
  const result = bytes(value);
  if (result.length !== 32) throw new Error("fixture field");
  return result as Bytes32;
};
const output = decode.record(decode.list(expected["outputs"], "outputs")[0], "output");
const treeId = Number(decode.integer(output["treeId"], "treeId"));
const indexed: IndexedShieldedTransaction = {
  slot: 7n,
  txSignature: signature,
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
        tree: treeAddress(treeId),
        treeId,
        leafIndex: decode.integer(output["leafIndex"], "leafIndex"),
      },
    },
  ],
};
const accounts = decode
  .list(source["accounts"], "accounts")
  .map((item) => decode.address(item, "account"));
const keys = [...new Set([...accounts, ring, SHIELDED_POOL_PROGRAM_ID])];
const indices = accounts.map((item) => keys.indexOf(item));
const confirmed = {
  slot: 7,
  transaction: {
    signatures: [signature],
    message: {
      accountKeys: keys,
      instructions: [{ programIdIndex: keys.indexOf(ring), accounts: indices, data: "" }],
    },
  },
  meta: {
    err: null,
    innerInstructions: [
      {
        index: 0,
        instructions: [
          {
            programIdIndex: keys.indexOf(SHIELDED_POOL_PROGRAM_ID),
            accounts: indices,
            stackHeight: 2,
            data: getBase58Decoder().decode(bytes(source["dataHex"])),
          },
          {
            programIdIndex: keys.indexOf(SHIELDED_POOL_PROGRAM_ID),
            accounts: indices,
            stackHeight: 3,
            data: getBase58Decoder().decode(bytes(fixture["eventDataHex"])),
          },
        ],
      },
    ],
  },
};
const member = (lastByte: number): Bytes32 => {
  const value = new Uint8Array(32);
  value[31] = lastByte;
  return value as Bytes32;
};
const members = [member(1), member(2)] as const;
const registry = registryFixture(members.map((value) => ({ member: value, lists: 0n })));
const [registryAddress, bump] = await ringMemberRegistryRootPda(ring);
const [configAddress, configBump] = await ringConfigPda(ring);

function scanClient(
  changes: Readonly<{ wrongRoot?: boolean; gap?: boolean; duplicate?: boolean }> = {},
) {
  const memberPages = vi.fn(async (request: { startIndex: bigint }) => {
    const second = request.startIndex === 2n;
    const record = registry.read(second ? members[1] : members[0]);
    if (record.record === null) throw new Error("missing fixture member");
    return {
      context: { slot: 7n, blockTime: 1n },
      root: changes.wrongRoot && second ? member(9) : registry.root,
      rootIndex: 0,
      nextIndex: 3n,
      records: [
        {
          index: changes.gap && second ? 3n : request.startIndex,
          record: record.record,
          path: record.path,
        },
      ],
      nextLeafIndex: second ? null : 2n,
    };
  });
  const cursor = Uint8Array.of(17);
  const transactionPages = vi.fn(async (request: { cursor?: Uint8Array }) =>
    request.cursor === undefined
      ? transactionsPage({ transactions: [indexed], nextCursor: cursor })
      : transactionsPage({ transactions: changes.duplicate ? [indexed] : [] }),
  );
  const getTransaction = vi.fn(() => ({ send: async () => confirmed }));
  const client = {
    ...kitReads({ solanaRpc: solanaRpcReads({ getTransaction }) }),
    getAccount: async (account: Address) =>
      account === configAddress
        ? ownedAccount(
            ring,
            ringProgramConfigData({
              authority: ring,
              auditorPublicKey: X25519Keypair.generate().publicKey().toBytes(),
              bump: configBump,
              hasPolicy: false,
              keyEscrow: true,
            }),
          )
        : account === registryAddress
          ? ownedAccount(ring, memberRegistryRootData({ root: registry.root, nextIndex: 3n, bump }))
          : account === treeAddress(treeId)
            ? ownedAccount(
                SHIELDED_POOL_PROGRAM_ID,
                treeAccount({ stateCursor: 0, written: 43, nullifierCursor: 0n, treeId }),
              )
            : undefined,
    getRingMemberRecord: async () => {
      throw new Error("single-member lookup must not be needed");
    },
    getRingMemberRecords: memberPages,
    getShieldedTransactionsByTags: transactionPages,
  };
  return { client, memberPages, transactionPages, getTransaction };
}

describe("auditRingMerges confirmed scan", () => {
  it("authenticates two registry pages and two transaction pages, retaining an unopened merge", async () => {
    const { client, memberPages, transactionPages, getTransaction } = scanClient();
    const auditor = X25519Keypair.generate();
    try {
      const result = await auditRingMerges({
        client,
        ringProgramId: ring,
        auditor,
        memberPageSize: 1,
        maxPages: 2,
      });
      expect(memberPages).toHaveBeenCalledTimes(2);
      expect(transactionPages).toHaveBeenCalledTimes(2);
      expect(getTransaction).toHaveBeenCalledTimes(1);
      expect(result.openings).toEqual([]);
      expect(result.unresolved).toEqual([
        {
          signature,
          slot: 7n,
          outputContext: indexed.outputSlots[0]!.outputContext,
        },
      ]);
      expect(result.nextCursor).toBeUndefined();
    } finally {
      auditor.destroy();
    }
  });

  it.each([
    ["wrong root", { wrongRoot: true }, "RING_MEMBER_REGISTRY_STALE"],
    ["pagination gap", { gap: true }, "RING_MEMBER_REGISTRY_INVALID"],
  ] as const)("rejects a %s before opening a merge", async (_, changes, code) => {
    const { client, getTransaction } = scanClient(changes);
    const auditor = X25519Keypair.generate();
    try {
      await expect(
        auditRingMerges({ client, ringProgramId: ring, auditor, memberPageSize: 1 }),
      ).rejects.toMatchObject({ code });
      expect(getTransaction).toHaveBeenCalledTimes(1);
    } finally {
      auditor.destroy();
    }
  });

  it("rejects a duplicate confirmed event across history pages", async () => {
    const { client } = scanClient({ duplicate: true });
    const auditor = X25519Keypair.generate();
    try {
      await expect(
        auditRingMerges({ client, ringProgramId: ring, auditor, memberPageSize: 1 }),
      ).rejects.toMatchObject({ code: "RING_RPC" });
    } finally {
      auditor.destroy();
    }
  });
});
