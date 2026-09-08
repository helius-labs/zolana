import { AccountRole, getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  ringConfigAddress,
  ringPolicyConfigAddress,
  ringPolicyNamespaceAddress,
  ringProgramDataAddress,
} from "../src/ring/config.js";
import {
  RING_CREATE_POLICY_COMPUTE_UNIT_LIMIT,
  RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
  RING_SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
  RING_SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
  createRingPolicyInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
} from "../src/ring/instructions.js";
import {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "../src/ring/policy-admin.js";
import { ListId, buildRuleTable, encodeRule, type Rule } from "../src/ring/policy.js";

import { BLOCKHASH } from "./helpers/clients.js";
import {
  ownSources,
  ownedAccount,
  policyConfigPda,
  ringPolicyConfigData,
} from "./helpers/ring-accounts.js";

await initializePoseidon();

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (byte: number): Address => getAddressDecoder().decode(filled(byte));
const RING = addressOf(10);
const PAYER = addressOf(11);
const AUTHORITY = addressOf(12);
const CURATOR_A = addressOf(20);
const CURATOR_B = addressOf(21);
const ENTRIES_TREE = addressOf(30);
const ASSET = filled(0x14);

const requireAllow: Rule = {
  subject: "outputOwner",
  source: { kind: "lists", present: [ListId.allow], absent: [] },
  guard: { kind: "always" },
};
const approvalOrUnfrozen: Rule = {
  subject: "sender",
  source: { kind: "lists", present: [ListId.approval], absent: [ListId.frozen] },
  guard: { kind: "always" },
};
const allowOnlyAssets: Rule = {
  subject: "asset",
  source: { kind: "inlineAssets" },
  guard: { kind: "always" },
};
/** Rust `instruction_builders.rs` `TABLE`. */
const TABLE = buildRuleTable({
  rules: [requireAllow, approvalOrUnfrozen, allowOnlyAssets],
  inlineAssets: [ASSET],
});
const BLOCK_ONLY = buildRuleTable({
  rules: [
    {
      subject: "outputOwner",
      source: { kind: "lists", present: [], absent: [ListId.block] },
      guard: { kind: "always" },
    },
  ],
});

/** `PolicyTableIxData` for `TABLE` under the given `(listId, source)` specs. */
function tableBody(sources: readonly (readonly [number, number])[]): number[] {
  return [
    sources.length,
    ...sources.flat(),
    3,
    ...TABLE.rules.flatMap((rule) => [...encodeRule(rule)]),
    1,
    ...ASSET,
    1,
    ...new Uint8Array(8),
  ];
}

describe("policy admin instructions", () => {
  it("create policy pins the rows with one source per referenced list", async () => {
    const instruction = await createRingPolicyInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      entriesTree: ENTRIES_TREE,
      table: TABLE,
      sharedSources: [{ listId: ListId.frozen, curatorRingProgramId: CURATOR_A }],
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [await ringPolicyConfigAddress(RING), AccountRole.WRITABLE],
      [ENTRIES_TREE, AccountRole.READONLY],
      [SYSTEM_PROGRAM, AccountRole.READONLY],
      [RING, AccountRole.READONLY],
      [await ringProgramDataAddress(RING), AccountRole.READONLY],
      [await ringPolicyConfigAddress(CURATOR_A), AccountRole.READONLY],
    ]);
    expect([...(instruction.data ?? [])]).toEqual([
      7,
      ...tableBody([
        [ListId.allow, 0],
        [ListId.frozen, 1],
        [ListId.approval, 0],
      ]),
    ]);
    // The group row carries its absent alternative at byte 19.
    expect(instruction.data?.[1 + 7 + 1 + 32 + 19]).toBe(1 << (ListId.frozen - 1));
    expect(RING_CREATE_POLICY_COMPUTE_UNIT_LIMIT).toBe(150_000);
    expect(RING_SET_POLICY_RULES_COMPUTE_UNIT_LIMIT).toBe(150_000);
    expect(RING_SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT).toBe(150_000);
    expect(RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT).toBe(1_400_000);
  });

  it("set policy rules gates on the upgrade authority with the same body", async () => {
    const shared = [{ listId: ListId.frozen, curatorRingProgramId: CURATOR_A }];
    const created = await createRingPolicyInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      entriesTree: ENTRIES_TREE,
      table: TABLE,
      sharedSources: shared,
    });
    const instruction = await setRingPolicyRulesInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      table: TABLE,
      sharedSources: shared,
    });
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [await ringPolicyConfigAddress(RING), AccountRole.WRITABLE],
      [RING, AccountRole.READONLY],
      [await ringProgramDataAddress(RING), AccountRole.READONLY],
      [await ringPolicyConfigAddress(CURATOR_A), AccountRole.READONLY],
    ]);
    expect(instruction.data?.[0]).toBe(12);
    expect(instruction.data?.subarray(1)).toEqual(created.data?.subarray(1));
  });

  it("indexes curators once in first-use order", async () => {
    const sharedSources = [
      { listId: ListId.approval, curatorRingProgramId: CURATOR_B },
      { listId: ListId.frozen, curatorRingProgramId: CURATOR_A },
      { listId: ListId.allow, curatorRingProgramId: CURATOR_B },
    ];
    for (const instruction of [
      await createRingPolicyInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        entriesTree: ENTRIES_TREE,
        table: TABLE,
        sharedSources,
      }),
      await setRingPolicyRulesInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        table: TABLE,
        sharedSources,
      }),
    ]) {
      expect(instruction.accounts?.slice(-2).map((meta) => meta.address)).toEqual([
        await ringPolicyConfigAddress(CURATOR_B),
        await ringPolicyConfigAddress(CURATOR_A),
      ]);
      expect([...(instruction.data?.subarray(1, 8) ?? [])]).toEqual([
        3,
        ListId.allow,
        1,
        ListId.frozen,
        2,
        ListId.approval,
        1,
      ]);
    }
  });

  it("refuses a shared source the table does not reference", async () => {
    await expect(
      setRingPolicyRulesInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        table: TABLE,
        sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR_A }],
      }),
    ).rejects.toMatchObject({
      code: "RING_POLICY_SOURCE_INVALID",
      details: { reason: "UnreferencedList", listId: ListId.block },
    });
  });

  it("set policy source names the config authority and the optional curator", async () => {
    const own = await setRingPolicySourceInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      listId: ListId.block,
      source: { kind: "own" },
    });
    expect(own.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [AUTHORITY, AccountRole.READONLY_SIGNER],
      [await ringConfigAddress(RING), AccountRole.READONLY],
      [await ringPolicyConfigAddress(RING), AccountRole.WRITABLE],
    ]);
    expect([...(own.data ?? [])]).toEqual([10, ListId.block, 0]);
    const curated = await setRingPolicySourceInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      listId: ListId.block,
      source: { kind: "curator", ringProgramId: CURATOR_A },
    });
    expect(curated.accounts?.at(-1)).toEqual({
      address: await ringPolicyConfigAddress(CURATOR_A),
      role: AccountRole.READONLY,
    });
    expect([...(curated.data ?? [])]).toEqual([10, ListId.block, 1]);
  });
});

describe("policy admin transactions", () => {
  /** The curator pins `BLOCK_ONLY` from its own namespace over `entriesTree`, the ring pins `TABLE` when `own` is set. */
  async function chain(input: Readonly<{ entriesTree: Address; own?: boolean }>) {
    const [[curatorPolicy, curatorBump], curatorNamespace, [ownPolicy, ownBump], ownNamespace] =
      await Promise.all([
        policyConfigPda(CURATOR_A),
        ringPolicyNamespaceAddress(CURATOR_A),
        policyConfigPda(RING),
        ringPolicyNamespaceAddress(RING),
      ]);
    const accounts = new Map([
      [
        curatorPolicy,
        ownedAccount(
          CURATOR_A,
          ringPolicyConfigData({
            table: BLOCK_ONLY,
            sources: ownSources(BLOCK_ONLY, curatorNamespace),
            entriesTree: input.entriesTree,
            bump: curatorBump,
          }),
        ),
      ],
    ]);
    if (input.own) {
      accounts.set(
        ownPolicy,
        ownedAccount(
          RING,
          ringPolicyConfigData({
            table: TABLE,
            sources: ownSources(TABLE, ownNamespace),
            entriesTree: ENTRIES_TREE,
            bump: ownBump,
          }),
        ),
      );
    }
    const getAccount = vi.fn(async (account: Address) => accounts.get(account));
    return { getAccount, getLatestBlockhash: vi.fn(async () => BLOCKHASH) };
  }

  it("compiles create policy under the payer after reading the curator", async () => {
    const client = await chain({ entriesTree: ENTRIES_TREE });
    const transaction = await buildRingCreatePolicyTransaction({
      client,
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      entriesTree: ENTRIES_TREE,
      table: BLOCK_ONLY,
      sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR_A }],
    });
    expect(Object.keys(transaction.signatures)).toEqual([PAYER, AUTHORITY]);
    expect(client.getAccount).toHaveBeenCalledWith(
      await ringPolicyConfigAddress(CURATOR_A),
      undefined,
    );
  });

  it("refuses a curator on another tree, without the list, or absent, before the blockhash", async () => {
    const cases = [
      {
        client: await chain({ entriesTree: addressOf(31) }),
        table: BLOCK_ONLY,
        listId: ListId.block,
        curator: CURATOR_A,
        cause: "RING_POLICY_SOURCE_INVALID",
      },
      {
        client: await chain({ entriesTree: ENTRIES_TREE }),
        table: TABLE,
        listId: ListId.frozen,
        curator: CURATOR_A,
        cause: "RING_POLICY_SOURCE_INVALID",
      },
      {
        client: await chain({ entriesTree: ENTRIES_TREE }),
        table: BLOCK_ONLY,
        listId: ListId.block,
        curator: CURATOR_B,
        cause: "RING_POLICY_CONFIG_NOT_FOUND",
      },
    ] as const;
    for (const { client, table, listId, curator, cause } of cases) {
      await expect(
        buildRingCreatePolicyTransaction({
          client,
          ringProgramId: RING,
          payer: PAYER,
          authority: AUTHORITY,
          entriesTree: ENTRIES_TREE,
          table,
          sharedSources: [{ listId, curatorRingProgramId: curator }],
        }),
      ).rejects.toMatchObject({ code: "RING_BUILD_POLICY", causeCode: cause });
      expect(client.getLatestBlockhash).not.toHaveBeenCalled();
    }
  });

  it("set rules and set source read the ring's own tree and referenced lists", async () => {
    const client = await chain({ entriesTree: ENTRIES_TREE, own: true });
    const rules = await buildRingSetPolicyRulesTransaction({
      client,
      ringProgramId: RING,
      authority: AUTHORITY,
      table: BLOCK_ONLY,
      sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR_A }],
    });
    expect(Object.keys(rules.signatures)).toEqual([AUTHORITY]);
    const source = await buildRingSetPolicySourceTransaction({
      client,
      ringProgramId: RING,
      authority: AUTHORITY,
      listId: ListId.frozen,
      source: { kind: "own" },
    });
    expect(Object.keys(source.signatures)).toEqual([AUTHORITY]);
    await expect(
      buildRingSetPolicySourceTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        listId: ListId.block,
        source: { kind: "curator", ringProgramId: CURATOR_A },
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_POLICY_SOURCE_INVALID",
    });
  });
});
