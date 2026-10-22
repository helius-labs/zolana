import { address, blockhash, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { RpcAccount } from "../src/client/rpc.js";
import { initializePoseidon } from "../src/hasher/index.js";
import {
  ringConfigPda,
  ringMemberRegistryAddress,
  ringMemberRegistryPda,
} from "../src/interface/pda/index.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import type { RingSourceSlot } from "../src/ring/codecs.js";
import { MEMBER_REGISTRY_EMPTY_ROOT } from "../src/ring/member-registry.js";
import { LIST_IDS, ListId, buildRuleTable, type Rule } from "../src/ring/policy.js";
import {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "../src/ring/policy-admin.js";
import {
  ZERO_ADDRESS,
  memberRegistryData,
  ownedAccount,
  ringProgramConfigData,
} from "./helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR_A = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const CURATOR_B = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const LIFETIME = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 10n,
});

const RULES: readonly Rule[] = [
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [ListId.block] },
    guard: { kind: "always" },
  },
];

beforeAll(initializePoseidon);

/** The ring's registry reads allow from its own records and block from curator A. */
async function chain(input: Readonly<{ hasPolicy?: boolean }> = {}) {
  const accounts = new Map<Address, RpcAccount>();
  const [config, configBump] = await ringConfigPda(RING);
  accounts.set(
    config,
    ownedAccount(
      RING,
      ringProgramConfigData({
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey().toBytes(),
        bump: configBump,
        hasPolicy: input.hasPolicy ?? true,
      }),
    ),
  );
  const curator = await ringMemberRegistryAddress(CURATOR_A);
  const sources: RingSourceSlot[] = LIST_IDS.map((listId) =>
    listId === ListId.allow
      ? { listId, registry: ZERO_ADDRESS }
      : listId === ListId.block
        ? { listId, registry: curator }
        : { listId: 0, registry: ZERO_ADDRESS },
  );
  for (const [ring, registrySources] of [
    [RING, sources],
    [CURATOR_A, undefined],
  ] as const) {
    const [registry, bump] = await ringMemberRegistryPda(ring);
    accounts.set(
      registry,
      ownedAccount(
        ring,
        memberRegistryData({
          bump,
          history: [{ root: MEMBER_REGISTRY_EMPTY_ROOT, applied: 0n, slot: 1n }],
          nextIndex: 1,
          ...(registrySources === undefined ? {} : { sources: registrySources }),
        }),
      ),
    );
  }
  return {
    getAccount: vi.fn(async (account: Address) => accounts.get(account)),
    getLatestBlockhash: vi.fn(async () => LIFETIME),
  };
}

describe("policy transactions", () => {
  it("compiles create policy under the authority after reading the curator registry", async () => {
    const client = await chain();
    const transaction = await buildRingCreatePolicyTransaction({
      client,
      ringProgramId: RING,
      authority: AUTHORITY,
      table: buildRuleTable({ rules: RULES }),
      sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR_A }],
    });
    expect(Object.keys(transaction.signatures)).toEqual([AUTHORITY]);
    expect(client.getAccount).toHaveBeenCalledWith(
      await ringMemberRegistryAddress(CURATOR_A),
      undefined,
    );
  });

  it("refuses a curator without a registry before the blockhash", async () => {
    const client = await chain();
    await expect(
      buildRingCreatePolicyTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        table: buildRuleTable({ rules: RULES }),
        sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR_B }],
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_MEMBER_REGISTRY_MISSING",
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("refuses an audit-only ring before the curator or the blockhash", async () => {
    const client = await chain({ hasPolicy: false });
    const shared = [{ listId: ListId.block, curatorRingProgramId: CURATOR_A }];
    const table = buildRuleTable({ rules: RULES });
    for (const build of [buildRingCreatePolicyTransaction, buildRingSetPolicyRulesTransaction])
      await expect(
        build({ client, ringProgramId: RING, authority: AUTHORITY, table, sharedSources: shared }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_POLICY",
        causeCode: "RING_POLICY_TIER_MISMATCH",
      });
    expect(client.getAccount).not.toHaveBeenCalledWith(
      await ringMemberRegistryAddress(CURATOR_A),
      undefined,
    );
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("re-points a referenced list and keeps the sources to one curator", async () => {
    const client = await chain();
    const build = (
      listId: ListId,
      source: Parameters<typeof buildRingSetPolicySourceTransaction>[0]["source"],
    ) =>
      buildRingSetPolicySourceTransaction({
        client,
        ringProgramId: RING,
        authority: AUTHORITY,
        listId,
        source,
      });
    await expect(build(ListId.block, { kind: "own" })).resolves.toBeDefined();
    await expect(
      build(ListId.allow, { kind: "curator", ringProgramId: CURATOR_A }),
    ).resolves.toBeDefined();
    await expect(build(ListId.frozen, { kind: "own" })).rejects.toMatchObject({
      code: "RING_BUILD_POLICY",
      causeCode: "RING_POLICY_SOURCE_INVALID",
    });
    await expect(
      build(ListId.allow, { kind: "curator", ringProgramId: CURATOR_B }),
    ).rejects.toMatchObject({ code: "RING_BUILD_POLICY", causeCode: "RING_POLICY_SOURCE_INVALID" });
  });
});
