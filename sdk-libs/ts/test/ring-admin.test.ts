import { address, type Address, type Instruction } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes } from "../src/interface/internal.js";
import {
  protocolConfigAddress,
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { EPOCH_SLOTS } from "../src/keypair/ring-stream.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  createMemberRegistryInstruction,
  createRingConfigInstruction,
  createRingPolicyInstruction,
  initSppRingConfigInstruction,
  ringComputeUnitLimit,
  setRingAuthorityInstruction,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingInsertFeeInstruction,
  setRingPausedInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
  type RingKind,
} from "../src/ring/admin.js";
import { decodeRingProgramConfig } from "../src/ring/codecs.js";
import { ringProgramDataAddress } from "../src/ring/config.js";
import { ListId, buildRuleTable, encodeRule, type Rule } from "../src/ring/policy.js";
import {
  grantReadAccessInstruction,
  readAccessRecordAddress,
  readerKeyBytes,
  revokeReadAccessInstruction,
} from "../src/ring/reader.js";

import { solanaRpcReads } from "./helpers/clients.js";
import { ringProgramConfigData } from "./helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CURATOR = address("CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const NEXT = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2");
const MINT = address("So11111111111111111111111111111111111111112");

const READ = 0;
const WRITE = 1;
const SIGN = 2;
const SIGN_WRITE = 3;

beforeAll(initializePoseidon);

function metas(instruction: Instruction): readonly (readonly [Address, number])[] {
  return (instruction.accounts ?? []).map(({ address: account, role }) => [account, role] as const);
}

/** A client whose rent read answers `minimum` and records every space it was asked for. */
function rentClient(minimum: bigint) {
  const spaces: bigint[] = [];
  const solanaRpc = solanaRpcReads({
    getMinimumBalanceForRentExemption: (space: bigint) => ({
      send: async () => {
        spaces.push(space);
        return minimum;
      },
    }),
  });
  return { client: { solanaRpc }, spaces };
}

function u64le(value: bigint): number[] {
  return Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(8 * index)) & 0xffn));
}

const RULES: readonly Rule[] = [
  {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [ListId.block] },
    guard: { kind: "always" },
  },
];

describe("ring setup", () => {
  it.each<readonly [RingKind, number]>([
    ["auditOnly", 0],
    ["policy", 1],
    ["anonymous", 2],
    ["anonymousPolicy", 3],
  ])("creates the config under the upgrade authority with the %s kind byte", async (kind, byte) => {
    const auditor = X25519Keypair.generate().publicKey();
    const instruction = await createRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      auditorPublicKey: auditor,
      kind,
    });
    expect(instruction.programAddress).toBe(RING);
    expect(instruction.data).toEqual(Uint8Array.of(1, ...auditor.toBytes(), byte));
    expect(metas(instruction)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), WRITE],
      [SYSTEM_PROGRAM, READ],
      [RING, READ],
      [await ringProgramDataAddress(RING), READ],
    ]);
  });

  it("refuses a kind the program does not know", async () => {
    await expect(
      createRingConfigInstruction({
        ringProgramId: RING,
        payer: PAYER,
        authority: AUTHORITY,
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        kind: "registry" as RingKind,
      }),
    ).rejects.toMatchObject({ code: "RING_CONFIG_INVALID", details: { reason: "kind" } });
  });

  it("registers with the pool, a policy ring naming its registry", async () => {
    const policy = await initSppRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      hasPolicy: true,
    });
    const auditOnly = await initSppRingConfigInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      hasPolicy: false,
    });
    const head = [
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await protocolConfigAddress(), READ],
      [await ringAuthAddress(RING), WRITE],
      [SYSTEM_PROGRAM, READ],
      [SHIELDED_POOL_PROGRAM_ID, READ],
    ];
    expect(policy.data).toEqual(Uint8Array.of(2));
    expect(metas(policy)).toEqual([...head, [await ringMemberRegistryAddress(RING), READ]]);
    expect(metas(auditOnly)).toEqual(head);
  });

  it("creates the registry and the queue beside a read-only config", async () => {
    const instruction = await createMemberRegistryInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
    });
    expect(instruction.data).toEqual(Uint8Array.of(28));
    expect(metas(instruction)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringMemberRegistryAddress(RING), WRITE],
      [await ringRecordQueueAddress(RING), WRITE],
      [SYSTEM_PROGRAM, READ],
    ]);
  });
});

describe("config account", () => {
  const MODE_OFFSET = 68;
  const CREATED_SLOT_OFFSET = 463;
  const account = () =>
    ringProgramConfigData({
      authority: AUTHORITY,
      auditorPublicKey: X25519Keypair.fromBytes(new Uint8Array(32).fill(9)).publicKey().toBytes(),
      bump: 254,
      hasPolicy: false,
    });

  it("reads the created slot after the delegate and the epoch a restore scans from", () => {
    const data = account();
    const slot = 3n * EPOCH_SLOTS + 7n;
    data.set(u64le(slot), CREATED_SLOT_OFFSET);
    expect(data).toHaveLength(471);
    expect(decodeRingProgramConfig(data)).toMatchObject({ createdSlot: slot, creationEpoch: 3n });
  });

  it("refuses the layout without a created slot and an unknown mode like Rust `InvalidRingMode`", () => {
    const data = account();
    expect(() => decodeRingProgramConfig(data.subarray(0, CREATED_SLOT_OFFSET))).toThrow(
      expect.objectContaining({
        code: "RING_CONFIG_INVALID",
        details: { length: CREATED_SLOT_OFFSET, discriminator: 10 },
      }),
    );
    data[MODE_OFFSET] = 3;
    expect(() => decodeRingProgramConfig(data)).toThrow(
      expect.objectContaining({
        code: "RING_CONFIG_INVALID",
        details: expect.objectContaining({ mode: 3 }),
      }),
    );
  });
});

describe("config writes", () => {
  it("hands the authority over only with both signatures", async () => {
    const instruction = await setRingAuthorityInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      newAuthority: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(6));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [NEXT, SIGN],
      [await ringConfigAddress(RING), WRITE],
    ]);
  });

  it("pauses through the pool's ring config", async () => {
    const instruction = await setRingPausedInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      paused: true,
    });
    expect(instruction.data).toEqual(Uint8Array.of(11, 1));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringAuthAddress(RING), WRITE],
      [SHIELDED_POOL_PROGRAM_ID, READ],
    ]);
  });

  it("writes the co-signer, its clearing and the insert fee into the config", async () => {
    const config = await ringConfigAddress(RING);
    const cosigner = await setRingCoSignerInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      signer: NEXT,
      scope: 5,
      thresholds: [{ mint: MINT, amount: 9n }],
    });
    expect(cosigner.data).toEqual(
      Uint8Array.of(27, ...addressBytes(NEXT), 5, 1, ...addressBytes(MINT), ...u64le(9n)),
    );
    const clear = await clearRingCoSignerInstruction({ ringProgramId: RING, authority: AUTHORITY });
    expect(clear.data).toEqual(Uint8Array.of(21));
    const fee = await setRingInsertFeeInstruction({
      client: rentClient(890_880n).client,
      ringProgramId: RING,
      authority: AUTHORITY,
      fee: 1_000_000n,
    });
    expect(fee.data).toEqual(Uint8Array.of(42, ...u64le(1_000_000n)));
    for (const instruction of [cosigner, clear, fee])
      expect(metas(instruction)).toEqual([
        [AUTHORITY, SIGN],
        [config, WRITE],
      ]);
  });

  it("refuses a nonzero insert fee below the rent of an empty account and reads no rent for a free write", async () => {
    const write = (fee: bigint, rent: ReturnType<typeof rentClient>) =>
      setRingInsertFeeInstruction({
        client: rent.client,
        ringProgramId: RING,
        authority: AUTHORITY,
        fee,
      });
    const floor = rentClient(890_880n);
    await expect(write(890_879n, floor)).rejects.toMatchObject({
      code: "RING_CONFIG_INVALID",
      details: { reason: "InsertFeeBelowRent", fee: "890879", minimum: "890880" },
    });
    expect((await write(890_880n, floor)).data).toEqual(Uint8Array.of(42, ...u64le(890_880n)));
    expect(floor.spaces).toEqual([0n, 0n]);
    const free = rentClient(890_880n);
    expect((await write(0n, free)).data).toEqual(Uint8Array.of(42, ...u64le(0n)));
    expect(free.spaces).toEqual([]);
  });

  it.each([
    ["a zero signer", { signer: address("11111111111111111111111111111111") }, "InvalidCoSigner"],
    ["an empty scope", { scope: 0 }, "InvalidCoSignerScope"],
    ["an unknown scope bit", { scope: 8 }, "InvalidCoSignerScope"],
    [
      "a repeated mint",
      {
        thresholds: [
          { mint: MINT, amount: 1n },
          { mint: MINT, amount: 2n },
        ],
      },
      "InvalidCoSignerThresholds",
    ],
    [
      "thresholds outside the withdrawal scope",
      { scope: 3, thresholds: [{ mint: MINT, amount: 1n }] },
      "ThresholdsWithoutWithdrawals",
    ],
  ] as const)("refuses a co-signer with %s", async (_case, change, reason) => {
    await expect(
      setRingCoSignerInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        signer: NEXT,
        scope: 1,
        ...change,
      }),
    ).rejects.toMatchObject({ code: "RING_CO_SIGNER_INVALID", details: { reason } });
  });

  it("appoints the delegate under the upgrade authority with the delegate signing", async () => {
    const instruction = await setRingDelegateInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      delegate: NEXT,
    });
    expect(instruction.data).toEqual(Uint8Array.of(24));
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), WRITE],
      [NEXT, SIGN],
      [await ringMemberRegistryAddress(RING), READ],
      [RING, READ],
      [await ringProgramDataAddress(RING), READ],
    ]);
  });

  it("grants and revokes a reader with its tagged key", async () => {
    const reader = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(3) as Bytes32),
    )
      .shieldedAddress()
      .solanaAddress();
    const record = await readAccessRecordAddress(RING, reader);
    const grant = await grantReadAccessInstruction({
      ringProgramId: RING,
      payer: PAYER,
      authority: AUTHORITY,
      reader,
    });
    const revoke = await revokeReadAccessInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      reader,
      rentRecipient: PAYER,
    });
    expect(grant.data).toEqual(Uint8Array.of(4, ...readerKeyBytes(reader)));
    expect(revoke.data).toEqual(Uint8Array.of(5, ...readerKeyBytes(reader)));
    expect(metas(grant)).toEqual([
      [PAYER, SIGN_WRITE],
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [record, WRITE],
      [SYSTEM_PROGRAM, READ],
    ]);
    expect(metas(revoke)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [record, WRITE],
      [PAYER, WRITE],
    ]);
  });
});

describe("policy writes", () => {
  it("pins the table with one source per referenced list and the curator registry after", async () => {
    const table = buildRuleTable({ rules: RULES });
    const [rule] = table.rules;
    if (rule === undefined) throw new Error("table without its rule");
    const instruction = await createRingPolicyInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      table,
      sharedSources: [{ listId: ListId.block, curatorRingProgramId: CURATOR }],
    });
    expect(instruction.data).toEqual(
      Uint8Array.of(7, 2, ListId.allow, 0, ListId.block, 1, 1, ...encodeRule(rule), 0, 0, 0),
    );
    expect(metas(instruction)).toEqual([
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringMemberRegistryAddress(RING), WRITE],
      [await ringMemberRegistryAddress(CURATOR), READ],
    ]);
    const rules = await setRingPolicyRulesInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      table,
    });
    expect(rules.data?.[0]).toBe(12);
    expect(metas(rules)).toHaveLength(3);
  });

  it.each([
    [
      "a list the table does not reference",
      [{ listId: ListId.frozen, curatorRingProgramId: CURATOR }],
      "UnreferencedList",
    ],
    [
      "a list shared twice",
      [
        { listId: ListId.block, curatorRingProgramId: CURATOR },
        { listId: ListId.block, curatorRingProgramId: CURATOR },
      ],
      "DuplicateList",
    ],
    [
      "two curators",
      [
        { listId: ListId.allow, curatorRingProgramId: CURATOR },
        { listId: ListId.block, curatorRingProgramId: NEXT },
      ],
      "MultipleCurators",
    ],
    [
      "the ring as its own curator",
      [{ listId: ListId.block, curatorRingProgramId: RING }],
      "OwnCurator",
    ],
  ] as const)("refuses %s", async (_case, sharedSources, reason) => {
    await expect(
      createRingPolicyInstruction({
        ringProgramId: RING,
        authority: AUTHORITY,
        table: buildRuleTable({ rules: RULES }),
        sharedSources,
      }),
    ).rejects.toMatchObject({ code: "RING_POLICY_SOURCE_INVALID", details: { reason } });
  });

  it.each([ListId.ringViewing, ListId.recovery, ListId.escrow])(
    "refuses a rule over list %i its members write, like Rust `EncodedRuleTable::validate`",
    async (listId) => {
      const required: Rule = {
        subject: "outputOwner",
        source: { kind: "lists", present: [listId], absent: [] },
        guard: { kind: "always" },
      };
      const alternative: Rule = {
        subject: "sender",
        source: { kind: "lists", present: [ListId.allow], absent: [listId] },
        guard: { kind: "always" },
      };
      for (const rule of [required, alternative])
        for (const write of [createRingPolicyInstruction, setRingPolicyRulesInstruction])
          await expect(
            write({
              ringProgramId: RING,
              authority: AUTHORITY,
              table: buildRuleTable({ rules: [rule] }),
            }),
          ).rejects.toMatchObject({
            code: "RING_RULE_TABLE_INVALID",
            details: { reason: "MemberWrittenList" },
          });
    },
  );

  it("re-points one list at a curator or back at the ring", async () => {
    const curator = await setRingPolicySourceInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      listId: ListId.block,
      source: { kind: "curator", ringProgramId: CURATOR },
    });
    const own = await setRingPolicySourceInstruction({
      ringProgramId: RING,
      authority: AUTHORITY,
      listId: ListId.block,
      source: { kind: "own" },
    });
    const head = [
      [AUTHORITY, SIGN],
      [await ringConfigAddress(RING), READ],
      [await ringMemberRegistryAddress(RING), WRITE],
    ];
    expect(curator.data).toEqual(Uint8Array.of(10, ListId.block, 1));
    expect(metas(curator)).toEqual([...head, [await ringMemberRegistryAddress(CURATOR), READ]]);
    expect(own.data).toEqual(Uint8Array.of(10, ListId.block, 0));
    expect(metas(own)).toEqual(head);
  });

  it("budgets each instruction like Rust `compute_unit_limit`", () => {
    expect(ringComputeUnitLimit(RingInstructionTag.createPolicy)).toBe(150_000);
    expect(ringComputeUnitLimit(RingInstructionTag.registerKey)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.applyRecords)).toBe(1_400_000);
    expect(ringComputeUnitLimit(RingInstructionTag.deposit)).toBe(200_000);
    expect(ringComputeUnitLimit(RingInstructionTag.setInsertFee)).toBe(50_000);
  });
});
