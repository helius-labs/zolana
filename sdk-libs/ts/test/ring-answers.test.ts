import { getAddressDecoder } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initializePoseidon } from "../src/hasher/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { ringMemberRegistryRootPda, treeAddress } from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  provePolicyAnswers,
  type PolicyAnswerInput,
  type RingPolicyAnswerClient,
} from "../src/ring/answers.js";
import {
  ListId,
  buildRuleTable,
  memberOfIdentity,
  memberOfAsset,
  type Rule,
  type RuleTable,
} from "../src/ring/policy.js";
import { createProofOutput, type ProofOutputUtxo } from "../src/transaction/utxo.js";
import { ownSources, ringPolicyConfig, ownedAccount } from "./helpers/ring-accounts.js";
import { registryFixture, memberRegistryRootData } from "./helpers/member-registry.js";
import { treeAccount } from "./helpers/tree-account.js";

const filled = (byte: number) => new Uint8Array(32).fill(byte) as Bytes32;
const address = (byte: number) => getAddressDecoder().decode(filled(byte));
const RING = address(2),
  TREE = treeAddress(0),
  ASSET = address(9);
beforeAll(initializePoseidon);
const requireList = (id: ListId): Rule => ({
  subject: "outputOwner",
  source: { kind: "lists", present: [id], absent: [] },
  guard: { kind: "always" },
});
const forbid = (id: ListId): Rule => ({
  ...requireList(id),
  source: { kind: "lists", present: [], absent: [id] },
});
const inline: Rule = {
  subject: "asset",
  source: { kind: "lists", present: [ListId.allow], absent: [] },
  guard: { kind: "always" },
};
function output(amount = 1n, asset = ASSET): ProofOutputUtxo {
  return createProofOutput({
    ownerAddress: ShieldedKeypair.generate().shieldedAddress(),
    asset,
    amount,
    blinding: filled(1),
  });
}
const member = (out: ProofOutputUtxo) => {
  if (out.ownerAddress === undefined) throw new Error("missing owner");
  return memberOfIdentity(out.ownerAddress.signingPublicKey.ownerProofInputHash());
};
async function fixture(
  table: RuleTable,
  outputs: readonly ProofOutputUtxo[],
  lists = 0n,
  assetLists = 1n,
) {
  const [root, bump] = await ringMemberRegistryRootPda(RING);
  const unique = new Map(
    outputs.map((out) => [Buffer.from(member(out)).toString("hex"), member(out)]),
  );
  const assets = new Map(
    outputs.map((out) => [
      Buffer.from(memberOfAsset(out.asset)).toString("hex"),
      memberOfAsset(out.asset),
    ]),
  );
  const registry = registryFixture([
    ...[...unique.values()].map((member) => ({ member, lists })),
    ...(table.rules.some((rule) => rule.subject === "asset")
      ? [...assets.values()].map((member) => ({ member, lists: assetLists }))
      : []),
  ]);
  const read = vi.fn(
    async (request: Parameters<RingPolicyAnswerClient["getRingMemberRecord"]>[0]) =>
      registry.read(request.member),
  );
  const client: RingPolicyAnswerClient = {
    getRingMemberRecord: read,
    getAccount: async (key) =>
      key === root
        ? ownedAccount(
            RING,
            memberRegistryRootData({
              root: registry.root,
              nextIndex: registry.tip.nextIndex,
              bump,
            }),
          )
        : key === TREE
          ? ownedAccount(
              SHIELDED_POOL_PROGRAM_ID,
              treeAccount({ stateCursor: 0, written: 1, nullifierCursor: 0n }),
            )
          : undefined,
  };
  const input: PolicyAnswerInput = {
    ringProgramId: RING,
    keyEscrow: false,
    proofDataSource: "client",
    table,
    config: ringPolicyConfig({ table, sources: ownSources(table, RING), addressTree: TREE }),
    inputs: [],
    outputs,
  };
  return {
    input,
    client,
    read,
    registry,
    prove: (changes: Partial<PolicyAnswerInput> = {}) =>
      provePolicyAnswers({ ...input, ...changes, client }),
  };
}
describe("member policy witnesses", () => {
  it("reads list bits from the configured curator and rejects a substituted registry owner", async () => {
    const out = output(),
      test = await fixture(buildRuleTable({ rules: [requireList(ListId.allow)] }), [out]);
    const curator = address(6),
      [root, bump] = await ringMemberRegistryRootPda(curator);
    const foreign = registryFixture([{ member: member(out), lists: 1n }]);
    const config = {
      ...test.input.config,
      sources: test.input.config.sources.map((slot) =>
        slot.listId === ListId.allow ? { ...slot, registry: root } : slot,
      ),
    };
    const getAccount = test.client.getAccount;
    const client = {
      ...test.client,
      getAccount: async (key: typeof root) =>
        key === root
          ? ownedAccount(curator, memberRegistryRootData({ ...foreign.tip, bump }))
          : getAccount(key),
      getRingMemberRecord: vi.fn(
        async (request: Parameters<RingPolicyAnswerClient["getRingMemberRecord"]>[0]) =>
          (request.ringProgramId === curator ? foreign : test.registry).read(request.member),
      ),
    };
    const result = await provePolicyAnswers({ ...test.input, config, client });
    expect(result.subjects[5]?.lists).toBe(0n);
    expect(result.foreignSubjects[5]?.lists).toBe(1n);
    expect(result.foreign?.indexed.root).toEqual(foreign.root);
    expect(client.getRingMemberRecord).toHaveBeenCalledTimes(2);
    client.getRingMemberRecord.mockClear();
    await expect(
      provePolicyAnswers({
        ...test.input,
        config,
        client: {
          ...client,
          getAccount: async (key) =>
            key === root
              ? ownedAccount(RING, memberRegistryRootData({ ...foreign.tip, bump }))
              : getAccount(key),
        },
      }),
    ).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID" });
    expect(client.getRingMemberRecord).not.toHaveBeenCalled();
  });

  it("screens authenticated mint records independently of approved owners", async () => {
    const table = buildRuleTable({ rules: [inline] });
    const out = output();
    const allowed = await fixture(table, [out, out], 0n, 1n);
    const answers = await allowed.prove();
    expect(answers.subjects[9]?.lists).toBe(1n);
    expect(answers.subjects[9]).toEqual(answers.subjects[10]);
    expect(allowed.read).toHaveBeenCalledTimes(2);
    await expect((await fixture(table, [out], 1n, 0n)).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
    allowed.read.mockImplementation(async () => allowed.registry.read(member(out)));
    await expect(allowed.prove()).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID" });
  });
  it("supports asset blocklists and rejects mixed mints under a scalar owner guard", async () => {
    const table = buildRuleTable({ rules: [{ ...forbid(ListId.block), subject: "asset" }] });
    await expect((await fixture(table, [output()], 0n, 0n)).prove()).resolves.toBeDefined();
    await expect((await fixture(table, [output()], 0n, 2n)).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
    const guard = buildRuleTable({
      rules: [{ ...requireList(ListId.allow), guard: { kind: "aboveAmount", amount: 5n } }],
    });
    await expect(
      (await fixture(guard, [output(1n), output(1n, address(8))], 1n)).prove(),
    ).rejects.toMatchObject({ code: "RING_POLICY_RULE_UNSATISFIED" });
  });
  it("deduplicates a recipient while filling both output slots", async () => {
    const out = output(),
      test = await fixture(buildRuleTable({ rules: [requireList(ListId.allow)] }), [out, out], 1n);
    const result = await test.prove();
    expect(test.read).toHaveBeenCalledTimes(1);
    expect(result.subjects).toHaveLength(13);
    expect(result.subjects[5]).toEqual(result.subjects[6]);
    expect(result.subjects[5]?.lists).toBe(1n);
    expect(result.registry.root).toEqual(test.registry.root);
  });
  it("refuses an unlisted recipient", async () => {
    const test = await fixture(buildRuleTable({ rules: [requireList(ListId.allow)] }), [output()]);
    await expect(test.prove()).rejects.toMatchObject({ code: "RING_POLICY_RULE_UNSATISFIED" });
  });
  it("allows a blocked member only through an approval alternative", async () => {
    const rule: Rule = {
      ...requireList(ListId.approval),
      source: { kind: "lists", present: [ListId.approval], absent: [ListId.block] },
    };
    const table = buildRuleTable({ rules: [rule] });
    await expect((await fixture(table, [output()], 2n | 64n)).prove()).resolves.toBeDefined();
    await expect((await fixture(table, [output()], 2n)).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
  });
  it("proves absence using the authenticated predecessor", async () => {
    const test = await fixture(buildRuleTable({ rules: [forbid(ListId.block)] }), [output()]);
    const empty = registryFixture();
    const [root, bump] = await ringMemberRegistryRootPda(RING);
    const account = test.client.getAccount;
    test.client.getAccount = async (key) =>
      key === root
        ? ownedAccount(RING, memberRegistryRootData({ root: empty.root, nextIndex: 1n, bump }))
        : account(key);
    test.read.mockImplementation(async (request) => empty.read(request.member));
    expect((await test.prove()).subjects[5]?.present).toBe(false);
  });
  it("treats cleared list bits as absence in a present record", async () => {
    const test = await fixture(buildRuleTable({ rules: [forbid(ListId.block)] }), [output()], 1n);
    expect((await test.prove()).subjects[5]).toMatchObject({ present: true, lists: 1n });
  });
  it("aggregates guarded amounts across recipient outputs", async () => {
    const out = output(3n),
      table = buildRuleTable({
        rules: [{ ...requireList(ListId.allow), guard: { kind: "aboveAmount", amount: 5n } }],
      });
    await expect((await fixture(table, [out])).prove()).resolves.toBeDefined();
    await expect((await fixture(table, [out, out])).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
  });
  it("does not overflow guarded totals above u64", async () => {
    const out = output((1n << 64n) - 1n),
      table = buildRuleTable({
        rules: [
          {
            ...requireList(ListId.allow),
            guard: { kind: "aboveAmount", amount: (1n << 64n) - 1n },
          },
        ],
      });
    await expect((await fixture(table, [out, out])).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
  });
  it("applies per-asset thresholds and refuses unknown mints", async () => {
    const table = buildRuleTable({
      rules: [{ ...requireList(ListId.allow), guard: { kind: "aboveAmountByAsset" } }],
      inlineAssets: [memberOfAsset(ASSET)],
      inlineLimits: [5n],
    });
    await expect((await fixture(table, [output(5n)])).prove()).resolves.toBeDefined();
    await expect((await fixture(table, [output(6n)])).prove()).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
    await expect((await fixture(table, [output(1n, address(8))])).prove()).rejects.toBeDefined();
  });
  it("rejects a sender guard at table construction", () =>
    expect(() =>
      buildRuleTable({
        rules: [
          {
            ...requireList(ListId.allow),
            subject: "sender",
            guard: { kind: "aboveAmount", amount: 1n },
          },
        ],
      }),
    ).toThrow());
  it("rejects too many output slots", async () => {
    const test = await fixture(buildRuleTable({ rules: [] }), [output()]);
    await expect(
      test.prove({ outputs: Array.from({ length: 5 }, () => output()) }),
    ).rejects.toMatchObject({ code: "RING_POLICY_SHAPE_UNSUPPORTED" });
  });
  it("binds indexed policy requests without fetching records", async () => {
    const test = await fixture(buildRuleTable({ rules: [] }), [output()]);
    const result = await test.prove({ proofDataSource: "prover" });
    expect(test.read).not.toHaveBeenCalled();
    expect(result.subjects.every((value) => value === undefined)).toBe(true);
    expect(result.treeSlots).toHaveLength(1);
  });
  it("rejects truncated, foreign and tampered record paths", async () => {
    for (const change of ["path", "member", "lists"]) {
      const test = await fixture(buildRuleTable({ rules: [] }), [output()]);
      test.read.mockImplementation(async (request) => {
        const row = test.registry.read(request.member);
        return {
          ...row,
          path: change === "path" ? row.path.slice(1) : row.path,
          record:
            row.record === null
              ? null
              : {
                  ...row.record,
                  ...(change === "member"
                    ? { member: filled(3) }
                    : change === "lists"
                      ? { lists: 9n }
                      : {}),
                },
        };
      });
      await expect(test.prove()).rejects.toMatchObject({ code: "RING_MEMBER_REGISTRY_INVALID" });
    }
  });
  it("rejects a missing or foreign address-tree account", async () => {
    for (const foreign of [false, true]) {
      const test = await fixture(buildRuleTable({ rules: [] }), [output()]);
      const read = test.client.getAccount;
      test.client.getAccount = async (key) =>
        key === TREE ? (foreign ? ownedAccount(RING, new Uint8Array()) : undefined) : read(key);
      await expect(test.prove()).rejects.toMatchObject({ code: "RING_POLICY_TREE_INVALID" });
    }
  });
  it("refuses escrow without a sealed key", async () => {
    const test = await fixture(buildRuleTable({ rules: [] }), [output()]);
    await expect(test.prove({ keyEscrow: true })).rejects.toMatchObject({
      code: "RING_UNREGISTERED_OUTPUT_KEY",
    });
  });
});
