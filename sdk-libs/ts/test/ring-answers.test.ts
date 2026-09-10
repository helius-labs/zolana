import { getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import type { ShieldedAddress } from "../src/keypair/shielded.js";
import { planPolicyAnswers, provePolicyAnswers } from "../src/ring/answers.js";
import {
  ListId,
  RingListNamespace,
  buildRuleTable,
  memberOfAsset,
  memberOfTag,
  type Member,
  type Rule,
  type RuleTable,
} from "../src/ring/policy.js";
import {
  ProofInputUtxo,
  Utxo,
  createProofOutput,
  type ProofOutputUtxo,
} from "../src/transaction/utxo.js";

import { ownSources, ringPolicyConfig } from "./helpers/ring-accounts.js";
import { FIXTURE_HEADS, entryProofReads, lineage } from "./helpers/ring-entries.js";

await initializePoseidon();

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (byte: number): Address => getAddressDecoder().decode(filled(byte));
const TREE = addressOf(0x30);
const NAMESPACE = addressOf(0x11);
const ASSET = addressOf(9);
const ASSET_MEMBER = memberOfAsset(ASSET);

function recipient(): Readonly<{ member: Member; address: ShieldedAddress }> {
  const address = ShieldedKeypair.generate().shieldedAddress();
  return { member: memberOfTag(address.confidentialViewTag()), address };
}

function output(address: ShieldedAddress, amount: bigint, asset = ASSET): ProofOutputUtxo {
  return createProofOutput({ ownerAddress: address, asset, amount, blinding: filled(1) });
}

const require = (subject: Rule["subject"], id: ListId): Rule => ({
  subject,
  source: { kind: "lists", present: [id], absent: [] },
  guard: { kind: "always" },
});
const forbid = (subject: Rule["subject"], id: ListId): Rule => ({
  subject,
  source: { kind: "lists", present: [], absent: [id] },
  guard: { kind: "always" },
});
const above = (rule: Rule, amount: bigint): Rule => ({
  ...rule,
  guard: { kind: "aboveAmount", amount },
});
const ALLOW_ONLY_ASSETS: Rule = {
  subject: "asset",
  source: { kind: "inlineAssets" },
  guard: { kind: "always" },
};

const EMPTY = buildRuleTable({ rules: [] });
const TWO_ALLOW = buildRuleTable({
  rules: [
    require("outputOwner", ListId.allow),
    {
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.allow, ListId.block], absent: [] },
      guard: { kind: "always" },
    },
  ],
});
/** An owner guard needs a single unguarded inline asset beside it. */
const GUARDED = buildRuleTable({
  rules: [above(require("outputOwner", ListId.allow), 5n), ALLOW_ONLY_ASSETS],
  inlineAssets: [ASSET_MEMBER],
});
const BLOCK = buildRuleTable({ rules: [forbid("outputOwner", ListId.block)] });
/** An approval overrides a block. */
const MIXED = buildRuleTable({
  rules: [
    {
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.approval], absent: [ListId.block] },
      guard: { kind: "always" },
    },
    ALLOW_ONLY_ASSETS,
  ],
  inlineAssets: [ASSET_MEMBER],
});

function input(
  table: RuleTable,
  outputs: readonly ProofOutputUtxo[],
  namespace = NAMESPACE,
): Parameters<typeof planPolicyAnswers>[0] {
  const config = ringPolicyConfig({
    table,
    sources: ownSources(table, namespace),
    entriesTree: TREE,
  });
  return { table, config, inputs: [], outputs };
}

const HEADS = FIXTURE_HEADS;

describe("answer planning", () => {
  it("list-backed asset rules name each live output asset", () => {
    const { address } = recipient();
    const table: RuleTable = {
      rules: [require("asset", ListId.allow)],
      inlineAssets: [],
      inlineLimits: [],
    };
    const plan = planPolicyAnswers(input(table, [output(address, 1n)]));
    expect(plan.lookups).toEqual([
      { namespace: NAMESPACE, listId: ListId.allow, member: ASSET_MEMBER },
    ]);
    expect(plan.demands).toHaveLength(1);
  });

  it("a guarded rule exempts a recipient only below the aggregated threshold", () => {
    const { address } = recipient();
    const guarded = buildRuleTable({
      rules: [above(require("outputOwner", ListId.allow), 2000n), ALLOW_ONLY_ASSETS],
      inlineAssets: [ASSET_MEMBER],
    });
    expect(
      planPolicyAnswers(input(guarded, [output(address, 1000n), output(address, 1500n)])).demands,
    ).toHaveLength(2);
    expect(planPolicyAnswers(input(guarded, [output(address, 1000n)])).demands).toHaveLength(0);
    const unguarded = buildRuleTable({ rules: [require("outputOwner", ListId.allow)] });
    expect(planPolicyAnswers(input(unguarded, [output(address, 1000n)])).demands).toHaveLength(1);
  });

  it("the guard sums exactly past the u64 range", () => {
    const { address } = recipient();
    const other = recipient();
    const max = (1n << 64n) - 1n;
    const guarded = buildRuleTable({
      rules: [above(require("outputOwner", ListId.allow), max), ALLOW_ONLY_ASSETS],
      inlineAssets: [ASSET_MEMBER],
    });
    expect(
      planPolicyAnswers(input(guarded, [output(address, max), output(address, 1n)])).demands,
    ).toHaveLength(2);
    expect(
      planPolicyAnswers(input(guarded, [output(address, max), output(other.address, 1n)])).demands,
    ).toHaveLength(0);
  });

  it("per-asset guard uses each mint limit and rejects an unknown mint", () => {
    const { address } = recipient();
    const first = addressOf(8);
    const second = addressOf(9);
    const table = buildRuleTable({
      rules: [{ ...require("outputOwner", ListId.allow), guard: { kind: "aboveAmountByAsset" } }],
      inlineAssets: [memberOfAsset(first), memberOfAsset(second)],
      inlineLimits: [10n, 20n],
    });
    const below = [
      output(address, 4n, first),
      output(address, 6n, first),
      output(address, 20n, second),
    ];
    expect(planPolicyAnswers(input(table, below)).demands).toHaveLength(0);
    expect(planPolicyAnswers(input(table, [output(address, 11n, first)])).demands).toHaveLength(1);
    expect(() => planPolicyAnswers(input(table, [output(address, 1n, addressOf(7))]))).toThrow(
      expect.objectContaining({ code: "RING_POLICY_ASSET_UNSUPPORTED" }),
    );
  });

  it("a sender guard never exempts", () => {
    const keypair = ShieldedKeypair.generate();
    const spend = new ProofInputUtxo({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: ASSET,
        amount: 7n,
        blinding: filled(1),
      }),
      nullifierKey: keypair.nullifierKey(),
    });
    const config = ringPolicyConfig({
      table: buildRuleTable({ rules: [require("sender", ListId.allow)] }),
      sources: ownSources(buildRuleTable({ rules: [require("sender", ListId.allow)] }), NAMESPACE),
      entriesTree: TREE,
    });
    const guarded: RuleTable = {
      rules: [above(require("sender", ListId.allow), (1n << 64n) - 1n)],
      inlineAssets: [],
      inlineLimits: [],
    };
    const plan = planPolicyAnswers({ table: guarded, config, inputs: [spend], outputs: [] });
    expect(plan.demands).toHaveLength(1);
    expect(plan.lookups[0]?.member).toEqual(
      memberOfTag(keypair.signingPublicKey().confidentialViewTag()),
    );
  });

  it("refuses a shape past the policy openings", () => {
    const { address } = recipient();
    expect(() =>
      planPolicyAnswers(
        input(
          EMPTY,
          Array.from({ length: 5 }, () => output(address, 1n)),
        ),
      ),
    ).toThrow(expect.objectContaining({ code: "RING_POLICY_SHAPE_UNSUPPORTED" }));
  });
});

describe("answer proving", () => {
  it("two outputs to one recipient under two rules consult the pair once", async () => {
    const { member, address } = recipient();
    const allow = lineage({
      namespace: NAMESPACE,
      tree: TREE,
      listId: ListId.allow,
      member,
      states: ["active"],
    });
    const client = entryProofReads({ tree: TREE, spenders: allow.spenders });
    const { answers, roots } = await provePolicyAnswers({
      client,
      ...input(TWO_ALLOW, [output(address, 10n), output(address, 20n)]),
    });
    expect(client.merkle).toEqual([[allow.utxoHash]]);
    expect(client.nonInclusion).toEqual([[allow.nullifier]]);
    expect(client.accounts).toBe(0);
    // The claim round asks for both group addresses, the Allow lineage one more round.
    expect(client.requests).toHaveLength(2);
    expect(client.requests[0]).toHaveLength(2);
    expect(client.requests[1]).toEqual([allow.nullifier]);
    const enabled = answers.filter((answer) => answer.enabled);
    expect(enabled).toHaveLength(1);
    expect(enabled[0]).toMatchObject({ member, absentBranch: 2, mode: 1, listId: ListId.allow });
    expect(answers).toHaveLength(10);
    expect(roots).toEqual({
      stateRoot: filled(1),
      stateRootIndex: 3,
      nullifierRoot: filled(2),
      nullifierRootIndex: 4,
    });
  });

  it("a guard-exempt subject triggers no request", async () => {
    const { address } = recipient();
    const client = entryProofReads({ tree: TREE, account: true });
    const { answers, roots } = await provePolicyAnswers({
      client,
      ...input(GUARDED, [output(address, 1n)]),
    });
    expect(client.requests).toHaveLength(0);
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toHaveLength(0);
    expect(answers.every((answer) => !answer.enabled)).toBe(true);
    expect(roots).toEqual(HEADS);
  });

  it("a missing entry refuses the transfer before any proof call", async () => {
    const { address } = recipient();
    const client = entryProofReads({ tree: TREE });
    await expect(
      provePolicyAnswers({ client, ...input(TWO_ALLOW, [output(address, 1n)]) }),
    ).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toHaveLength(0);
  });

  it("responses with two roots are refused", async () => {
    const first = recipient();
    const second = recipient();
    const client = entryProofReads({
      tree: TREE,
      spenders: [
        ...lineage({
          namespace: NAMESPACE,
          tree: TREE,
          listId: ListId.allow,
          member: first.member,
          states: ["active"],
        }).spenders,
        ...lineage({
          namespace: NAMESPACE,
          tree: TREE,
          listId: ListId.allow,
          member: second.member,
          states: ["active"],
        }).spenders,
      ],
      stateRoots: [
        { value: filled(1), index: 3 },
        { value: filled(5), index: 5 },
      ],
    });
    await expect(
      provePolicyAnswers({
        client,
        ...input(TWO_ALLOW, [output(first.address, 1n), output(second.address, 1n)]),
      }),
    ).rejects.toMatchObject({ code: "RING_POLICY_ROOT_MISMATCH" });
  });

  it("unclaimed answers take the state root from the tree account", async () => {
    const { member, address } = recipient();
    const client = entryProofReads({ tree: TREE, account: true });
    const { answers, roots } = await provePolicyAnswers({
      client,
      ...input(BLOCK, [output(address, 1n)]),
    });
    expect(roots).toEqual({ ...HEADS, nullifierRoot: filled(2), nullifierRootIndex: 4 });
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toEqual([
      [RingListNamespace.of(NAMESPACE, 0).entryAddress({ listId: ListId.block, member })],
    ]);
    expect(client.accounts).toBe(1);
    expect(answers[0]).toMatchObject({
      enabled: true,
      absentBranch: 1,
      mode: 2,
      listId: ListId.block,
    });
  });

  it("a table without answers reads both roots from the tree account", async () => {
    const client = entryProofReads({ tree: TREE, account: true });
    const { roots } = await provePolicyAnswers({ client, ...input(EMPTY, []) });
    expect(roots).toEqual(HEADS);
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toHaveLength(0);
    expect(client.accounts).toBe(1);
  });

  it("a blocked member passes through its approval", async () => {
    const { member, address } = recipient();
    const approved = lineage({
      namespace: NAMESPACE,
      tree: TREE,
      listId: ListId.approval,
      member,
      states: ["active"],
    });
    const blocked = lineage({
      namespace: NAMESPACE,
      tree: TREE,
      listId: ListId.block,
      member,
      states: ["active"],
    });
    const client = entryProofReads({
      tree: TREE,
      spenders: [...approved.spenders, ...blocked.spenders],
    });
    const { answers } = await provePolicyAnswers({
      client,
      ...input(MIXED, [output(address, 1n)]),
    });
    const enabled = answers.filter((answer) => answer.enabled);
    expect(enabled).toHaveLength(1);
    expect(enabled[0]).toMatchObject({
      listId: ListId.approval,
      mode: 1,
      absentBranch: 2,
      state: 1,
    });
    expect(client.merkle).toEqual([[approved.utxoHash]]);
    expect(client.nonInclusion).toEqual([[approved.nullifier]]);
    expect(client.requests[0]).toHaveLength(2);
  });

  it("an unlisted member passes through the absent alternative", async () => {
    const { member, address } = recipient();
    const client = entryProofReads({ tree: TREE, account: true });
    const { answers } = await provePolicyAnswers({
      client,
      ...input(MIXED, [output(address, 1n)]),
    });
    const enabled = answers.filter((answer) => answer.enabled);
    expect(enabled).toHaveLength(1);
    expect(enabled[0]).toMatchObject({ listId: ListId.block, mode: 2, absentBranch: 1 });
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toEqual([
      [RingListNamespace.of(NAMESPACE, 0).entryAddress({ listId: ListId.block, member })],
    ]);
  });

  it("a blocked member without approval is refused", async () => {
    const { member, address } = recipient();
    const client = entryProofReads({
      tree: TREE,
      spenders: lineage({
        namespace: NAMESPACE,
        tree: TREE,
        listId: ListId.block,
        member,
        states: ["active"],
      }).spenders,
    });
    await expect(
      provePolicyAnswers({ client, ...input(MIXED, [output(address, 1n)]) }),
    ).rejects.toMatchObject({
      code: "RING_POLICY_RULE_UNSATISFIED",
    });
    expect(client.merkle).toHaveLength(0);
    expect(client.nonInclusion).toHaveLength(0);
  });

  it("a cleared entry answers an absence through the cleared branch", async () => {
    const { member, address } = recipient();
    const cleared = lineage({
      namespace: NAMESPACE,
      tree: TREE,
      listId: ListId.block,
      member,
      states: ["active", "cleared"],
    });
    const client = entryProofReads({ tree: TREE, spenders: cleared.spenders });
    const { answers } = await provePolicyAnswers({
      client,
      ...input(BLOCK, [output(address, 1n)]),
    });
    expect(answers[0]).toMatchObject({
      enabled: true,
      mode: 2,
      absentBranch: 2,
      state: 2,
      version: 1n,
    });
    expect(client.merkle).toEqual([[cleared.utxoHash]]);
    expect(client.nonInclusion).toEqual([[cleared.nullifier]]);
  });

  it("refuses a proof set that is short, foreign or truncated", async () => {
    const { member, address } = recipient();
    const allow = lineage({
      namespace: NAMESPACE,
      tree: TREE,
      listId: ListId.allow,
      member,
      states: ["active"],
    });
    const cases: readonly ((reads: ReturnType<typeof entryProofReads>) => void)[] = [
      (reads) =>
        reads.getMerkleProofs.mockResolvedValue({
          context: { blockTime: 0n, slot: 0n },
          proofs: [],
        }),
      (reads) =>
        reads.getMerkleProofs.mockImplementation(async (_tree, leaves) => ({
          context: { blockTime: 0n, slot: 0n },
          proofs: leaves.map((leaf) => ({
            leaf,
            merkleContext: { treeType: 0, tree: addressOf(0x31) },
            path: Array.from({ length: 32 }, () => filled(0)),
            leafIndex: 0n,
            root: filled(1),
            rootSeq: 0n,
            rootIndex: 3,
          })),
        })),
      (reads) =>
        reads.getNonInclusionProofs.mockImplementation(async (_tree, leaves) => ({
          context: { blockTime: 0n, slot: 0n },
          proofs: leaves.map((leaf) => ({
            leaf,
            merkleContext: { treeType: 1, tree: TREE },
            path: [filled(0)],
            lowElement: filled(0),
            lowElementIndex: 0n,
            highElement: filled(0xff),
            highElementIndex: 1n,
            root: filled(2),
            rootSeq: 0n,
            rootIndex: 4,
          })),
        })),
    ];
    for (const corrupt of cases) {
      const client = entryProofReads({ tree: TREE, spenders: allow.spenders });
      corrupt(client);
      await expect(
        provePolicyAnswers({ client, ...input(TWO_ALLOW, [output(address, 1n)]) }),
      ).rejects.toMatchObject({ code: "RING_ENTRY_PROOF_INCOMPLETE" });
    }
  });

  it("refuses a missing, foreign or undecodable entries tree account", async () => {
    const { address } = recipient();
    const client = entryProofReads({ tree: TREE });
    await expect(
      provePolicyAnswers({ client, ...input(BLOCK, [output(address, 1n)]) }),
    ).rejects.toMatchObject({
      code: "RING_ENTRIES_TREE_INVALID",
    });
    client.getAccount.mockResolvedValue({
      owner: NAMESPACE,
      lamports: 1n,
      data: new Uint8Array(30_344),
    });
    await expect(
      provePolicyAnswers({ client, ...input(BLOCK, [output(address, 1n)]) }),
    ).rejects.toMatchObject({
      code: "RING_ENTRIES_TREE_INVALID",
    });
  });

  it("refuses a referenced list without a source and a table past the answer width", () => {
    const { address } = recipient();
    const unmapped = { ...input(BLOCK, [output(address, 1n)]) };
    const config = {
      ...unmapped.config,
      sources: unmapped.config.sources.map((slot) => ({ ...slot, listId: 0 })),
    };
    expect(() => planPolicyAnswers({ ...unmapped, config })).toThrow(
      expect.objectContaining({
        code: "RING_POLICY_SOURCE_INVALID",
        details: { reason: "MissingSourceOwner", listId: ListId.block },
      }),
    );
    const wide: RuleTable = {
      rules: [
        require("outputOwner", ListId.allow),
        require("outputOwner", ListId.block),
        require("outputOwner", ListId.frozen),
      ],
      inlineAssets: [],
      inlineLimits: [],
    };
    const parties = Array.from({ length: 4 }, () => recipient());
    const client = entryProofReads({
      tree: TREE,
      spenders: parties.flatMap((party) =>
        [ListId.allow, ListId.block, ListId.frozen].flatMap(
          (listId) =>
            lineage({
              namespace: NAMESPACE,
              tree: TREE,
              listId,
              member: party.member,
              states: ["active"],
            }).spenders,
        ),
      ),
    });
    return expect(
      provePolicyAnswers({
        client,
        ...input(
          wide,
          parties.map((party) => output(party.address, 1n)),
        ),
      }),
    ).rejects.toMatchObject({ code: "RING_POLICY_SHAPE_UNSUPPORTED" });
  });
});
