import type { ChainReader, ProofReader } from "../client/ports.js";
import {
  RING_ANSWER_SLOTS,
  RING_INPUT_SLOTS,
  RING_NULLIFIER_PATH_LENGTH,
  RING_OUTPUT_SLOTS,
  RING_STATE_PATH_LENGTH,
  disabledRuleAnswer,
  type CustomRingRuleAnswer,
} from "../client/prover/types.js";
import type { MerkleProof, NonInclusionProof } from "../client/rpc.js";
import type { Address, Bytes32, RequestContext, TreeHeadRoots } from "../interface/types.js";
import type { ProofInputUtxo, ProofOutputUtxo, TreeId } from "../transaction/utxo.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";

import type { RingPolicyConfig } from "./codecs.js";
import { checkedEntryProof, readEntriesTreeHeads } from "./entries-tree.js";
import { RingError } from "./error.js";
import {
  RingListNamespace,
  listIdFromByte,
  memberOfAsset,
  memberOfIdentity,
  readRingEntryLineages,
  ruleAlternatives,
  type EntryIndexer,
  type ListId,
  type LiveEntry,
  type Member,
  type Rule,
  type RuleMode,
  type RuleTable,
} from "./policy.js";

export type RingPolicyAnswerClient = Pick<ChainReader, "getAccount"> &
  EntryIndexer &
  Pick<ProofReader, "getMerkleProofs" | "getNonInclusionProofs">;

export interface PolicyAnswerInput {
  readonly table: RuleTable;
  readonly config: RingPolicyConfig;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
}

export interface PolicyAnswers {
  readonly answers: readonly CustomRingRuleAnswer[];
  readonly roots: TreeHeadRoots;
}

/** Mirrors Rust `CustomRingWitnessInput::build`, a rule no entry admits is refused before any prover round. */
export async function provePolicyAnswers(
  input: PolicyAnswerInput & Readonly<{ client: RingPolicyAnswerClient }>,
  context?: RequestContext,
): Promise<PolicyAnswers> {
  const plan = planPolicyAnswers(input);
  const lineages = await readRingEntryLineages(
    {
      indexer: input.client,
      entriesTree: input.config.entriesTree,
      entriesTreeId: input.config.entriesTreeId,
      lookups: plan.lookups,
    },
    context,
  );
  const resolved = resolvePolicyAnswers(plan, lineages, input.config.entriesTreeId);
  const queries = answerQueries(resolved);
  const tree = input.config.entriesTree;
  const [states, absences] = await Promise.all([
    queries.states.length === 0
      ? []
      : input.client
          .getMerkleProofs(tree, queries.states, undefined, context)
          .then((response) => response.proofs),
    queries.absences.length === 0
      ? []
      : input.client
          .getNonInclusionProofs(tree, queries.absences, undefined, context)
          .then((response) => response.proofs),
  ]);
  const proofs = checkedEntryProofs({ tree, queries, states, absences });
  const fixed = fixedRoots(proofs);
  const roots =
    fixed.complete() ?? fixed.fill(await readEntriesTreeHeads(input.client, tree, context));
  return Object.freeze({ answers: assemblePolicyAnswers(resolved, proofs), roots });
}

interface AnswerLookup {
  readonly namespace: Address;
  readonly listId: ListId;
  readonly member: Member;
}

interface Alternative {
  readonly lookup: number;
  readonly mode: RuleMode;
}

interface Demand {
  readonly ruleIndex: number;
  readonly member: Member;
  readonly alternatives: readonly Alternative[];
}

interface AnswerPlan {
  readonly lookups: readonly AnswerLookup[];
  readonly demands: readonly Demand[];
}

/** Mirrors Rust `WitnessPlan`, one lookup per distinct list entry the rules consult. */
export function planPolicyAnswers(input: PolicyAnswerInput): AnswerPlan {
  if (input.inputs.length > RING_INPUT_SLOTS || input.outputs.length > RING_OUTPUT_SLOTS) {
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED", {
      details: { inputs: input.inputs.length, outputs: input.outputs.length },
    });
  }
  const namespaces = sourceNamespaces(input.config);
  const lookups: AnswerLookup[] = [];
  const keys = new Map<string, number>();
  const demands: Demand[] = [];
  input.table.rules.forEach((rule, ruleIndex) => {
    const alternatives = ruleAlternatives(rule);
    if (alternatives.length === 0) return;
    for (const member of subjects(rule, input)) {
      if (guardExempts(rule, member, input)) continue;
      demands.push({
        ruleIndex,
        member,
        alternatives: alternatives.map(({ listId, mode }) => {
          const namespace = namespaces.get(listId);
          if (namespace === undefined) {
            throw new RingError("RING_POLICY_SOURCE_INVALID", {
              details: { reason: "MissingSourceOwner", listId },
            });
          }
          const key = `${namespace}:${String(listId)}:${bytesKey(member)}`;
          let lookup = keys.get(key);
          if (lookup === undefined) {
            lookup = lookups.length;
            keys.set(key, lookup);
            lookups.push({ namespace, listId, member });
          }
          return { lookup, mode };
        }),
      });
    }
  });
  return Object.freeze({ lookups: Object.freeze(lookups), demands: Object.freeze(demands) });
}

/** The lookups read the namespace whose owner hash the proof binds. */
function sourceNamespaces(config: RingPolicyConfig): Map<ListId, Address> {
  const namespaces = new Map<ListId, Address>();
  for (const slot of config.sources) {
    if (slot.listId === 0) continue;
    const listId = listIdFromByte(slot.listId);
    if (listId === undefined) {
      throw new RingError("RING_POLICY_SOURCE_INVALID", {
        details: { reason: "NotPositional", listId: slot.listId },
      });
    }
    namespaces.set(listId, slot.namespace);
  }
  return namespaces;
}

/** Mirrors Rust `subjects`, live outputs and non-dummy inputs in slot order. */
function subjects(rule: Rule, input: PolicyAnswerInput): readonly Member[] {
  switch (rule.subject) {
    case "outputOwner":
      return liveOutputs(input).map((output) => ownerMember(output));
    case "sender":
      return input.inputs
        .filter((spend) => !spend.isDummy())
        .map((spend) => memberOfIdentity(spend.utxo.owner.ownerProofInputHash()));
    case "asset":
      return liveOutputs(input).map((output) => memberOfAsset(output.asset));
    case "exitDestination":
      return [];
  }
}

type LiveOutput = ProofOutputUtxo &
  Readonly<{ ownerAddress: NonNullable<ProofOutputUtxo["ownerAddress"]> }>;

function liveOutputs(input: PolicyAnswerInput): readonly LiveOutput[] {
  return input.outputs.filter((output): output is LiveOutput => output.ownerAddress !== undefined);
}

/** The identity the opening carries as `ownerPkHash`, one list serves every owner curve. */
function ownerMember(output: LiveOutput): Member {
  return memberOfIdentity(output.ownerAddress.signingPublicKey.ownerProofInputHash());
}

/** Mirrors Rust `guard_exempts`, the aggregate over every live output to the member is weighed. */
function guardExempts(rule: Rule, member: Member, input: PolicyAnswerInput): boolean {
  switch (rule.guard.kind) {
    case "always":
      return false;
    case "aboveAmount":
      if (rule.subject === "sender" || rule.subject === "exitDestination") return false;
      return subjectTotal(rule, member, input) <= rule.guard.amount;
    case "aboveAmountByAsset":
      return assetLimitsExempt(member, input);
  }
}

function subjectTotal(rule: Rule, member: Member, input: PolicyAnswerInput): bigint {
  return liveOutputs(input).reduce((total, output) => {
    const outputMember =
      rule.subject === "asset" ? memberOfAsset(output.asset) : ownerMember(output);
    return equalBytes(outputMember, member) ? total + output.amount : total;
  }, 0n);
}

function assetLimitsExempt(owner: Member, input: PolicyAnswerInput): boolean {
  const totals = input.table.inlineAssets.map(() => 0n);
  for (const output of liveOutputs(input)) {
    if (!equalBytes(ownerMember(output), owner)) continue;
    const asset = memberOfAsset(output.asset);
    const index = input.table.inlineAssets.findIndex((known) => equalBytes(known, asset));
    if (index < 0) {
      throw new RingError("RING_POLICY_ASSET_UNSUPPORTED", { details: { asset: output.asset } });
    }
    totals[index] = (totals[index] ?? 0n) + output.amount;
  }
  return totals.every((total, index) => total <= (input.table.inlineLimits[index] ?? 0n));
}

type EntryFact =
  | Readonly<{ kind: "unclaimed"; address: Bytes32 }>
  | Readonly<{ kind: "live"; live: LiveEntry }>;

interface ResolvedAnswer {
  readonly listId: ListId;
  readonly member: Member;
  readonly mode: RuleMode;
  readonly fact: EntryFact;
}

/** Mirrors Rust `WitnessPlan::resolve`, the first alternative the entries satisfy answers a demand. */
function resolvePolicyAnswers(
  plan: AnswerPlan,
  lineages: readonly (LiveEntry | undefined)[],
  treeId: TreeId,
): readonly ResolvedAnswer[] {
  if (lineages.length !== plan.lookups.length) {
    throw new RingError("RING_ENTRY_PROOF_INCOMPLETE", {
      details: { expected: plan.lookups.length, actual: lineages.length },
    });
  }
  const facts: EntryFact[] = plan.lookups.map((lookup, index) => {
    const live = lineages[index];
    return live === undefined
      ? {
          kind: "unclaimed",
          address: RingListNamespace.of(lookup.namespace, treeId).entryAddress(lookup),
        }
      : { kind: "live", live };
  });
  const answers: ResolvedAnswer[] = [];
  for (const demand of plan.demands) {
    const satisfied = demand.alternatives
      .map((candidate) => ({ candidate, fact: facts[candidate.lookup] }))
      .find(({ candidate, fact }) => fact !== undefined && satisfies(fact, candidate.mode));
    const lookup = satisfied === undefined ? undefined : plan.lookups[satisfied.candidate.lookup];
    if (satisfied?.fact === undefined || lookup === undefined) {
      throw new RingError("RING_POLICY_RULE_UNSATISFIED", {
        details: { ruleIndex: demand.ruleIndex, member: bytesKey(demand.member) },
      });
    }
    const answer: ResolvedAnswer = {
      listId: lookup.listId,
      member: demand.member,
      mode: satisfied.candidate.mode,
      fact: satisfied.fact,
    };
    if (!answers.some((known) => sameQuestion(known, answer))) answers.push(answer);
  }
  if (answers.length > RING_ANSWER_SLOTS) {
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED", { details: { answers: answers.length } });
  }
  return Object.freeze(answers);
}

function satisfies(fact: EntryFact, mode: RuleMode): boolean {
  const active = fact.kind === "live" && fact.live.entry.state === "active";
  return mode === "present" ? active : !active;
}

function sameQuestion(left: ResolvedAnswer, right: ResolvedAnswer): boolean {
  return (
    left.listId === right.listId &&
    left.mode === right.mode &&
    equalBytes(left.member, right.member)
  );
}

interface AnswerQueries {
  readonly states: readonly Bytes32[];
  readonly absences: readonly Bytes32[];
}

function answerQueries(answers: readonly ResolvedAnswer[]): AnswerQueries {
  return Object.freeze({
    states: Object.freeze(
      answers.flatMap((answer) => (answer.fact.kind === "live" ? [answer.fact.live.utxoHash] : [])),
    ),
    absences: Object.freeze(
      answers.map((answer) =>
        answer.fact.kind === "live" ? answer.fact.live.nullifier : answer.fact.address,
      ),
    ),
  });
}

interface EntryProofs {
  readonly states: readonly MerkleProof[];
  readonly absences: readonly NonInclusionProof[];
}

/** Every requested leaf answered from the entries tree, in request order. */
function checkedEntryProofs(
  input: Readonly<{
    tree: Address;
    queries: AnswerQueries;
    states: readonly MerkleProof[];
    absences: readonly NonInclusionProof[];
  }>,
): EntryProofs {
  if (
    input.states.length !== input.queries.states.length ||
    input.absences.length !== input.queries.absences.length
  ) {
    throw new RingError("RING_ENTRY_PROOF_INCOMPLETE", { details: { entriesTree: input.tree } });
  }
  return Object.freeze({
    states: input.queries.states.map((leaf, index) =>
      checkedEntryProof(input.states[index], {
        entriesTree: input.tree,
        leaf,
        pathLength: RING_STATE_PATH_LENGTH,
      }),
    ),
    absences: input.queries.absences.map((leaf, index) =>
      checkedEntryProof(input.absences[index], {
        entriesTree: input.tree,
        leaf,
        pathLength: RING_NULLIFIER_PATH_LENGTH,
      }),
    ),
  });
}

interface HistoryRoot {
  readonly value: Bytes32;
  readonly index: number;
}

/** Mirrors Rust `FixedRoots`, a tree no answer touched has none. */
interface FixedRoots {
  readonly state: HistoryRoot | undefined;
  readonly nullifier: HistoryRoot | undefined;
  complete(): TreeHeadRoots | undefined;
  /** The program admits any live state root and any nullifier root inside its window. */
  fill(heads: TreeHeadRoots): TreeHeadRoots;
}

function fixedRoots(proofs: EntryProofs): FixedRoots {
  const state = singleRoot(proofs.states);
  const nullifier = singleRoot(proofs.absences);
  return Object.freeze({
    state,
    nullifier,
    complete: () =>
      state === undefined || nullifier === undefined
        ? undefined
        : Object.freeze({
            stateRoot: state.value,
            stateRootIndex: state.index,
            nullifierRoot: nullifier.value,
            nullifierRootIndex: nullifier.index,
          }),
    fill: (heads: TreeHeadRoots) =>
      Object.freeze({
        stateRoot: state?.value ?? heads.stateRoot,
        stateRootIndex: state?.index ?? heads.stateRootIndex,
        nullifierRoot: nullifier?.value ?? heads.nullifierRoot,
        nullifierRootIndex: nullifier?.index ?? heads.nullifierRootIndex,
      }),
  });
}

/** One call proves every leaf against one root. */
function singleRoot(proofs: readonly (MerkleProof | NonInclusionProof)[]): HistoryRoot | undefined {
  const [first] = proofs;
  if (first === undefined) return undefined;
  if (
    proofs.some(
      (proof) => proof.rootIndex !== first.rootIndex || !equalBytes(proof.root, first.root),
    )
  ) {
    throw new RingError("RING_POLICY_ROOT_MISMATCH");
  }
  return { value: first.root, index: first.rootIndex };
}

/** Mirrors Rust `ResolvedWitness::assemble`, padded to the answer width. */
function assemblePolicyAnswers(
  answers: readonly ResolvedAnswer[],
  proofs: EntryProofs,
): readonly CustomRingRuleAnswer[] {
  let liveIndex = 0;
  const assembled = answers.map((answer, index) => {
    const absence = proofs.absences[index];
    if (absence === undefined) throw new RingError("RING_ENTRY_PROOF_INCOMPLETE");
    const base = {
      ...disabledRuleAnswer(),
      enabled: true,
      mode: answer.mode === "present" ? 1 : 2,
      listId: answer.listId,
      member: answer.member,
      low: absence.lowElement,
      next: absence.highElement,
      nullifierPath: absence.path,
      nullifierPathIndex: absence.lowElementIndex,
    };
    if (answer.fact.kind === "unclaimed") return Object.freeze({ ...base, absentBranch: 1 });
    const state = proofs.states[liveIndex];
    liveIndex += 1;
    if (state === undefined) throw new RingError("RING_ENTRY_PROOF_INCOMPLETE");
    const { entry } = answer.fact.live;
    return Object.freeze({
      ...base,
      absentBranch: 2,
      state: entry.state === "active" ? 1 : 2,
      version: entry.version,
      blinding: entry.blinding,
      contentHash: entry.contentHash,
      statePath: state.path,
      statePathIndex: state.leafIndex,
    });
  });
  return Object.freeze([
    ...assembled,
    ...Array.from({ length: RING_ANSWER_SLOTS - assembled.length }, () => disabledRuleAnswer()),
  ]);
}
