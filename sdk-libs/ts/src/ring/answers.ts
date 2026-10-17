import type {
  ChainReader,
  RingMemberRegistryReader,
  ProofDataSource,
  IndexedRegistry,
} from "../client/ports.js";
import {
  RING_INPUT_SLOTS,
  RING_OUTPUT_SLOTS,
  RING_SUBJECT_SLOTS,
  type CustomRingSubjectWitness,
} from "../client/prover/types.js";
import type { TreeSlot } from "../interface/tree-slot.js";
import type { Address, Bytes32, RequestContext, TreeContext } from "../interface/types.js";
import type { ProofInputUtxo, ProofOutputUtxo } from "../transaction/utxo.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";
import { ZERO_32 } from "../transaction/internal.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { ringMemberRegistryRootAddress } from "../interface/pda/index.js";
import { waitForProjection } from "../client/retry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { type RingPolicyConfig, decodeRingMemberRegistryRoot } from "./codecs.js";
import { fetchRingMemberRegistryRoot } from "./config.js";
import { readRingMemberRecord, type MemberRecordRead } from "./member-record.js";
import type { MemberOpening } from "./member-registry-tree.js";
import { registeredKeyHash } from "./member-registry.js";
import { RingError } from "./error.js";
import { readTreeHeads } from "./policy-trees.js";
import {
  policySourceOwners,
  memberOfAsset,
  memberOfIdentity,
  ruleAlternatives,
  type Member,
  type Rule,
  type RuleTable,
} from "./policy.js";

export type RingPolicyAnswerClient = Pick<ChainReader, "getAccount"> &
  Pick<RingMemberRegistryReader, "getRingMemberRecord">;
export interface PolicyAnswerInput {
  readonly ringProgramId: Address;
  readonly keyEscrow: boolean;
  readonly proofDataSource: ProofDataSource;
  readonly table: RuleTable;
  readonly config: RingPolicyConfig;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
}
export interface PolicyAnswers {
  readonly subjects: readonly (CustomRingSubjectWitness | undefined)[];
  readonly foreignSubjects: readonly (CustomRingSubjectWitness | undefined)[];
  readonly ctHashes: readonly Bytes32[];
  readonly registry: IndexedRegistry;
  readonly rootIndex: number;
  readonly foreign?: Readonly<{ registry: Address; rootIndex: number; indexed: IndexedRegistry }>;
  readonly policyTrees: readonly Address[];
  readonly treeSlots: readonly TreeSlot[];
  readonly treeContexts: readonly TreeContext[];
}
export function subjectWitness(opening: MemberOpening): CustomRingSubjectWitness {
  if (opening.present)
    return {
      present: true,
      next: opening.record.next,
      lists: opening.record.lists,
      escrowKey: opening.record.escrowKey,
      index: opening.index,
      path: opening.path,
      lowMember: ZERO_32,
      lowNext: ZERO_32,
      lowLists: 0n,
      lowEscrow: ZERO_32,
    };
  return {
    present: false,
    next: ZERO_32,
    lists: 0n,
    escrowKey: ZERO_32,
    index: opening.index,
    path: opening.path,
    lowMember: opening.low.member,
    lowNext: opening.low.next,
    lowLists: opening.low.lists,
    lowEscrow: opening.low.escrowKey,
  };
}
export async function provePolicyAnswers(
  input: PolicyAnswerInput & Readonly<{ client: RingPolicyAnswerClient }>,
  context?: RequestContext,
): Promise<PolicyAnswers> {
  return waitForProjection(
    (context) => proveAtRoots(input, context),
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}
async function proveAtRoots(
  input: PolicyAnswerInput & Readonly<{ client: RingPolicyAnswerClient }>,
  context: RequestContext,
): Promise<PolicyAnswers> {
  if (input.inputs.length > RING_INPUT_SLOTS || input.outputs.length > RING_OUTPUT_SLOTS)
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED");
  policySourceOwners(input.config.sources);
  const root = await fetchRingMemberRegistryRoot(input.client, input.ringProgramId, context);
  const heads = await readTreeHeads(
    input.client,
    { tree: input.config.addressTree, treeId: input.config.addressTreeId },
    context,
  );
  let foreign: PolicyAnswers["foreign"];
  let foreignRoot: typeof root | undefined;
  const curator = input.config.sources.find(
    (slot) => slot.listId !== 0 && !equalBytes(addressBytes(slot.registry), ZERO_32),
  )?.registry;
  if (curator !== undefined) {
    const account = await input.client.getAccount(curator, context);
    if (account === undefined || (await ringMemberRegistryRootAddress(account.owner)) !== curator)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID");
    foreignRoot = decodeRingMemberRegistryRoot(account.data);
    foreign = {
      registry: curator,
      rootIndex: foreignRoot.historyCursor,
      indexed: {
        ringProgramId: account.owner,
        root: foreignRoot.root,
        nextIndex: foreignRoot.nextIndex,
      },
    };
  }
  const own: Array<CustomRingSubjectWitness | undefined> = Array.from(
    { length: RING_SUBJECT_SLOTS },
    () => undefined,
  );
  const other: Array<CustomRingSubjectWitness | undefined> = Array.from(
    { length: RING_SUBJECT_SLOTS },
    () => undefined,
  );
  const ctHashes: Bytes32[] = Array.from({ length: RING_OUTPUT_SLOTS }, () => ZERO_32);
  if (input.proofDataSource !== "prover") {
    const slots: Array<Readonly<{ position: number; member: Member }>> = [];
    input.inputs.forEach((spend, position) => {
      if (!spend.isDummy())
        slots.push({ position, member: memberOfIdentity(spend.utxo.owner.ownerProofInputHash()) });
    });
    input.outputs.forEach((output, index) => {
      if (output.ownerAddress !== undefined)
        slots.push({
          position: RING_INPUT_SLOTS + index,
          member: ownerMember({ ...output, ownerAddress: output.ownerAddress }),
        });
    });
    if (input.table.rules.some((rule) => rule.subject === "asset")) {
      input.outputs.forEach((output, index) => {
        if (output.ownerAddress !== undefined)
          slots.push({
            position: RING_INPUT_SLOTS + RING_OUTPUT_SLOTS + index,
            member: memberOfAsset(output.asset),
          });
      });
    }
    const cache = new Map<
      string,
      Promise<Readonly<{ own: MemberRecordRead; foreign?: MemberRecordRead }>>
    >();
    const records = new Map<
      string,
      Readonly<{ own: MemberRecordRead; foreign?: MemberRecordRead }>
    >();
    await Promise.all(
      slots.map(async (slot) => {
        const key = bytesKey(slot.member);
        let pending = cache.get(key);
        if (pending === undefined) {
          pending = (async () => {
            const own = await readRingMemberRecord(
              {
                client: input.client,
                ringProgramId: input.ringProgramId,
                member: slot.member,
                registry: root,
              },
              context,
            );
            const readForeign =
              foreign === undefined || foreignRoot === undefined
                ? undefined
                : await readRingMemberRecord(
                    {
                      client: input.client,
                      ringProgramId: foreign.indexed.ringProgramId,
                      member: slot.member,
                      registry: foreignRoot,
                    },
                    context,
                  );
            return { own, ...(readForeign === undefined ? {} : { foreign: readForeign }) };
          })();
          cache.set(key, pending);
        }
        const read = await pending;
        records.set(key, read);
        own[slot.position] = subjectWitness(read.own.opening);
        if (read.foreign !== undefined) other[slot.position] = subjectWitness(read.foreign.opening);
        if (
          input.keyEscrow &&
          slot.position >= RING_INPUT_SLOTS &&
          slot.position < RING_INPUT_SLOTS + RING_OUTPUT_SLOTS
        ) {
          const index = slot.position - RING_INPUT_SLOTS;
          const output = input.outputs[index];
          if (
            output?.ownerAddress === undefined ||
            !read.own.opening.present ||
            read.own.sealed === null ||
            !equalBytes(
              read.own.opening.record.escrowKey,
              registeredKeyHash({
                nullifierPublicKey: output.ownerAddress.nullifierPublicKey,
                ciphertext: read.own.sealed.ciphertext,
              }),
            )
          )
            throw new RingError("RING_UNREGISTERED_OUTPUT_KEY", { details: { owner: key } });
          ctHashes[index] = hashBytes(read.own.sealed.ciphertext) as Bytes32;
        }
      }),
    );
    input.table.rules.forEach((rule, ruleIndex) => {
      if (rule.subject === "outputOwner" && rule.guard.kind === "aboveAmount") {
        const assets = new Set(
          input.outputs
            .filter((output) => output.ownerAddress !== undefined)
            .map((output) => bytesKey(memberOfAsset(output.asset))),
        );
        if (assets.size > 1) throw new RingError("RING_POLICY_RULE_UNSATISFIED");
      }
      for (const member of subjects(rule, input)) {
        if (guardExempts(rule, member, input)) continue;
        const found = records.get(bytesKey(member));
        if (found === undefined) throw new RingError("RING_MEMBER_REGISTRY_INVALID");
        const satisfied = ruleAlternatives(rule).some(({ listId, mode }) => {
          const source = input.config.sources[listId - 1];
          if (source?.listId !== listId) throw new RingError("RING_POLICY_SOURCE_INVALID");
          const record = equalBytes(addressBytes(source.registry), ZERO_32)
            ? found.own
            : found.foreign;
          if (record === undefined) throw new RingError("RING_MEMBER_REGISTRY_INVALID");
          const lists = record.opening.present ? record.opening.record.lists : 0n;
          const on = (lists & (1n << BigInt(listId - 1))) !== 0n;
          return mode === "present" ? on : !on;
        });
        if (!satisfied)
          throw new RingError("RING_POLICY_RULE_UNSATISFIED", {
            details: { ruleIndex, member: bytesKey(member) },
          });
      }
    });
  }
  return {
    subjects: own,
    foreignSubjects: other,
    ctHashes,
    registry: { ringProgramId: input.ringProgramId, root: root.root, nextIndex: root.nextIndex },
    rootIndex: root.historyCursor,
    ...(foreign === undefined ? {} : { foreign }),
    policyTrees: [input.config.addressTree],
    treeSlots: [
      {
        id: input.config.addressTreeId,
        utxoRoot: heads.stateRoot,
        nullifierRoot: heads.nullifierRoot,
      },
    ],
    treeContexts: [
      { utxoTreeRootIndex: heads.stateRootIndex, nullifierTreeRootIndex: heads.nullifierRootIndex },
    ],
  };
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
