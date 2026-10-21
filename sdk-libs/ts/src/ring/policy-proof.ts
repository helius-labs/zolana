/** The policy half of a ring transfer, the ring's table and every subject's record under the roots the statement binds, Rust `pipeline::policy`. */
import {
  publicAmountFields,
  ringInputOpening,
  ringOutputOpening,
  type PublicSlots,
} from "../client/prover/assembly.js";
import type { ChainReader, RingRecordReader } from "../client/ports.js";
import type {
  DelegatePolicyProofRequest,
  MemberPolicyProofRequest,
  PolicySubjectEntry,
} from "../client/prover/ring.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import {
  assetField,
  privateTxAddressChain,
  sppPrivateTxHashInput,
  type SppProofInputs,
} from "../transaction/instructions/transact.js";
import { ZERO_32, nonZeroHashChain } from "../transaction/internal.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";

import { registryCurrentRoot, type RingMemberRegistry, type RingProgramConfig } from "./codecs.js";
import { fetchCuratorRegistry, fetchRingMemberRegistry } from "./config.js";
import { RingError } from "./error.js";
import { ownerEscrowed, type MemberOpeningRead } from "./member-registry.js";
import {
  admitTransfer,
  memberOfAsset,
  pinnedPolicy,
  policyTableProofInputs,
  type OutflowLimit,
  type PinnedPolicy,
  type RecordLists,
  type RuleRefusal,
} from "./policy.js";
import { readMemberOpenings } from "./registered-record.js";
import { policyStatementHash, type PolicyKey } from "./statement.js";
import type { RingRail } from "./transact.js";

/** The registry root a statement names by its history slot. */
export interface BoundRoot {
  readonly ringProgramId: Address;
  readonly rootIndex: number;
  readonly root: Bytes32;
}

/** The registry policy hash a policy statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getRingMemberOpenings">;

/** The ring's table, its roots and every subject's openings, read before the statement, Rust `PolicyInputs`. */
export interface PolicyInputs {
  readonly pinned: PinnedPolicy;
  readonly own: BoundRoot;
  /** The curator registry account and the root bound from it. */
  readonly curator?: Readonly<{ registry: Address; root: BoundRoot }>;
  readonly senderEntry: PolicySubjectEntry;
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  /** The escrowed key ciphertext hash of every UTXO output's owner, under key escrow. */
  readonly ctHashes: readonly (Bytes32 | undefined)[];
  readonly approvalRequired: boolean;
  readonly keyEscrow: boolean;
}

/** What the statement and the request read besides the policy inputs, Rust `PolicyProving`. */
export interface PolicyProving {
  readonly ringId: Bytes32;
  readonly rail: RingRail;
  readonly proofInputs: SppProofInputs;
  readonly privateTxHash: Bytes32;
  /** The owner identity, the anonymous rail's sender commitment, zero on the delegate rail. */
  readonly sender: Bytes32;
  readonly senderPkHash: Bytes32;
  readonly publicSlots: PublicSlots;
}

/** Rust `PolicyRead::read`, `sender` is the owner identity the rules read as the sender. */
export async function readPolicy(
  input: Readonly<{
    client: PolicyReadClient;
    ringProgramId: Address;
    config: RingProgramConfig;
    rail: RingRail;
    proofInputs: SppProofInputs;
    sender: Bytes32;
    publicSlots: PublicSlots;
  }>,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, ringProgramId, proofInputs } = input;
  const registry = await fetchRingMemberRegistry(client, ringProgramId, context);
  const pinned = pinnedPolicy(registry);
  const own = currentRoot(ringProgramId, registry);
  const curatorRegistry = pinned.curator;
  const curator =
    curatorRegistry === undefined
      ? undefined
      : await (async () => {
          const read = await fetchCuratorRegistry(client, curatorRegistry, context);
          return {
            registry: curatorRegistry,
            root: currentRoot(read.ringProgramId, read.registry),
          };
        })();
  const outputs = proofInputs.outputs;
  const assetRules = pinned.table.rules.some((rule) => rule.subject === "asset");
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    assetRules && !output.isDummy() ? memberOfAsset(output.asset) : undefined,
  );
  const members = uniqueMembers([input.sender, ...owners, ...assets]);
  const ownReads = await openingsByMember(client, own, members, context);
  const curatorReads =
    curator === undefined
      ? undefined
      : await openingsByMember(client, curator.root, members, context);
  const reads = (member: Bytes32 | undefined) =>
    member === undefined
      ? { own: undefined, curator: undefined }
      : { own: ownReads.get(bytesKey(member)), curator: curatorReads?.get(bytesKey(member)) };
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry => {
    const { own, curator } = reads(member);
    return { own: own?.opening, curator: curator?.opening };
  };
  const lists = (member: Bytes32 | undefined): RecordLists => {
    const { own, curator } = reads(member);
    return Object.freeze({
      own: own?.record()?.lists ?? 0n,
      curator: curator?.record()?.lists ?? 0n,
    });
  };
  const live = outputs.flatMap((output, slotIndex) =>
    output.isDummy() ? [] : [{ output, slotIndex }],
  );
  const refusal = admitTransfer(pinned.table, pinned.sources, {
    sender: lists(input.sender),
    outputs: live.map(({ output, slotIndex }) => ({
      owner: owners[slotIndex] ?? ZERO_32,
      asset: memberOfAsset(output.asset),
      amount: output.amount,
      ownerLists: lists(owners[slotIndex]),
      assetLists: lists(assets[slotIndex]),
    })),
  });
  if (refusal !== undefined)
    throw ruleUnsatisfied(
      refusal,
      live.map(({ slotIndex }) => slotIndex),
    );
  const keyEscrow = input.config.keyEscrow;
  const ctHashes = outputs.map((output, slotIndex) => {
    const owner = owners[slotIndex];
    const address = output.ownerAddress;
    if (!keyEscrow || owner === undefined || address === undefined) return undefined;
    return ownerEscrowed(owner, ownReads.get(bytesKey(owner)), address.nullifierPublicKey).ctHash;
  });
  const approvalRequired =
    input.rail === "delegate"
      ? false
      : outflowApproval({
          sender: input.sender,
          ringProgramId,
          proofInputs,
          publicSlots: input.publicSlots,
          limits: pinned.table.limits,
        });
  return Object.freeze({
    pinned,
    own,
    ...(curator === undefined ? {} : { curator }),
    senderEntry: entry(input.sender),
    ownerEntries: Object.freeze(owners.map(entry)),
    assetEntries: Object.freeze(assets.map(entry)),
    ctHashes: Object.freeze(ctHashes),
    approvalRequired,
    keyEscrow,
  });
}

/** Rust `PolicyInputs::statement`, the delegate key always proves escrowed keys. */
export function policyPublicInputHash(policy: PolicyInputs, proving: PolicyProving): Bytes32 {
  const key = policyKey(proving.rail);
  return policyStatementHash({
    key,
    privateTxHash: proving.privateTxHash,
    policyHash: policy.pinned.policyHash,
    ringId: proving.ringId,
    approvalRequired: policy.approvalRequired,
    keyEscrow: key.kind === "delegate" || policy.keyEscrow,
    ownRoot: policy.own.root,
    curatorRoot: policy.curator?.root.root ?? zeroField(),
    sender: proving.sender,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
  });
}

/** The policy proof's request, Rust `PolicyInputs::prove`. */
export function policyProofRequest(
  policy: PolicyInputs,
  proving: PolicyProving,
): MemberPolicyProofRequest | DelegatePolicyProofRequest {
  const { proofInputs } = proving;
  const publicInputHash = policyPublicInputHash(policy, proving);
  const privateTx = sppPrivateTxHashInput(proofInputs);
  const params = {
    ...policyTableProofInputs(policy.pinned.table, policy.pinned.sources),
    privateTxHash: proving.privateTxHash,
    policyHash: policy.pinned.policyHash,
    ringId: proving.ringId,
    ownRoot: policy.own.root,
    curatorRoot: policy.curator?.root.root ?? zeroField(),
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    addressChain: privateTxAddressChain(privateTx),
    privateTxBlinding: proofInputs.privateTxBlinding(),
    outputs: proofInputs.outputs.map((output, slotIndex) => {
      const ctHash = policy.ctHashes[slotIndex];
      return Object.freeze({
        ...ringOutputOpening(output, proofInputs.outputTreeId),
        ...(ctHash === undefined ? {} : { ctHash }),
      });
    }),
    senderPkHash: proving.senderPkHash,
    senderEntry: policy.senderEntry,
    ownerEntries: policy.ownerEntries,
    assetEntries: policy.assetEntries,
  };
  if (proving.rail === "delegate")
    return Object.freeze({
      kind: "delegatePolicy",
      publicInputHash,
      ...params,
      inputs: proofInputs.inputUtxos.map(ringInputOpening),
    });
  return Object.freeze({
    kind: "memberPolicy",
    publicInputHash,
    ...params,
    anonymous: proving.rail === "anonymous",
    approvalRequired: policy.approvalRequired,
    keyEscrow: policy.keyEscrow,
    sender: proving.sender,
    inputChain: nonZeroHashChain(privateTx.inputHashes),
  });
}

/** Rust `RingRail::policy_key`. */
export function policyKey(rail: RingRail): PolicyKey {
  return rail === "delegate"
    ? { kind: "delegate" }
    : { kind: "member", anonymous: rail === "anonymous" };
}

/**
 * Rust `Outflows::approval_required`. Every UTXO output but the sender's change inside the ring
 * leaves it, less the asset's public net, a nonzero cap refuses more and a nonzero co-sign bound sets
 * the approval bit.
 */
export function outflowApproval(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
    limits: readonly OutflowLimit[];
  }>,
): boolean {
  let approval = false;
  for (const limit of input.limits) {
    const outflow = assetOutflow(input, limit.asset);
    const over = (bound: bigint): boolean => bound !== 0n && outflow > bound;
    if (over(limit.cap))
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { cap: limit.cap.toString(), outflow: outflow.toString() },
      });
    approval ||= over(limit.cosignAbove);
  }
  return approval;
}

function assetOutflow(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
  }>,
  asset: Bytes32,
): bigint {
  let others = 0n;
  for (const output of input.proofInputs.outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const change =
      equalBytes(owner.signingPublicKey.ownerProofInputHash(), input.sender) &&
      output.ringProgramId === input.ringProgramId;
    if (!change && equalBytes(assetField(output.asset), asset)) others += output.amount;
  }
  const net = input.publicSlots.assets.reduce(
    (sum, publicAsset, index) =>
      equalBytes(publicAsset, asset) ? sum + (input.publicSlots.nets[index] ?? 0n) : sum,
    0n,
  );
  if (net > others) throw new RingError("RING_DEPOSIT_ABOVE_OUTFLOW");
  return others - net;
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const slot = (output: number): number => live[output] ?? -1;
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      refusal.kind !== "lists"
        ? { reason: refusal.kind, ruleIndex: refusal.rule, slotIndex: slot(refusal.output) }
        : refusal.subject.kind === "sender"
          ? { reason: refusal.kind, ruleIndex: refusal.rule, subject: "sender" }
          : {
              reason: refusal.kind,
              ruleIndex: refusal.rule,
              subject: refusal.subject.kind,
              slotIndex: slot(refusal.subject.output),
            },
  });
}

/** Rust `BoundRoot::current`, the newest root of the registry. */
function currentRoot(ringProgramId: Address, registry: RingMemberRegistry): BoundRoot {
  return Object.freeze({
    ringProgramId,
    rootIndex: registry.historyCursor,
    root: registryCurrentRoot(registry).root,
  });
}

/** Every member's verified opening under `root`, keyed by member, Rust `RecordReads::read_keyed`. */
async function openingsByMember(
  client: PolicyReadClient,
  root: BoundRoot,
  members: readonly Bytes32[],
  context: RequestContext | undefined,
): Promise<ReadonlyMap<string, MemberOpeningRead>> {
  const reads = await readMemberOpenings(
    { client, ringProgramId: root.ringProgramId, root: root.root, members },
    context,
  );
  return new Map(
    members.flatMap((member, index) => {
      const read = reads[index];
      return read === undefined ? [] : [[bytesKey(member), read] as const];
    }),
  );
}

/** Sorted by bytes like Rust's `BTreeSet`, padding and duplicates dropped. */
function uniqueMembers(members: readonly (Bytes32 | undefined)[]): readonly Bytes32[] {
  const unique = new Map<string, Bytes32>();
  for (const member of members) if (member !== undefined) unique.set(bytesKey(member), member);
  return [...unique.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, member]) => member);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}
