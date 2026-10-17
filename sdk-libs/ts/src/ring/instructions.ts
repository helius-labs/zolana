import { updateMembersPublicInputHash, checkedRegistryField } from "./member-registry-tree.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import {
  AccountRole,
  downgradeRoleToNonSigner,
  isSignerRole,
  type Address,
  type Instruction,
} from "@solana/kit";

import {
  SYSTEM_PROGRAM,
  meta,
  ringCoSignerMetas,
  ringTransactAccounts,
  type SignerAccount,
} from "../interface/instructions/index.js";
import {
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
  writeTreeContext,
} from "../interface/codecs/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import {
  nullifierPdaAddress,
  protocolConfigAddress,
  ringAuthAddress,
  ringCoSignerAddress,
  ringConfigAddress,
  ringDelegateAddress,
  ringMemberRegistryRootAddress,
  ringPolicyConfigAddress,
} from "../interface/pda/index.js";
import type {
  MergeTransactInstructionData,
  Bytes32,
  Bytes33,
  TransactInstructionData,
  TransactWithdrawal,
  TreeContext,
} from "../interface/types.js";

import { Writer } from "../interface/internal.js";

import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import { checkedCustomRingProof } from "./codecs.js";
import {
  ringPolicyNamespaceAddress,
  ringProgramDataAddress,
  setRingDepositAuditInstruction,
} from "./config.js";
import { RingError } from "./error.js";
import {
  encodeRuleTable,
  checkedListId,
  referencedLists,
  type ListId,
  type RuleTable,
} from "./policy.js";

/** Rust `tag`. */
const RingProgramTag = Object.freeze({
  createConfig: 1,
  initSppRingConfig: 2,
  transact: 3,
  delegateTransact: 25,
  createPolicy: 7,
  updateMembers: 32,
  setPolicySource: 10,
  setPolicyRules: 12,
  registerKey: 29,
} as const);

/** Rust `*_COMPUTE_UNIT_LIMIT`. */
export const RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_READ_ACCESS_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_SET_PAUSED_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_CREATE_POLICY_COMPUTE_UNIT_LIMIT = 150_000;
export const RING_SET_POLICY_RULES_COMPUTE_UNIT_LIMIT = 150_000;
export const RING_SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT = 150_000;
export const RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT = 1_400_000;
export const RING_REGISTER_KEY_COMPUTE_UNIT_LIMIT = RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;

/** SPP input trees in tree context order, then the output tree. */
export type RingTransactTrees = Readonly<{ inputTrees: readonly Address[]; outputTree: Address }>;

/** The accounts and bindings a policy statement reads, absent on an audit-only ring. */
export interface RingTransactPolicy {
  /** Distinct SPP trees in proof slot order, one history context each. */
  readonly trees: readonly Address[];
  readonly treeContexts: readonly TreeContext[];
  /** The bound own-registry history slot, required for every policy proof. */
  readonly memberRegistryRootIndex?: number;
  /** The root at `memberRegistryRootIndex` the proof binds, a failed proof checks the slot for it. */
  readonly memberRegistryRoot?: Bytes32;
  readonly foreignRegistry?: Address;
  readonly foreignRootIndex?: number;
  readonly foreignRoot?: Bytes32;
}

/** Mirrors Rust `CreateConfig`. The authority signs, so the recorded authority consented to the role. */
export async function createRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: X25519PublicKey;
    /** A policy ring enforces its compiled rules, an audit-only ring skips them. */
    hasPolicy: boolean;
  }>,
): Promise<Instruction> {
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  // The final zero byte selects the supported non-anonymous ring mode.
  const data = new Uint8Array(1 + 33 + 1 + 1);
  data[0] = RingProgramTag.createConfig;
  data.set(input.auditorPublicKey.toBytes(), 1);
  data[34] = input.hasPolicy ? 1 : 0;
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
    ],
    data,
  };
}

export async function initializeRingConfigInstructions(
  input: Parameters<typeof createRingConfigInstruction>[0] & Readonly<{ depositAudit?: boolean }>,
): Promise<readonly Instruction[]> {
  if (input.depositAudit !== undefined && typeof input.depositAudit !== "boolean")
    throw new RingError("RING_DEPOSIT_AUDIT_INVALID");
  const config = await createRingConfigInstruction(input);
  return Object.freeze(
    input.depositAudit === true
      ? [config, await setRingDepositAuditInstruction({ ...input, required: true })]
      : [config],
  );
}

/** Mirrors Rust `InitSppRingConfig`. `ringAuth` stays unsigned, the ring program signs it inside its CPI. */
export async function initSppRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    /** A policy ring registers only after its policy config exists. */
    hasPolicy: boolean;
  }>,
): Promise<Instruction> {
  const [config, protocolConfig, ringAuth, policyConfig] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    protocolConfigAddress(),
    ringAuthAddress(input.ringProgramId),
    input.hasPolicy ? ringPolicyConfigAddress(input.ringProgramId) : undefined,
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(protocolConfig, false, false),
      meta(ringAuth, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      ...(policyConfig === undefined ? [] : [meta(policyConfig, false, false)]),
    ],
    data: Uint8Array.of(RingProgramTag.initSppRingConfig),
  };
}

type RingTransactCommon = RingTransactTrees &
  Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    policy?: RingTransactPolicy;
    proof: Uint8Array;
    data: TransactInstructionData;
    cosigner?: SignerAccount;
    /** Must equal the proof's approval bit. */
    approvalRequired?: boolean;
  }>;

export async function ringTransactInstruction(
  input: RingTransactCommon &
    Readonly<{
      /** Non-payer input owners, the ed25519 rail adds them as signers. */
      ownerSigners?: readonly SignerAccount[];
      /** Settlement accounts for a public withdrawal in `data.interfaceTransfers`. */
      withdrawal?: TransactWithdrawal;
    }>,
): Promise<Instruction> {
  if ("cacheAccess" in input.data.circuit) {
    throw new RingError("RING_CACHE_UNSUPPORTED", { details: { kind: input.data.circuit.kind } });
  }
  const [config, ringAuth, cosignerPda, policy] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    policyAccountMetas(input.ringProgramId, input.policy),
  ]);
  const raw = await ringTransactAccounts({
    payer: input.payer,
    inputTrees: input.inputTrees,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    treeContexts: input.data.treeContexts,
    ...(input.ownerSigners === undefined ? {} : { ownerSigners: input.ownerSigners }),
    ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
  });
  // The namespace PDA signs only inside the program's CPI.
  const namespace =
    input.policy === undefined ? undefined : await ringPolicyNamespaceAddress(input.ringProgramId);
  const pool = raw.map((account) =>
    account.address === namespace && isSignerRole(account.role)
      ? { address: account.address, role: downgradeRoleToNonSigner(account.role) }
      : account,
  );
  return {
    programAddress: input.ringProgramId,
    accounts: [
      { address: config, role: AccountRole.READONLY },
      ...ringCoSignerMetas(cosignerPda, input.cosigner),
      ...policy,
      ...pool,
    ],
    data: transactData(RingProgramTag.transact, input),
  };
}

/** Mirrors Rust `CustomRingTransactIxData`. */
function transactData(
  tag: number,
  input: Readonly<{
    proof: Uint8Array;
    policy?: RingTransactPolicy;
    approvalRequired?: boolean;
    data: TransactInstructionData;
  }>,
): Uint8Array {
  const proof = checkedCustomRingProof(input.proof);
  const policy = input.policy;
  const contexts = policy?.treeContexts ?? [];
  const prefix = new Writer().u8(contexts.length, "policyTrees.length");
  for (const context of contexts) writeTreeContext(prefix, context);
  prefix
    .u8(policy?.memberRegistryRootIndex ?? 0, "registryRootIndex")
    .u8(policy?.foreignRootIndex ?? 0, "foreignRootIndex")
    .bool(input.approvalRequired === true, "approvalRequired");
  const prefixBytes = prefix.finish();
  const transact = encodeTransactInstructionData(input.data);
  const data = new Uint8Array(1 + proof.length + prefixBytes.length + transact.length);
  data[0] = tag;
  data.set(proof, 1);
  data.set(prefixBytes, 1 + proof.length);
  data.set(transact, 1 + proof.length + prefixBytes.length);
  return data;
}

/** Mirrors Rust `CustomRingDelegateTransact`, the delegate signs and value stays inside the ring. */
export async function ringDelegateTransactInstruction(
  input: RingTransactCommon & Readonly<{ delegate: SignerAccount }>,
): Promise<Instruction> {
  if (input.approvalRequired === true) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "approvalRequired" } });
  }
  if (input.data.interfaceTransfers.length > 0) {
    throw new RingError("RING_DELEGATE_PUBLIC_LEG", {
      details: { legs: input.data.interfaceTransfers.length },
    });
  }
  // The caller binds policy roots; the program checks that its config enables escrow.
  if (input.policy?.memberRegistryRootIndex === undefined) {
    throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "keyEscrow" } });
  }
  const [config, ringAuth, cosignerPda, delegatePda, policy] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    ringDelegateAddress(input.ringProgramId),
    policyAccountMetas(input.ringProgramId, input.policy),
  ]);
  const pool = await ringTransactAccounts({
    payer: input.payer,
    inputTrees: input.inputTrees,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    treeContexts: input.data.treeContexts,
  });
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(config, false, false),
      ...ringCoSignerMetas(cosignerPda, input.cosigner),
      meta(delegatePda, false, false),
      meta(input.delegate, true, false),
      ...policy,
      ...pool,
    ],
    data: transactData(RingProgramTag.delegateTransact, input),
  };
}

/** The mint of every public leg in leg order, an SPL leg settles through `withdrawal`. */
/** Mirrors Rust `TransactRail::verify_and_forward`, read-only and before the SPP list. */
async function policyAccountMetas(
  ringProgramId: Address,
  policy: RingTransactPolicy | undefined,
): Promise<readonly { address: Address; role: AccountRole }[]> {
  if (policy === undefined) return [];
  if (policy.trees.length !== policy.treeContexts.length) {
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED", {
      details: { policyTrees: policy.trees.length, treeContexts: policy.treeContexts.length },
    });
  }
  for (const index of [policy.memberRegistryRootIndex, policy.foreignRootIndex ?? 0])
    if (index === undefined || !Number.isInteger(index) || index < 0 || index >= 32)
      throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED");
  if (policy.foreignRegistry === undefined && (policy.foreignRootIndex ?? 0) !== 0)
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED");
  const [policyConfig, memberRegistryRoot] = await Promise.all([
    ringPolicyConfigAddress(ringProgramId),
    ringMemberRegistryRootAddress(ringProgramId),
  ]);
  return [
    policyConfig,
    ...policy.trees,
    memberRegistryRoot,
    ...(policy.foreignRegistry === undefined ? [] : [policy.foreignRegistry]),
  ].map((address) => ({ address, role: AccountRole.READONLY }));
}

export interface RingSharedSource {
  readonly listId: ListId;
  readonly curatorRingProgramId: Address;
}

export interface RingPolicyTableInput {
  readonly table: RuleTable;
  /** Every other referenced list reads the ring's own entries. */
  readonly sharedSources?: readonly RingSharedSource[];
}

/** Mirrors Rust `CreatePolicy`, signed by the upgrade authority. */
export async function createRingPolicyInstruction(
  input: RingPolicyTableInput &
    Readonly<{
      ringProgramId: Address;
      payer: SignerAccount;
      authority: SignerAccount;
      addressTree: Address;
    }>,
): Promise<Instruction> {
  const [config, policyConfig, programData, body] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringPolicyConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
    policyTableBody(input),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(policyConfig, false, true),
      meta(input.addressTree, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
      ...body.curatorRegistries.map((account) => meta(account, false, false)),
    ],
    data: Uint8Array.of(RingProgramTag.createPolicy, ...body.data),
  };
}

/** Mirrors Rust `SetPolicyRules`, a new generation under the upgrade authority. */
export async function setRingPolicyRulesInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  const [config, policyConfig, programData, body] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringPolicyConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
    policyTableBody(input),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(policyConfig, false, true),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
      ...body.curatorRegistries.map((account) => meta(account, false, false)),
    ],
    data: Uint8Array.of(RingProgramTag.setPolicyRules, ...body.data),
  };
}

export type RingPolicySourceOwner =
  | Readonly<{ kind: "own" }>
  | Readonly<{ kind: "curator"; ringProgramId: Address }>;

/** Mirrors Rust `SetSourceOwner`, signed by the config authority. */
export async function setRingPolicySourceInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    listId: ListId;
    source: RingPolicySourceOwner;
  }>,
): Promise<Instruction> {
  const [config, policyConfig, curatorPolicyConfig] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringPolicyConfigAddress(input.ringProgramId),
    input.source.kind === "curator"
      ? ringMemberRegistryRootAddress(input.source.ringProgramId)
      : undefined,
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(policyConfig, false, true),
      ...(curatorPolicyConfig === undefined ? [] : [meta(curatorPolicyConfig, false, false)]),
    ],
    data: Uint8Array.of(
      RingProgramTag.setPolicySource,
      checkedListId(input.listId),
      curatorPolicyConfig === undefined ? 0 : 1,
    ),
  };
}

/** Mirrors Rust `ProvenKeyRegistration::instruction`, the member signs and pays. */
export async function registerRingKeyInstruction(
  input: Readonly<{
    ringProgramId: Address;
    member: SignerAccount;
    proof: Uint8Array;
    registryOldRootIndex: number;
    registryNewRoot: Bytes32;
    item: import("../interface/member-registry.js").MemberUpdate;
    nullifierPublicKey: Bytes32;
    ephemeralPublicKey: Bytes33;
    ciphertext: Bytes32;
  }>,
): Promise<Instruction> {
  checkedRegistryIndex(input.registryOldRootIndex);
  checkedRegistryField(input.registryNewRoot);
  updateMembersPublicInputHash(new Uint8Array(32) as Bytes32, input.registryNewRoot, [input.item]);
  const [config, root] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringMemberRegistryRootAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.member, true, false),
      meta(config, false, false),
      meta(root, false, true),
    ],
    data: writeMemberUpdate(
      new Writer()
        .u8(RingProgramTag.registerKey, "tag")
        .bytes(checkedCustomRingProof(input.proof), CUSTOM_RING_PROOF_LENGTH, "proof")
        .u8(input.registryOldRootIndex, "registryOldRootIndex")
        .bytes(input.registryNewRoot, 32, "registryNewRoot"),
      input.item,
    )
      .bytes(input.nullifierPublicKey, 32, "nullifierPublicKey")
      .bytes(input.ephemeralPublicKey, 33, "ephemeralPublicKey")
      .bytes(input.ciphertext, 32, "ciphertext")
      .finish(),
  };
}

async function policyTableBody(
  input: RingPolicyTableInput,
): Promise<Readonly<{ data: Uint8Array; curatorRegistries: readonly Address[] }>> {
  const referenced = referencedLists(input.table.rules);
  const shared = input.sharedSources ?? [];
  const seen = new Set<ListId>();
  for (const source of shared) {
    const reason = !referenced.includes(source.listId)
      ? "UnreferencedList"
      : seen.has(source.listId)
        ? "DuplicateList"
        : undefined;
    if (reason !== undefined) {
      throw new RingError("RING_POLICY_SOURCE_INVALID", {
        details: { reason, listId: source.listId },
      });
    }
    seen.add(source.listId);
  }
  const curators: Address[] = [];
  const writer = new Writer().u8(referenced.length, "sources.length");
  for (const listId of referenced) {
    const curator = shared.find((source) => source.listId === listId)?.curatorRingProgramId;
    let source = 0;
    if (curator !== undefined) {
      if (!curators.includes(curator)) curators.push(curator);
      source = 1 + curators.indexOf(curator);
    }
    writer.u8(listId, "listId").u8(source, "source");
  }
  if (curators.length > 1)
    throw new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason: "MultipleCurators" } });
  const encoded = encodeRuleTable(input.table);
  writer.u8(encoded.ruleCount, "rules.length");
  for (const row of encoded.rules) writer.bytes(row, 32, "rule");
  writer.u8(encoded.inlineCount, "inlineAssets.length");
  for (const asset of encoded.inlineAssets) writer.bytes(asset, 32, "inlineAsset");
  writer.u8(encoded.inlineCount, "inlineLimits.length");
  for (const limit of encoded.inlineLimits) writer.u64(limit, "inlineLimit");
  writer.u8(encoded.limitCount, "limits.length");
  for (const limit of encoded.limits) {
    writer
      .bytes(limit.asset, 32, "limits.asset")
      .u64(limit.cap, "limits.cap")
      .u64(limit.cosignAbove, "limits.cosignAbove");
  }
  return Object.freeze({
    data: writer.finish(),
    curatorRegistries: await Promise.all(curators.map(ringMemberRegistryRootAddress)),
  });
}

export async function ringMergeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    data: MergeTransactInstructionData;
    outputRingDataHash: Bytes32;
    cosigner?: SignerAccount;
  }>,
): Promise<Instruction> {
  const [config, cosigner, auth, nullifiers] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    Promise.all(input.data.nullifiers.map((value) => nullifierPdaAddress(input.inputTree, value))),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(config, false, false),
      ...ringCoSignerMetas(cosigner, input.cosigner),
      meta(input.inputTree, false, true),
      meta(input.outputTree, false, true),
      meta(auth, false, false),
      meta(input.payer, true, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      ...nullifiers.map((key) => meta(key, false, true)),
    ],
    data: new Writer()
      .u8(InstructionTag.ringMergeTransact, "instructionTag")
      .bytes(input.outputRingDataHash, 32, "outputRingDataHash")
      .bytes(encodeMergeTransactInstructionData(input.data))
      .finish(),
  };
}

function writeMemberUpdate(
  writer: Writer,
  item: import("../interface/member-registry.js").MemberUpdate,
): Writer {
  return writer
    .bytes(item.member, 32, "member")
    .u64(item.oldLists, "oldLists")
    .bytes(item.oldEscrowKey, 32, "oldEscrowKey")
    .u64(item.lists, "lists")
    .bytes(item.escrowKey, 32, "escrowKey")
    .u64(item.index, "index");
}

export async function updateRingMembersInstruction(
  input: Readonly<{
    ringProgramId: Address;
    proof: Uint8Array;
    oldRootIndex: number;
    newRoot: Bytes32;
    items: readonly import("../interface/member-registry.js").MemberUpdate[];
    signers: readonly SignerAccount[];
  }>,
): Promise<Instruction> {
  checkedRegistryIndex(input.oldRootIndex);
  updateMembersPublicInputHash(new Uint8Array(32) as Bytes32, input.newRoot, input.items);
  const [config, root] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringMemberRegistryRootAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingProgramTag.updateMembers, "tag")
    .bytes(checkedCustomRingProof(input.proof), CUSTOM_RING_PROOF_LENGTH, "proof")
    .u8(input.oldRootIndex, "oldRootIndex")
    .bytes(input.newRoot, 32, "newRoot")
    .u8(input.items.length, "items.length");
  for (const item of input.items) writeMemberUpdate(data, item);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(config, false, false),
      meta(root, false, true),
      ...input.signers.map((signer) => meta(signer, true, false)),
    ],
    data: data.finish(),
  };
}

function checkedRegistryIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= 32)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID");
}
