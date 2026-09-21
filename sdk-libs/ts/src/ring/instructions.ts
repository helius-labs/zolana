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
  ringSpendWindowMetas,
  ringTransactAccounts,
  signerAddress,
  type SignerAccount,
} from "../interface/instructions/index.js";
import {
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
} from "../interface/codecs/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import {
  nullifierPdaAddress,
  protocolConfigAddress,
  ringAuthAddress,
  ringCoSignerAddress,
  ringConfigAddress,
  ringDelegateAddress,
  ringHeadMapRootAddress,
  ringKeyRegistryRootAddress,
  ringPolicyConfigAddress,
} from "../interface/pda/index.js";
import type {
  MergeTransactInstructionData,
  Bytes32,
  Bytes33,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import { SOL_MINT } from "../transaction/asset.js";

import { Writer } from "../interface/internal.js";

import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import { checkedCustomRingProof } from "./codecs.js";
import {
  ringPolicyNamespaceAddress,
  ringProgramDataAddress,
  setRingDepositAuditInstruction,
} from "./config.js";
import type { RingEntryProof } from "./entry-proof.js";
import { RingError } from "./error.js";
import {
  encodeRuleTable,
  checkedListId,
  referencedLists,
  type ListEntry,
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
  createEntry: 8,
  updateEntry: 9,
  setPolicySource: 10,
  setPolicyRules: 12,
  registerSpend: 26,
  registerKey: 30,
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
export const RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT = RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;
export const RING_REGISTER_KEY_COMPUTE_UNIT_LIMIT = RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT;

export type RingTransactTrees = Readonly<{ tree: Address; outputTree: Address }> &
  (
    | Readonly<{ hasPolicy: false }>
    | Readonly<{
        hasPolicy: true;
        /** The pinned `PolicyConfig.entriesTree`. */
        entriesTree: Address;
      }>
  );

/** Mirrors Rust `CreateConfig`. The authority signs, so the recorded authority consented to the role. */
export async function createRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: P256PublicKey;
    /** A policy ring enforces its compiled rules, an audit-only ring skips them. */
    hasPolicy: boolean;
  }>,
): Promise<Instruction> {
  if (isDerivationPoint(input.auditorPublicKey)) {
    throw new RingError("RING_RESERVED_AUDITOR_KEY");
  }
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Uint8Array(1 + 33 + 1);
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

type RingTransactCommon = Readonly<{
  ringProgramId: Address;
  payer: SignerAccount;
  inputTree: Address;
  outputTree: Address;
  /** Read for the policy roots, never forwarded to SPP. */
  entriesTree?: Address;
  /** False drops the policy_config and entries_tree accounts. */
  hasPolicy?: boolean;
  proof: Uint8Array;
  /** History entries the ring statement binds, unread by an audit-only ring. */
  stateRootIndex: number;
  nullifierRootIndex: number;
  data: TransactInstructionData;
  cosigner?: SignerAccount;
  /** Must equal the proof's approval bit. */
  approvalRequired?: boolean;
  headTransition?: Readonly<{ oldRoot: Bytes32; newRoot: Bytes32 }>;
  revocationTargets?: readonly Bytes32[];
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
  const hasPolicy = input.hasPolicy ?? true;
  const entriesTree = input.entriesTree;
  const [config, ringAuth, cosignerPda, windows, revocationPdas] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    ringSpendWindowMetas(input.ringProgramId, settledMints(input.data, input.withdrawal)),
    entriesTree === undefined
      ? []
      : Promise.all(
          (input.revocationTargets ?? [])
            .filter((target) => target.some((byte) => byte !== 0))
            .map((target) => nullifierPdaAddress(entriesTree, target)),
        ),
  ]);
  const payerAddress = signerAddress(input.payer);
  const raw = await ringTransactAccounts({
    payer: input.payer,
    inputTree: input.inputTree,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    treeContexts: input.data.treeContexts,
    ...(input.ownerSigners === undefined ? {} : { ownerSigners: input.ownerSigners }),
    ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
  });
  // The namespace PDA signs only inside the program's CPI.
  const namespace = hasPolicy ? await ringPolicyNamespaceAddress(input.ringProgramId) : undefined;
  const pool = raw.map((account) =>
    account.address === namespace && isSignerRole(account.role)
      ? { address: account.address, role: downgradeRoleToNonSigner(account.role) }
      : account,
  );
  return {
    programAddress: input.ringProgramId,
    accounts: [
      {
        address: payerAddress,
        role: AccountRole.WRITABLE_SIGNER,
        ...(typeof input.payer === "string" ? {} : { signer: input.payer }),
      },
      { address: config, role: AccountRole.READONLY },
      ...ringCoSignerMetas(cosignerPda, input.cosigner),
      ...(hasPolicy ? await policyAccountMetas(input.ringProgramId, input.entriesTree) : []),
      ...(input.headTransition === undefined
        ? []
        : [
            {
              address: await ringHeadMapRootAddress(input.ringProgramId),
              role: AccountRole.WRITABLE,
            },
          ]),
      ...revocationPdas.map((address) => ({ address, role: AccountRole.READONLY })),
      ...windows,
      ...pool,
    ],
    data: transactData(RingProgramTag.transact, input),
  };
}

function transactData(
  tag: number,
  input: Readonly<{
    proof: Uint8Array;
    stateRootIndex: number;
    nullifierRootIndex: number;
    approvalRequired?: boolean;
    headTransition?: Readonly<{ oldRoot: Bytes32; newRoot: Bytes32 }>;
    revocationTargets?: readonly Bytes32[];
    data: TransactInstructionData;
  }>,
): Uint8Array {
  const proof = checkedCustomRingProof(input.proof);
  const prefix = new Writer()
    .u16(input.stateRootIndex, "stateRootIndex")
    .u16(input.nullifierRootIndex, "nullifierRootIndex")
    .u8(input.approvalRequired === true ? 1 : 0, "approvalRequired")
    .u8(input.headTransition === undefined ? 0 : 1, "headTransition");
  if (input.headTransition !== undefined)
    prefix
      .bytes(input.headTransition.oldRoot, 32, "headOldRoot")
      .bytes(input.headTransition.newRoot, 32, "headNewRoot");
  const targets = input.revocationTargets ?? [];
  if (targets.length !== 0 && targets.length !== 10) {
    throw new RingError("RING_POLICY_SHAPE_UNSUPPORTED", {
      details: { revocationTargets: targets.length },
    });
  }
  for (let index = 0; index < 10; index++) {
    prefix.bytes(targets[index] ?? new Uint8Array(32), 32, "revocationTarget");
  }
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
  if (input.headTransition !== undefined || input.approvalRequired === true) {
    throw new RingError("RING_DELEGATE_ON_VELOCITY_RING", {
      details: {
        headTransition: input.headTransition !== undefined,
        approvalRequired: input.approvalRequired === true,
      },
    });
  }
  if (input.data.interfaceTransfers.length > 0) {
    throw new RingError("RING_DELEGATE_PUBLIC_LEG", {
      details: { legs: input.data.interfaceTransfers.length },
    });
  }
  const hasPolicy = input.hasPolicy ?? true;
  const entriesTree = input.entriesTree;
  const [config, ringAuth, cosignerPda, delegatePda, revocationPdas] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    ringDelegateAddress(input.ringProgramId),
    entriesTree === undefined
      ? []
      : Promise.all(
          (input.revocationTargets ?? [])
            .filter((target) => target.some((byte) => byte !== 0))
            .map((target) => nullifierPdaAddress(entriesTree, target)),
        ),
  ]);
  const pool = await ringTransactAccounts({
    payer: input.payer,
    inputTree: input.inputTree,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    treeContexts: input.data.treeContexts,
  });
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(config, false, false),
      ...ringCoSignerMetas(cosignerPda, input.cosigner),
      meta(delegatePda, false, false),
      meta(input.delegate, true, false),
      ...(hasPolicy ? await policyAccountMetas(input.ringProgramId, input.entriesTree) : []),
      ...revocationPdas.map((address) => ({ address, role: AccountRole.READONLY })),
      ...pool,
    ],
    data: transactData(RingProgramTag.delegateTransact, input),
  };
}

/** The mint of every public leg in leg order, an SPL leg settles through `withdrawal`. */
function settledMints(
  data: TransactInstructionData,
  withdrawal: TransactWithdrawal | undefined,
): Address[] {
  return data.interfaceTransfers.map((leg) => {
    if (leg.kind === "solDeposit" || leg.kind === "solWithdrawal") return SOL_MINT;
    if (withdrawal?.kind !== "spl") {
      throw new RingError("RING_BUILD_WITHDRAWAL", { details: { leg: leg.kind } });
    }
    return withdrawal.mint;
  });
}

/** The policy tier reads `policy_config` and `entries_tree`, read-only and before the SPP list. */
async function policyAccountMetas(
  ringProgramId: Address,
  entriesTree: Address | undefined,
): Promise<readonly { address: Address; role: AccountRole }[]> {
  if (entriesTree === undefined) {
    throw new RingError("RING_ENTRIES_TREE_REQUIRED", { details: { ringProgramId } });
  }
  const policyConfig = await ringPolicyConfigAddress(ringProgramId);
  return [
    { address: policyConfig, role: AccountRole.READONLY },
    { address: entriesTree, role: AccountRole.READONLY },
  ];
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
      entriesTree: Address;
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
      meta(input.entriesTree, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
      ...body.curatorPolicyConfigs.map((account) => meta(account, false, false)),
    ],
    data: Uint8Array.of(RingProgramTag.createPolicy, ...body.data),
  };
}

/** Mirrors Rust `SetPolicyRules`, a new generation under the upgrade authority. */
export async function setRingPolicyRulesInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  const [policyConfig, programData, body] = await Promise.all([
    ringPolicyConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
    policyTableBody(input),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.authority, true, false),
      meta(policyConfig, false, true),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
      ...body.curatorPolicyConfigs.map((account) => meta(account, false, false)),
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
      ? ringPolicyConfigAddress(input.source.ringProgramId)
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

export interface RingEntryInstructionInput {
  readonly ringProgramId: Address;
  /** An authority list needs the config authority, a member list the member's key. */
  readonly payer: SignerAccount;
  readonly entriesTree: Address;
  readonly entry: ListEntry;
  readonly proof: RingEntryProof;
}

/** Mirrors Rust `ProvenEntry::instruction` for a claim at version zero. */
export async function createRingEntryInstruction(
  input: RingEntryInstructionInput,
): Promise<Instruction> {
  const data = new Writer()
    .u8(RingProgramTag.createEntry, "tag")
    .u8(input.entry.listId, "listId")
    .bytes(input.entry.member, 32, "member");
  writeEntryTail(data, input.entry, input.proof);
  return entryInstruction(input, data.finish());
}

/** Mirrors Rust `ProvenEntry::instruction` for a spend, the spent fields rebuild the live leaf. */
export async function updateRingEntryInstruction(
  input: RingEntryInstructionInput & Readonly<{ spent: ListEntry }>,
): Promise<Instruction> {
  const data = new Writer()
    .u8(RingProgramTag.updateEntry, "tag")
    .u8(input.entry.listId, "listId")
    .bytes(input.entry.member, 32, "member")
    .u8(entryStateByte(input.spent), "spentState")
    .bytes(input.spent.contentHash, 32, "spentContentHash")
    .u64(input.spent.version, "spentVersion")
    .bytes(input.spent.blinding, 32, "spentBlinding");
  writeEntryTail(data, input.entry, input.proof);
  return entryInstruction(input, data.finish());
}

/** Mirrors Rust `ProvenSpendRegistration::instruction`, the record content is derived on chain. */
export async function registerRingSpendInstruction(
  input: Readonly<{
    ringProgramId: Address;
    /** The member, its Solana key is the record's identity. */
    payer: SignerAccount;
    entriesTree: Address;
    /** The SPP output blinding the registration proof derived. */
    blinding: Bytes32;
    proof: RingEntryProof;
    headOldRoot: Bytes32;
    headNewRoot: Bytes32;
    headNextIndex: bigint;
    headProof: Uint8Array;
  }>,
): Promise<Instruction> {
  const data = new Writer()
    .u8(RingProgramTag.registerSpend, "tag")
    .bytes(input.blinding, 32, "blinding")
    .bytes(input.proof.privateTxBlinding, 32, "privateTxBlinding")
    .u16(input.proof.nullifierTreeRootIndex, "nullifierTreeRootIndex")
    .u16(input.proof.utxoTreeRootIndex, "utxoTreeRootIndex")
    .bytes(input.proof.proof.a, 32, "proof.a")
    .bytes(input.proof.proof.b, 128, "proof.b")
    .bytes(input.proof.proof.c, 32, "proof.c")
    .bytes(input.headOldRoot, 32, "headOldRoot")
    .bytes(input.headNewRoot, 32, "headNewRoot")
    .u64(input.headNextIndex, "headNextIndex")
    .bytes(input.headProof, 128, "headProof");
  const instruction = await entryInstruction(input, data.finish());
  const headMapRoot = await ringHeadMapRootAddress(input.ringProgramId);
  return {
    ...instruction,
    accounts: [...(instruction.accounts ?? []), meta(headMapRoot, false, true)],
  };
}

/** Mirrors Rust `ProvenKeyRegistration::instruction`, the member signs and pays. */
export async function registerRingKeyInstruction(
  input: Readonly<{
    ringProgramId: Address;
    member: SignerAccount;
    proof: Uint8Array;
    registryOldRoot: Bytes32;
    registryNewRoot: Bytes32;
    registryNextIndex: bigint;
    nullifierPublicKey: Bytes32;
    ephemeralPublicKey: Bytes33;
    ciphertext: Bytes32;
  }>,
): Promise<Instruction> {
  const [config, root] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringKeyRegistryRootAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.member, true, false),
      meta(config, false, false),
      meta(root, false, true),
    ],
    data: new Writer()
      .u8(RingProgramTag.registerKey, "tag")
      .bytes(checkedCustomRingProof(input.proof), CUSTOM_RING_PROOF_LENGTH, "proof")
      .bytes(input.registryOldRoot, 32, "registryOldRoot")
      .bytes(input.registryNewRoot, 32, "registryNewRoot")
      .u64(input.registryNextIndex, "registryNextIndex")
      .bytes(input.nullifierPublicKey, 32, "nullifierPublicKey")
      .bytes(input.ephemeralPublicKey, 33, "ephemeralPublicKey")
      .bytes(input.ciphertext, 32, "ciphertext")
      .finish(),
  };
}

function writeEntryTail(writer: Writer, entry: ListEntry, proof: RingEntryProof): void {
  writer
    .u8(entryStateByte(entry), "state")
    .bytes(entry.contentHash, 32, "contentHash")
    .bytes(entry.blinding, 32, "blinding")
    .bytes(proof.privateTxBlinding, 32, "privateTxBlinding")
    .u16(proof.nullifierTreeRootIndex, "nullifierTreeRootIndex")
    .u16(proof.utxoTreeRootIndex, "utxoTreeRootIndex")
    .bytes(proof.proof.a, 32, "proof.a")
    .bytes(proof.proof.b, 128, "proof.b")
    .bytes(proof.proof.c, 32, "proof.c");
}

function entryStateByte(entry: ListEntry): number {
  return entry.state === "active" ? 1 : 2;
}

/** Everything after the two config accounts is forwarded to SPP position for position. */
async function entryInstruction(
  input: Pick<RingEntryInstructionInput, "ringProgramId" | "payer" | "entriesTree" | "proof">,
  data: Uint8Array,
): Promise<Instruction> {
  const [config, policyConfig, namespace, nullifierPda] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringPolicyConfigAddress(input.ringProgramId),
    ringPolicyNamespaceAddress(input.ringProgramId),
    nullifierPdaAddress(input.entriesTree, input.proof.nullifier),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(config, false, false),
      meta(policyConfig, false, false),
      meta(input.payer, true, true),
      meta(input.entriesTree, false, true),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.entriesTree, false, true),
      meta(nullifierPda, false, true),
      meta(namespace, false, false),
    ],
    data,
  };
}

/** Mirrors Rust `PolicyTable::body`, curators indexed in first-use order. */
async function policyTableBody(
  input: RingPolicyTableInput,
): Promise<Readonly<{ data: Uint8Array; curatorPolicyConfigs: readonly Address[] }>> {
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
  const encoded = encodeRuleTable(input.table);
  writer.u8(encoded.ruleCount, "rules.length");
  for (const row of encoded.rules) writer.bytes(row, 32, "rule");
  writer.u8(encoded.inlineCount, "inlineAssets.length");
  for (const asset of encoded.inlineAssets) writer.bytes(asset, 32, "inlineAsset");
  writer.u8(encoded.inlineCount, "inlineLimits.length");
  for (const limit of encoded.inlineLimits) writer.u64(limit, "inlineLimit");
  writer.u64(encoded.windowSlots, "windowSlots");
  writer.u8(encoded.velocityCount, "velocity.length");
  for (const row of encoded.velocity) {
    writer
      .bytes(row.asset, 32, "velocity.asset")
      .u64(row.cap, "velocity.cap")
      .u64(row.cosignAbove, "velocity.cosignAbove");
  }
  return Object.freeze({
    data: writer.finish(),
    curatorPolicyConfigs: await Promise.all(curators.map(ringPolicyConfigAddress)),
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
    hasPolicy: boolean;
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
      ...(input.hasPolicy
        ? [meta(await ringPolicyConfigAddress(input.ringProgramId), false, false)]
        : []),
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
