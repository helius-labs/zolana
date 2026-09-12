import { AccountRole, type Address, type Instruction } from "@solana/kit";

import {
  SYSTEM_PROGRAM,
  meta,
  ringTransactAccounts,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { encodeTransactInstructionData } from "../interface/codecs/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import {
  nullifierPdaAddress,
  protocolConfigAddress,
  ringAuthAddress,
} from "../interface/pda/index.js";
import type { TransactInstructionData, TransactWithdrawal } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";
import type { P256PublicKey } from "../keypair/public-key.js";

import { Writer } from "../interface/internal.js";

import { checkedCustomRingProof } from "./codecs.js";
import {
  ringConfigAddress,
  ringPolicyConfigAddress,
  ringPolicyNamespaceAddress,
  ringProgramDataAddress,
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
  createPolicy: 7,
  createEntry: 8,
  updateEntry: 9,
  setPolicySource: 10,
  setPolicyRules: 12,
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

/** Mirrors Rust `CustomRingTransact`, `tag || proof || state root index || nullifier root index || transact data`. */
export async function ringTransactInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    /** Read for the policy roots, never forwarded to SPP. */
    entriesTree?: Address;
    /** False drops the policy_config and entries_tree accounts. */
    hasPolicy?: boolean;
    proof: Uint8Array;
    /** History entries the ring statement binds, unread by a ring without rules. */
    stateRootIndex: number;
    nullifierRootIndex: number;
    data: TransactInstructionData;
    /** Non-payer input owners, the ed25519 rail adds them as signers. */
    ownerSigners?: readonly SignerAccount[];
    /** Settlement accounts for a public withdrawal in `data.interfaceTransfers`. */
    withdrawal?: TransactWithdrawal;
  }>,
): Promise<Instruction> {
  const hasPolicy = input.hasPolicy ?? true;
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const payerAddress = typeof input.payer === "string" ? input.payer : input.payer.address;
  const pool = await ringTransactAccounts({
    payer: input.payer,
    inputTree: input.inputTree,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    treeContexts: input.data.treeContexts,
    ...(input.ownerSigners === undefined ? {} : { ownerSigners: input.ownerSigners }),
    ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
  });
  const proof = checkedCustomRingProof(input.proof);
  const rootIndexes = new Writer()
    .u16(input.stateRootIndex, "stateRootIndex")
    .u16(input.nullifierRootIndex, "nullifierRootIndex")
    .finish();
  const transact = encodeTransactInstructionData(input.data);
  const data = new Uint8Array(1 + proof.length + rootIndexes.length + transact.length);
  data[0] = RingProgramTag.transact;
  data.set(proof, 1);
  data.set(rootIndexes, 1 + proof.length);
  data.set(transact, 1 + proof.length + rootIndexes.length);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      {
        address: payerAddress,
        role: AccountRole.WRITABLE_SIGNER,
        ...(typeof input.payer === "string" ? {} : { signer: input.payer }),
      },
      { address: config, role: AccountRole.READONLY },
      ...(hasPolicy ? await policyAccountMetas(input.ringProgramId, input.entriesTree) : []),
      ...pool,
    ],
    data,
  };
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
  const [policyConfig, programData, body] = await Promise.all([
    ringPolicyConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
    policyTableBody(input),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
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
  input: RingEntryInstructionInput,
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
  return Object.freeze({
    data: writer.finish(),
    curatorPolicyConfigs: await Promise.all(curators.map(ringPolicyConfigAddress)),
  });
}
