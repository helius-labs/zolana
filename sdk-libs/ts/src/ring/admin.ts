import type { AccountMeta, Address, Instruction } from "@solana/kit";

import { checkTransactionFits } from "../flows/compile.js";
import {
  SYSTEM_PROGRAM,
  meta,
  signerAddress,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { Writer, addressBytes } from "../interface/internal.js";
import {
  protocolConfigAddress,
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../interface/pda/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { ZERO_32 } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

import {
  RING_COSIGN_SCOPE_MASK,
  RING_COSIGN_THRESHOLD_SLOTS,
  type RingCoSignThreshold,
} from "./codecs.js";
import { ringProgramDataAddress } from "./config.js";
import { RingError } from "./error.js";
import {
  checkedListId,
  encodeRule,
  policySourceLists,
  type ListId,
  type RuleTable,
} from "./policy.js";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  createConfig: 1,
  initSppRingConfig: 2,
  transact: 3,
  grantReadAccess: 4,
  revokeReadAccess: 5,
  setAuthority: 6,
  createPolicy: 7,
  setPolicySource: 10,
  setPaused: 11,
  setPolicyRules: 12,
  /** SPP's `RING_DEPOSIT`, always refused, `auditedDeposit` replaces it. */
  deposit: InstructionTag.ringDeposit,
  clearCoSigner: 21,
  merge: InstructionTag.ringMergeTransact,
  setDelegate: 24,
  delegateTransact: 25,
  setCoSigner: 27,
  createMemberRegistry: 28,
  registerKey: 29,
  auditedDeposit: 31,
  writeRecords: 39,
  authorityWriteRecords: 40,
  applyRecords: 41,
  setInsertFee: 42,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];

const ACCOUNT_UNITS = 50_000;
/** One policy hash plus a curator registry load. */
const POLICY_UNITS = 150_000;
/** A ring proof, most also CPI into SPP and its own proof. */
const PROOF_UNITS = 1_400_000;

/** Rust `compute_unit_limit`, the budget one instruction of `tag` declares. */
export function ringComputeUnitLimit(tag: RingInstructionTag): number {
  switch (tag) {
    case RingInstructionTag.createPolicy:
    case RingInstructionTag.setPolicySource:
    case RingInstructionTag.setPolicyRules:
      return POLICY_UNITS;
    case RingInstructionTag.transact:
    case RingInstructionTag.merge:
    case RingInstructionTag.delegateTransact:
    case RingInstructionTag.registerKey:
    case RingInstructionTag.auditedDeposit:
    case RingInstructionTag.authorityWriteRecords:
    case RingInstructionTag.applyRecords:
      return PROOF_UNITS;
    case RingInstructionTag.deposit:
      return 200_000;
    default:
      return ACCOUNT_UNITS;
  }
}

/** Rust `CustomRing::create_config`, the upgrade authority signs and becomes the ring authority. */
export async function createRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: X25519PublicKey;
    /** A policy ring enforces a table, an audit-only ring proves only the audit statement. */
    hasPolicy: boolean;
    /** Hides the sender and discloses every opening to the auditor, fixed for the ring's life. */
    anonymous: boolean;
  }>,
): Promise<Instruction> {
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.createConfig, "tag")
    .bytes(input.auditorPublicKey.toBytes(), 33, "auditorPubkey")
    .bool(input.hasPolicy, "hasPolicy")
    .bool(input.anonymous, "anonymous")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(config, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(input.ringProgramId, false, false),
    meta(programData, false, false),
  ]);
}

/** Rust `CustomRing::init_spp_ring_config`, a policy ring registers after its policy is set. */
export async function initSppRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    hasPolicy: boolean;
  }>,
): Promise<Instruction> {
  const [config, protocolConfig, ringAuth, registry] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    protocolConfigAddress(),
    ringAuthAddress(input.ringProgramId),
    ringMemberRegistryAddress(input.ringProgramId),
  ]);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.initSppRingConfig), [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(config, false, false),
    meta(protocolConfig, false, false),
    meta(ringAuth, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ...(input.hasPolicy ? [meta(registry, false, false)] : []),
  ]);
}

/** Rust `CustomRing::create_member_registry`, the registry with its sentinel and the record queue. */
export async function createMemberRegistryInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
  }>,
): Promise<Instruction> {
  const [config, registry, queue] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringMemberRegistryAddress(input.ringProgramId),
    ringRecordQueueAddress(input.ringProgramId),
  ]);
  return ringInstruction(
    input.ringProgramId,
    Uint8Array.of(RingInstructionTag.createMemberRegistry),
    [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(registry, false, true),
      meta(queue, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
  );
}

/** Rust `CustomRing::set_authority`, both keys sign so a mistyped address cannot strand the config. */
export async function setRingAuthorityInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    newAuthority: SignerAccount;
  }>,
): Promise<Instruction> {
  const config = await ringConfigAddress(input.ringProgramId);
  return ringInstruction(input.ringProgramId, Uint8Array.of(RingInstructionTag.setAuthority), [
    meta(input.authority, true, false),
    meta(input.newAuthority, true, false),
    meta(config, false, true),
  ]);
}

/** Rust `CustomRing::set_paused`. */
export async function setRingPausedInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    paused: boolean;
  }>,
): Promise<Instruction> {
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.setPaused, "tag")
    .bool(input.paused, "paused")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(config, false, false),
    meta(ringAuth, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ]);
}

/** Rust `CustomRing::set_cosigner`, a mint without a threshold always needs the co-signer. */
export async function setRingCoSignerInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    signer: Address;
    /** A nonzero subset of the `RING_COSIGN_*` bits. */
    scope: number;
    thresholds?: readonly RingCoSignThreshold[];
  }>,
): Promise<Instruction> {
  const thresholds = input.thresholds ?? [];
  checkCoSigner(input.signer, input.scope, thresholds);
  const writer = new Writer()
    .u8(RingInstructionTag.setCoSigner, "tag")
    .bytes(addressBytes(input.signer, "signer"), 32, "signer")
    .u8(input.scope, "scope")
    .u8(thresholds.length, "thresholds.length");
  for (const row of thresholds)
    writer.bytes(addressBytes(row.mint, "mint"), 32, "mint").u64(row.amount, "amount");
  return configWriteInstruction(input, writer.finish());
}

/** Rust `CustomRing::clear_cosigner`. */
export function clearRingCoSignerInstruction(
  input: Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  return configWriteInstruction(input, Uint8Array.of(RingInstructionTag.clearCoSigner));
}

/** Rust `CustomRing::set_insert_fee`, lamports a member's record write pays the authority, zero writes free. */
export function setRingInsertFeeInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    fee: bigint;
  }>,
): Promise<Instruction> {
  const data = new Writer()
    .u8(RingInstructionTag.setInsertFee, "tag")
    .u64(input.fee, "fee")
    .finish();
  return configWriteInstruction(input, data);
}

/** Rust `CustomRing::set_delegate`, signed by the upgrade authority, permanent and it turns key escrow on. */
export async function setRingDelegateInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    delegate: Address;
  }>,
): Promise<Instruction> {
  const delegate = addressBytes(input.delegate, "delegate");
  if (equalBytes(delegate, ZERO_32)) throw new RingError("RING_DELEGATE_INVALID");
  const [config, registry, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringMemberRegistryAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Writer()
    .u8(RingInstructionTag.setDelegate, "tag")
    .bytes(delegate, 32, "delegate")
    .finish();
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(config, false, true),
    meta(registry, false, false),
    meta(input.ringProgramId, false, false),
    meta(programData, false, false),
  ]);
}

/** Where a policy list is read, the ring's own registry or another ring's. */
export type RingPolicySourceOwner =
  | Readonly<{ kind: "own" }>
  | Readonly<{ kind: "curator"; ringProgramId: Address }>;

/** A referenced list read from a curator ring's registry. */
export interface RingSharedSource {
  readonly listId: ListId;
  readonly curatorRingProgramId: Address;
}

/** A table and the lists it reads from curators, every other referenced list reads the ring's own. */
export interface RingPolicyTableInput {
  readonly table: RuleTable;
  readonly sharedSources?: readonly RingSharedSource[];
}

/** Rust `CustomRing::set_source_owner`, re-points one referenced list, the rows stay. */
export async function setRingPolicySourceInstruction(
  input: Readonly<{
    ringProgramId: Address;
    authority: SignerAccount;
    listId: ListId;
    source: RingPolicySourceOwner;
  }>,
): Promise<Instruction> {
  const curator =
    input.source.kind === "curator"
      ? curatorRegistry(input.ringProgramId, input.source.ringProgramId)
      : undefined;
  const [accounts, curatorAccount] = await Promise.all([
    policyWriteMetas(input.ringProgramId, input.authority),
    curator,
  ]);
  return ringInstruction(
    input.ringProgramId,
    Uint8Array.of(
      RingInstructionTag.setPolicySource,
      checkedListId(input.listId),
      curatorAccount === undefined ? 0 : 1,
    ),
    curatorAccount === undefined ? accounts : [...accounts, meta(curatorAccount, false, false)],
  );
}

/** Rust `CustomRing::create_policy`, pins the table and its source map. */
export function createRingPolicyInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  return policyTableInstruction(RingInstructionTag.createPolicy, input);
}

/** Rust `CustomRing::set_policy_rules`, replaces the pinned table and the complete source map. */
export function setRingPolicyRulesInstruction(
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  return policyTableInstruction(RingInstructionTag.setPolicyRules, input);
}

/** `[authority, config]`, the config takes the write. */
async function configWriteInstruction(
  input: Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
  data: Uint8Array,
): Promise<Instruction> {
  const config = await ringConfigAddress(input.ringProgramId);
  return ringInstruction(input.ringProgramId, data, [
    meta(input.authority, true, false),
    meta(config, false, true),
  ]);
}

/** `CreatePolicy`, `SetPolicyRules` and `SetPolicySource` write the registry. */
async function policyWriteMetas(
  ringProgramId: Address,
  authority: SignerAccount,
): Promise<readonly AccountMeta[]> {
  const [config, registry] = await Promise.all([
    ringConfigAddress(ringProgramId),
    ringMemberRegistryAddress(ringProgramId),
  ]);
  return [meta(authority, true, false), meta(config, false, false), meta(registry, false, true)];
}

/** Rust `CustomRing::policy_table`, curator registries follow in first-use order and the transaction fits v1. */
async function policyTableInstruction(
  tag: typeof RingInstructionTag.createPolicy | typeof RingInstructionTag.setPolicyRules,
  input: RingPolicyTableInput & Readonly<{ ringProgramId: Address; authority: SignerAccount }>,
): Promise<Instruction> {
  const referenced = policySourceLists(input.table.rules);
  const shared = input.sharedSources ?? [];
  const seen = new Set<ListId>();
  for (const source of shared) {
    if (!referenced.includes(source.listId)) throw sourceInvalid("UnreferencedList", source.listId);
    if (seen.has(source.listId)) throw sourceInvalid("DuplicateList", source.listId);
    seen.add(source.listId);
  }
  const curators: Address[] = [];
  const writer = new Writer().u8(tag, "tag").u8(referenced.length, "sources.length");
  for (const listId of referenced) {
    const curator = shared.find((source) => source.listId === listId)?.curatorRingProgramId;
    if (curator !== undefined && !curators.includes(curator)) curators.push(curator);
    writer
      .u8(listId, "listId")
      .u8(curator === undefined ? 0 : 1 + curators.indexOf(curator), "source");
  }
  if (curators.length > 1) throw sourceInvalid("MultipleCurators");
  const { rules, inlineAssets, inlineLimits, limits } = input.table;
  writer.u8(rules.length, "rules.length");
  for (const rule of rules) writer.bytes(encodeRule(rule), 32, "rule");
  writer.u8(inlineAssets.length, "inlineAssets.length");
  for (const asset of inlineAssets) writer.bytes(asset, 32, "inlineAsset");
  writer.u8(inlineLimits.length, "inlineLimits.length");
  for (const limit of inlineLimits) writer.u64(limit, "inlineLimit");
  writer.u8(limits.length, "limits.length");
  for (const limit of limits)
    writer
      .bytes(limit.asset, 32, "limit.asset")
      .u64(limit.cap, "limit.cap")
      .u64(limit.cosignAbove, "limit.cosignAbove");
  const [accounts, curatorAccounts] = await Promise.all([
    policyWriteMetas(input.ringProgramId, input.authority),
    Promise.all(curators.map((curator) => curatorRegistry(input.ringProgramId, curator))),
  ]);
  const instruction = ringInstruction(input.ringProgramId, writer.finish(), [
    ...accounts,
    ...curatorAccounts.map((registry) => meta(registry, false, false)),
  ]);
  checkFits(input.authority, instruction, ringComputeUnitLimit(tag));
  return instruction;
}

/** A curator source names another ring's registry, the own registry keeps its hard floor. */
function curatorRegistry(ringProgramId: Address, curator: Address): Promise<Address> {
  if (curator === ringProgramId) throw sourceInvalid("OwnCurator");
  return ringMemberRegistryAddress(curator);
}

/** Rust `fit`, the signed transaction must fit v1 before the authority signs it. */
function checkFits(payer: SignerAccount, instruction: Instruction, computeUnitLimit: number): void {
  checkTransactionFits({
    feePayer: signerAddress(payer),
    instructions: [instruction],
    computeUnitLimit,
  });
}

/** Mirrors the program's `SetCoSigner` refusals before the authority signs. */
function checkCoSigner(
  signer: Address,
  scope: number,
  thresholds: readonly RingCoSignThreshold[],
): void {
  const reason = equalBytes(addressBytes(signer, "signer"), ZERO_32)
    ? "InvalidCoSigner"
    : !Number.isInteger(scope) || scope === 0 || (scope & ~RING_COSIGN_SCOPE_MASK) !== 0
      ? "InvalidCoSignerScope"
      : thresholds.length > RING_COSIGN_THRESHOLD_SLOTS ||
          new Set(thresholds.map((row) => row.mint)).size !== thresholds.length
        ? "InvalidCoSignerThresholds"
        : undefined;
  if (reason !== undefined) throw new RingError("RING_CO_SIGNER_INVALID", { details: { reason } });
}

function ringInstruction(
  ringProgramId: Address,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): Instruction {
  return { programAddress: ringProgramId, accounts, data };
}

function sourceInvalid(reason: string, listId?: ListId): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", {
    details: listId === undefined ? { reason } : { reason, listId },
  });
}
