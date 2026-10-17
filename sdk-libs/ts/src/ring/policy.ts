import type { Address, Signature } from "@solana/kit";

import { ClientError } from "../client/error.js";
import { ownerHash } from "../keypair/hash.js";
import type { IndexerReader } from "../client/ports.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
  RING_OUTFLOW_LIMIT_SLOTS,
  type CustomRingSourceOwner,
  type CustomRingOutflowLimit,
} from "../client/prover/types.js";
import { hashBytes, solanaOwnerIdentity } from "../hasher/index.js";
import { Reader, Writer, addressBytes } from "../interface/internal.js";
import { ADDRESS_DOMAIN, UTXO_DOMAIN } from "../interface/program.js";
import { treeIdField } from "../interface/tree-slot.js";
import type { TreeId } from "../transaction/utxo.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import { SOL_MINT } from "../transaction/asset.js";
import type {
  IndexedShieldedTransaction,
  OutputSlot,
} from "../transaction/instructions/transact.js";
import {
  ZERO_32,
  bigIntBytes,
  bytesToBigInt,
  decodeAddress,
  poseidon,
  rightAlign,
} from "../transaction/internal.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";

import type { RingPolicyConfig, RingPolicySource } from "./codecs.js";
import { RingError } from "./error.js";

/** Mirrors Rust `ListId`, the on-chain discriminant of a list, never `0`. */
export const ListId = Object.freeze({
  allow: 1,
  block: 2,
  frozen: 3,
  ringViewing: 4,
  recovery: 5,
  reader: 6,
  approval: 7,
  escrow: 8,
} as const);
export type ListId = (typeof ListId)[keyof typeof ListId];

/** Source-slot order, the id of `LIST_IDS[i]` is `i + 1`. */
export const LIST_IDS: readonly ListId[] = Object.freeze(Object.values(ListId));

export function listIdFromByte(byte: number): ListId | undefined {
  return LIST_IDS.find((id) => id === byte);
}

/** Mirrors Rust `ListSet`, bit `i` is list `i + 1`. */
export function listSet(bits: number): readonly ListId[] {
  return Object.freeze(LIST_IDS.filter((id) => (bits & listBit(id)) !== 0));
}

function listBit(id: ListId): number {
  return 1 << (checkedListId(id) - 1);
}

/** A byte outside `LIST_IDS` never reaches a mask, a seed or the wire. */
export function checkedListId(id: ListId): ListId {
  if (listIdFromByte(id) === undefined) throw ruleTableInvalid("UnknownList");
  return id;
}

function listBits(ids: readonly ListId[]): number {
  return ids.reduce((bits, id) => bits | listBit(id), 0);
}

export type RuleSubject = "outputOwner" | "sender" | "exitDestination" | "asset";

export type RuleSource =
  | Readonly<{ kind: "lists"; present: readonly ListId[]; absent: readonly ListId[] }>
  | Readonly<{ kind: "inlineAssets" }>;

export type RuleGuard =
  | Readonly<{ kind: "always" }>
  | Readonly<{ kind: "aboveAmount"; amount: bigint }>
  | Readonly<{ kind: "aboveAmountByAsset" }>;

export interface Rule {
  readonly subject: RuleSubject;
  readonly source: RuleSource;
  readonly guard: RuleGuard;
}

/** One limit per inline asset, zero outside a per-asset guard. */
export interface RuleTable {
  readonly rules: readonly Rule[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  /** At most one per mint, each bounds a transfer's outflow of it. */
  readonly limits: readonly CustomRingOutflowLimit[];
}

const U64_MAX = (1n << 64n) - 1n;

const SUBJECTS: readonly RuleSubject[] = ["outputOwner", "sender", "exitDestination", "asset"];

export type RuleMode = "present" | "absent";

export interface RuleAlternative {
  readonly listId: ListId;
  readonly mode: RuleMode;
}

/** Mirrors Rust `Rule::alternatives`, presences first, each in slot order. */
export function ruleAlternatives(rule: Rule): readonly RuleAlternative[] {
  if (rule.source.kind !== "lists") return Object.freeze([]);
  const { present, absent } = rule.source;
  return Object.freeze([
    ...listSet(listBits(present)).map((listId) => ({ listId, mode: "present" as const })),
    ...listSet(listBits(absent)).map((listId) => ({ listId, mode: "absent" as const })),
  ]);
}

/** Mirrors Rust `Rule::encoded`, an absent-only rule carries its lists in the mask. */
export function encodeRule(rule: Rule): Bytes32 {
  checkRule(rule);
  let mask = 0;
  let alternative = 0;
  let mode = 1;
  if (rule.source.kind === "lists") {
    const present = listBits(rule.source.present);
    if (present === 0) {
      mask = listBits(rule.source.absent);
      mode = 2;
    } else {
      mask = present;
      alternative = listBits(rule.source.absent);
    }
  }
  const [guardTag, threshold] =
    rule.guard.kind === "always"
      ? [0, 0n]
      : rule.guard.kind === "aboveAmount"
        ? [1, rule.guard.amount]
        : [2, 0n];
  if (threshold < 0n || threshold > U64_MAX) throw ruleTableInvalid("ThresholdRange");
  return new Writer()
    .bytes(new Uint8Array(19))
    .u8(alternative, "alternative")
    .bytes(bigIntBytes(threshold, 8))
    .u8(guardTag, "guardTag")
    .u8(mask, "mask")
    .u8(mode, "mode")
    .u8(SUBJECTS.indexOf(rule.subject) + 1, "subject")
    .finish() as Bytes32;
}

/** Mirrors Rust `Rule::decode` and `Rule::check`, `details.reason` names the Rust variant. */
export function decodeRule(row: Bytes32): Rule {
  const reader = new Reader(row);
  const reserved = reader.bytes(19, "reserved");
  const alternative = reader.u8("alternative");
  const threshold = bytesToBigInt(reader.bytes(8, "threshold"));
  const guardTag = reader.u8("guardTag");
  const mask = reader.u8("mask");
  const mode = reader.u8("mode");
  const subjectByte = reader.u8("subject");
  reader.done();
  if (reserved.some((byte) => byte !== 0)) throw ruleTableInvalid("ReservedBytes");
  const subject = SUBJECTS[subjectByte - 1];
  if (subject === undefined) throw ruleTableInvalid("UnknownSubject");
  if (mode !== 1 && mode !== 2) throw ruleTableInvalid("UnknownMode");
  let source: RuleSource;
  if (mask === 0) {
    if (alternative !== 0) throw ruleTableInvalid("InlineWithAlternative");
    if (mode === 2) throw ruleTableInvalid("InlineAbsent");
    source = { kind: "inlineAssets" };
  } else if (mode === 1) {
    source = { kind: "lists", present: listSet(mask), absent: listSet(alternative) };
  } else {
    if (alternative !== 0) throw ruleTableInvalid("NonCanonicalAlternative");
    source = { kind: "lists", present: [], absent: listSet(mask) };
  }
  let guard: RuleGuard;
  if (guardTag === 0) {
    if (threshold !== 0n) throw ruleTableInvalid("ThresholdWithoutGuard");
    guard = { kind: "always" };
  } else if (guardTag === 1) {
    guard = { kind: "aboveAmount", amount: threshold };
  } else if (guardTag === 2) {
    if (threshold !== 0n) throw ruleTableInvalid("ThresholdWithoutGuard");
    guard = { kind: "aboveAmountByAsset" };
  } else {
    throw ruleTableInvalid("UnknownGuardTag");
  }
  const rule: Rule = Object.freeze({ subject, source, guard });
  checkRule(rule);
  return rule;
}

function checkRule(rule: Rule): void {
  if (rule.subject === "exitDestination") throw ruleTableInvalid("ExitDestination");
  if (rule.source.kind === "lists") {
    if (rule.subject === "asset") throw ruleTableInvalid("AssetListRule");
    const { present, absent } = rule.source;
    if (present.length + absent.length === 0) throw ruleTableInvalid("EmptyLists");
    if ((listBits(present) & listBits(absent)) !== 0) throw ruleTableInvalid("ListInBothSets");
  } else if (rule.subject !== "asset") {
    throw ruleTableInvalid("InlineNotAsset");
  }
  if (rule.guard.kind === "aboveAmount") {
    if (rule.subject === "sender") throw ruleTableInvalid("SenderGuard");
    if (rule.guard.amount === 0n) throw ruleTableInvalid("ZeroThreshold");
  }
  if (rule.guard.kind === "aboveAmountByAsset") {
    if (rule.subject !== "outputOwner") throw ruleTableInvalid("PerAssetGuardNotOwner");
    if (rule.source.kind === "inlineAssets") throw ruleTableInvalid("PerAssetGuardInline");
  }
}

/** Mirrors Rust `EncodedRuleTable::decode`, the padding is checked by `decodeRingPolicyConfig`. */
export function decodeRuleTable(
  config: Pick<RingPolicyConfig, "rules" | "inlineAssets" | "inlineLimits" | "limits">,
): RuleTable {
  if (config.rules.length > RING_RULE_SLOTS) throw ruleTableInvalid("TooManyRules");
  if (config.inlineLimits.length !== config.inlineAssets.length) {
    throw ruleTableInvalid("MissingAssetLimit");
  }
  return checkedRuleTable({
    rules: config.rules.map(decodeRule),
    inlineAssets: config.inlineAssets,
    inlineLimits: config.inlineLimits,
    limits: config.limits,
  });
}

export interface RuleTableInput {
  readonly rules: readonly Rule[];
  readonly inlineAssets?: readonly Bytes32[];
  readonly inlineLimits?: readonly bigint[];
  readonly limits?: readonly CustomRingOutflowLimit[];
}

/** Mirrors Rust `RuleTableBuilder::try_build`. */
export function buildRuleTable(input: RuleTableInput): RuleTable {
  const inlineAssets = input.inlineAssets ?? [];
  const inlineLimits = input.inlineLimits ?? [];
  if (input.rules.length > RING_RULE_SLOTS) throw ruleTableInvalid("TooManyRules");
  if (inlineLimits.length > RING_INLINE_ASSET_SLOTS) throw ruleTableInvalid("TooManyInlineAssets");
  if (inlineAssets.some((asset) => asset.length !== 32)) {
    throw ruleTableInvalid("InlineAssetLength");
  }
  if (inlineLimits.some((limit) => limit < 0n || limit > U64_MAX)) {
    throw ruleTableInvalid("LimitRange");
  }
  const table = checkedRuleTable({
    rules: input.rules,
    inlineAssets,
    inlineLimits: inlineAssets.map((_, index) => inlineLimits[index] ?? 0n),
    limits: input.limits ?? [],
  });
  const perAssetGuard = table.rules.some((rule) => rule.guard.kind === "aboveAmountByAsset");
  if (perAssetGuard ? inlineLimits.length !== inlineAssets.length : inlineLimits.length !== 0) {
    throw ruleTableInvalid(perAssetGuard ? "MissingAssetLimit" : "AssetLimitWithoutGuard");
  }
  return table;
}

/** Mirrors Rust `RuleTable::encode`, counted rows without the zero padding. */
export function encodeRuleTable(table: RuleTable): EncodedRuleTable {
  const rules = table.rules.map(encodeRule);
  return Object.freeze({
    ruleCount: rules.length,
    rules: Object.freeze(rules),
    inlineCount: table.inlineAssets.length,
    inlineAssets: table.inlineAssets,
    inlineLimits: table.inlineLimits,
    limitCount: table.limits.length,
    limits: table.limits,
  });
}

export type EncodedRuleTable = Pick<
  RingPolicyConfig,
  "ruleCount" | "rules" | "inlineCount" | "inlineAssets" | "inlineLimits" | "limitCount" | "limits"
>;

/** The invariants both `decode` and `try_build` enforce. */
function checkedRuleTable(table: RuleTable): RuleTable {
  const { rules, inlineAssets, inlineLimits, limits } = table;
  checkLimits(limits);
  if (inlineAssets.length > RING_INLINE_ASSET_SLOTS) throw ruleTableInvalid("TooManyInlineAssets");
  if (inlineAssets.some((asset) => equalBytes(asset, ZERO_32))) {
    throw ruleTableInvalid("ZeroInlineAsset");
  }
  for (const rule of rules) checkRule(rule);
  const signatures = new Set<string>();
  let ownerGuard = false;
  let inlineRule = false;
  let unguardedInline = false;
  let perAssetGuard = false;
  for (const rule of rules) {
    const signature = ruleSignature(rule);
    if (signatures.has(signature)) throw ruleTableInvalid("DuplicateRule");
    signatures.add(signature);
    if (rule.source.kind === "inlineAssets") {
      inlineRule = true;
      unguardedInline = rule.guard.kind === "always";
    }
    if (rule.subject === "outputOwner" && rule.guard.kind === "aboveAmount") ownerGuard = true;
    if (rule.guard.kind === "aboveAmountByAsset") perAssetGuard = true;
  }
  const pool = inlineAssets.length;
  if (inlineRule && pool === 0) throw ruleTableInvalid("InlineWithoutPool");
  if (!inlineRule && !perAssetGuard && pool > 0) throw ruleTableInvalid("PoolWithoutInlineRule");
  if (ownerGuard && !(unguardedInline && pool === 1)) {
    throw ruleTableInvalid("OwnerGuardWithoutInlineAsset");
  }
  if (perAssetGuard) {
    if (pool === 0 || inlineLimits.some((limit) => limit === 0n)) {
      throw ruleTableInvalid("MissingAssetLimit");
    }
    const assets = new Set(inlineAssets.map((asset) => bytesKey(asset)));
    if (assets.size !== pool) throw ruleTableInvalid("DuplicateInlineAsset");
  } else if (inlineLimits.some((limit) => limit !== 0n)) {
    throw ruleTableInvalid("AssetLimitWithoutGuard");
  }
  return Object.freeze({
    rules: Object.freeze([...rules]),
    inlineAssets: Object.freeze([...inlineAssets]),
    inlineLimits: Object.freeze([...inlineLimits]),
    limits: Object.freeze(limits.map((limit) => Object.freeze({ ...limit }))),
  });
}

/** Mirrors the limit checks of Rust `RuleTableBuilder::try_build`. */
function checkLimits(limits: readonly CustomRingOutflowLimit[]): void {
  if (limits.length > RING_OUTFLOW_LIMIT_SLOTS) throw ruleTableInvalid("TooManyOutflowLimits");
  const assets = new Set<string>();
  for (const limit of limits) {
    if (limit.asset.length !== 32 || equalBytes(limit.asset, ZERO_32)) {
      throw ruleTableInvalid("ZeroLimitAsset");
    }
    for (const bound of [limit.cap, limit.cosignAbove]) {
      if (bound < 0n || bound > U64_MAX) throw ruleTableInvalid("LimitRange");
    }
    if (limit.cap === 0n && limit.cosignAbove === 0n) throw ruleTableInvalid("LimitWithoutBound");
    const key = bytesKey(limit.asset);
    if (assets.has(key)) throw ruleTableInvalid("DuplicateLimitAsset");
    assets.add(key);
  }
}

function ruleSignature(rule: Rule): string {
  const [present, absent] =
    rule.source.kind === "lists"
      ? [listBits(rule.source.present), listBits(rule.source.absent)]
      : [0, 0];
  return `${rule.subject}:${present}:${absent}`;
}

/** In slot order. */
export function referencedLists(rules: readonly Rule[]): readonly ListId[] {
  const bits = rules.reduce(
    (set, rule) =>
      rule.source.kind === "lists"
        ? set | listBits(rule.source.present) | listBits(rule.source.absent)
        : set,
    0,
  );
  return listSet(bits);
}

function ruleTableInvalid(reason: string): RingError {
  return new RingError("RING_RULE_TABLE_INVALID", { details: { reason } });
}

/** Mirrors Rust `SourceMap::from_namespaces`. */
export function policySourceOwners(
  sources: readonly RingPolicySource[],
): readonly CustomRingSourceOwner[] {
  return checkedSourceOwners(
    sources.map((slot) =>
      Object.freeze(
        slot.listId === 0
          ? { listId: 0, registry: new Uint8Array(32) as Bytes32 }
          : {
              listId: slot.listId,
              registry: equalBytes(addressBytes(slot.registry), ZERO_32)
                ? ZERO_32
                : (hashBytes(addressBytes(slot.registry)) as Bytes32),
            },
      ),
    ),
  );
}

function checkedSourceOwners(
  owners: readonly CustomRingSourceOwner[],
): readonly CustomRingSourceOwner[] {
  if (owners.length !== RING_SOURCE_SLOTS) {
    throw sourceInvalid("SlotCount", { slots: owners.length });
  }
  owners.forEach((slot, index) => {
    const empty = slot.listId === 0 && equalBytes(slot.registry, ZERO_32);
    const positional = slot.listId === index + 1;
    if (!empty && !positional) throw sourceInvalid("NotPositional", { index });
  });
  const foreign = new Set(
    owners
      .filter((slot) => !equalBytes(slot.registry, ZERO_32))
      .map((slot) => Array.from(slot.registry).join(",")),
  );
  if (foreign.size > 1) throw sourceInvalid("MultipleCurators", {});
  return Object.freeze([...owners]);
}

function sourceInvalid(reason: string, details: Readonly<Record<string, unknown>>): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason, ...details } });
}

/** Rust `POLICY_VERSION`, enters the policy hash. */
export const RING_POLICY_VERSION = 9;

/** Mirrors Rust `EncodedRuleTable::hash`, a referenced list without a source fails closed. */
export function ringPolicyHash(
  table: RuleTable,
  sources: readonly CustomRingSourceOwner[],
): Bytes32 {
  const owners = checkedSourceOwners(sources);
  for (const listId of referencedLists(table.rules)) {
    if (owners[listId - 1]?.listId !== listId) throw sourceInvalid("MissingSource", { listId });
  }
  const encoded = encodeRuleTable(table);
  const elements: Bytes32[] = [POLICY_TABLE_DOMAIN, fieldU8(RING_POLICY_VERSION)];
  for (const slot of owners) elements.push(fieldU8(slot.listId), slot.registry);
  elements.push(
    fieldU8(encoded.ruleCount),
    fieldU8(encoded.inlineAssets.length),
    fieldU8(encoded.limits.length),
    ...encoded.rules,
  );
  encoded.inlineAssets.forEach((asset, index) => {
    elements.push(asset, fieldU64(encoded.inlineLimits[index] ?? 0n));
  });
  for (const limit of encoded.limits) {
    elements.push(limit.asset, fieldU64(limit.cap), fieldU64(limit.cosignAbove));
  }
  return elements.reduce((chain, element) => poseidon([chain, element]));
}

/** Mirrors Rust `policy_config_table`, the rows are trusted once they reproduce the pinned hash. */
export function verifiedRuleTable(
  config: RingPolicyConfig,
  sources: readonly CustomRingSourceOwner[] = policySourceOwners(config.sources),
): RuleTable {
  const table = decodeRuleTable(config);
  const hash = ringPolicyHash(table, sources);
  if (!equalBytes(hash, config.policyHash)) {
    throw new RingError("RING_POLICY_HASH_MISMATCH", {
      details: { addressTree: config.addressTree, generation: config.generation },
    });
  }
  return table;
}

declare const memberBrand: unique symbol;
/** Mirrors Rust `Member`, never zero. */
export type Member = Bytes32 & { readonly [memberBrand]: true };

/** Mirrors Rust `Member::owner_tag`, the derivation `zolana-ring list add` applies to `--owner`. */
export function memberOfTag(tag: Uint8Array): Member {
  if (tag.length !== 32) throw entryInvalid("tagLength");
  return checkedMember(solanaOwnerIdentity(tag) as Bytes32);
}

/** Mirrors Rust `Member::owner_identity`, an owner of any curve by `ownerProofInputHash`. */
export function memberOfIdentity(identity: Bytes32): Member {
  return checkedMember(identity);
}

/** Mirrors Rust `Member::asset`, the mint as the UTXO asset field. */
export function memberOfAsset(mint: Address): Member {
  return checkedMember(hashBytes(decodeAddress(mint)) as Bytes32);
}

function checkedMember(bytes: Bytes32): Member {
  if (equalBytes(bytes, ZERO_32)) throw entryInvalid("zeroMember");
  return bytes as Member;
}

export type EntryState = "active" | "cleared";

const ENTRY_STATES: readonly EntryState[] = ["active", "cleared"];

/** Mirrors Rust `ListEntry`, the published SPP output blinding rebuilds the leaf. */
export interface ListEntry {
  readonly listId: ListId;
  readonly member: Member;
  readonly state: EntryState;
  readonly version: bigint;
  readonly contentHash: Bytes32;
  readonly blinding: Bytes32;
}

const LIST_ENTRY_LEN = 106;

export type ListWriter = "authority" | "member";

/** Mirrors Rust `ListId::writer`. */
export function listWriter(listId: ListId): ListWriter {
  switch (checkedListId(listId)) {
    case ListId.ringViewing:
    case ListId.recovery:
    case ListId.escrow:
      return "member";
    case ListId.allow:
    case ListId.block:
    case ListId.frozen:
    case ListId.reader:
    case ListId.approval:
      return "authority";
  }
}

/** Mirrors Rust `ListEntry::to_output_data`. */
export function encodeListEntry(entry: ListEntry): Uint8Array {
  return new Writer()
    .u8(0, "tag")
    .u32(LIST_ENTRY_LEN, "length")
    .u8(entry.listId, "listId")
    .bytes(entry.member, 32, "member")
    .u8(ENTRY_STATES.indexOf(entry.state) + 1, "state")
    .u64(entry.version, "version")
    .bytes(entry.contentHash, 32, "contentHash")
    .bytes(entry.blinding, 32, "blinding")
    .finish();
}

/** Mirrors Rust `ListEntry::from_entry_bytes` over the plaintext output-data envelope. */
export function decodeListEntry(outputData: Uint8Array): ListEntry {
  const reader = new Reader(outputData);
  if (reader.u8("tag") !== 0) throw entryInvalid("encoding");
  if (reader.u32("length") !== LIST_ENTRY_LEN) throw entryInvalid("length");
  const listId = listIdFromByte(reader.u8("listId"));
  if (listId === undefined) throw entryInvalid("listId");
  const member = checkedMember(reader.bytes(32, "member") as Bytes32);
  const state = ENTRY_STATES[reader.u8("state") - 1];
  if (state === undefined) throw entryInvalid("state");
  const version = reader.u64("version");
  const contentHash = reader.bytes(32, "contentHash") as Bytes32;
  const blinding = reader.bytes(32, "blinding") as Bytes32;
  reader.done();
  return Object.freeze({ listId, member, state, version, contentHash, blinding });
}

function entryInvalid(reason: string): RingError {
  return new RingError("RING_ENTRY_INVALID", { details: { reason } });
}

export interface EntryHashes {
  readonly address: Bytes32;
  readonly dataHash: Bytes32;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
}

const POLICY_ADDRESS_DOMAIN = packedAscii("zolana:ring-policy:address:v1");
const POLICY_RECORD_DOMAIN = packedAscii("zolana:ring-policy:record:v1");
const POLICY_TABLE_DOMAIN = packedAscii("zolana:ring-policy:policy:v1");
/** @internal Mirrors Rust `ZERO_NULLIFIER_PK`, `Poseidon(0)`, the nullifier public key of the zero secret. */
export const ZERO_NULLIFIER_PK = Uint8Array.from([
  0x2a, 0x09, 0xa9, 0xfd, 0x93, 0xc5, 0x90, 0xc2, 0x6b, 0x91, 0xef, 0xfb, 0xb2, 0x49, 0x9f, 0x07,
  0xe8, 0xf7, 0xaa, 0x12, 0xe2, 0xb4, 0x94, 0x0a, 0x3a, 0xed, 0x24, 0x11, 0xcb, 0x65, 0xe1, 0x1c,
]) as Bytes32;

/** Mirrors Rust `ListNamespace::new`, the shielded owner hash of the ring's entry notes. */
export function ringNamespaceOwnerHash(namespacePda: Address): Bytes32 {
  return ownerHash(
    solanaOwnerIdentity(addressBytes(namespacePda, "namespacePda")) as Bytes32,
    ZERO_NULLIFIER_PK,
  ) as Bytes32;
}

/** Mirrors Rust `ListNamespace`, addresses hash under the address tree, leaves under the tree holding them. */
export class RingListNamespace {
  readonly address: Address;
  readonly ownerHash: Bytes32;
  readonly addressTreeId: TreeId;

  private constructor(address: Address, ownerHash: Bytes32, addressTreeId: TreeId) {
    this.address = address;
    this.ownerHash = ownerHash;
    this.addressTreeId = addressTreeId;
  }

  static of(namespace: Address, addressTreeId: TreeId): RingListNamespace {
    return new RingListNamespace(namespace, ringNamespaceOwnerHash(namespace), addressTreeId);
  }

  /** One address lineage per `(listId, member)` pair under one namespace. */
  entryAddress(input: Readonly<{ listId: ListId; member: Member }>): Bytes32 {
    const seed = entrySeed(input);
    return entryNullifier(this.addressSlotHash(seed), seed);
  }

  entryHashes(entry: ListEntry, treeId: TreeId): EntryHashes {
    const address = this.entryAddress(entry);
    const dataHash = poseidon([
      POLICY_RECORD_DOMAIN,
      address,
      fieldU8(entry.listId),
      entry.member,
      fieldU8(ENTRY_STATES.indexOf(entry.state) + 1),
      fieldU64(entry.version),
      entry.contentHash,
    ]);
    const utxoHash = this.leafHash(dataHash, entry.blinding, treeId);
    return Object.freeze({
      address,
      dataHash,
      utxoHash,
      nullifier: entryNullifier(utxoHash, entry.blinding),
    });
  }

  /** Mirrors Rust `ListNamespace::leaf_hash`, a zero-amount SOL data leaf in the default ring. */
  leafHash(dataHash: Bytes32, blinding: Bytes32, treeId: TreeId): Bytes32 {
    return poseidon([
      fieldU16(UTXO_DOMAIN),
      treeIdField(treeId),
      solAssetField(),
      ZERO_32,
      dataHash,
      ringHash(),
      poseidon([this.ownerHash, blinding]),
    ]);
  }

  /** The address slot commitment, its blinding is the entry seed. */
  addressSlotHash(seed: Bytes32): Bytes32 {
    return poseidon([
      fieldU16(ADDRESS_DOMAIN),
      treeIdField(this.addressTreeId),
      ZERO_32,
      ZERO_32,
      ZERO_32,
      ringHash(),
      poseidon([this.ownerHash, seed]),
    ]);
  }
}

/** Rust `SOL_ASSET_FIELD`, the asset every entry note carries. */
export function solAssetField(): Bytes32 {
  return hashBytes(decodeAddress(SOL_MINT)) as Bytes32;
}

/** Mirrors Rust `entry_seed`. */
export function entrySeed(input: Readonly<{ listId: ListId; member: Member }>): Bytes32 {
  return poseidon([POLICY_ADDRESS_DOMAIN, fieldU8(checkedListId(input.listId)), input.member]);
}

/** The nullifier secret is zero for every entry. */
function entryNullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
  return poseidon([utxoHash, blinding, ZERO_32]);
}

function ringHash(): Bytes32 {
  return poseidon([ZERO_32, ZERO_32]);
}

function fieldU8(value: number): Bytes32 {
  return rightAlign(Uint8Array.of(value));
}

function fieldU16(value: number): Bytes32 {
  return rightAlign(Uint8Array.of(value >> 8, value & 0xff));
}

function fieldU64(value: bigint): Bytes32 {
  return rightAlign(bigIntBytes(value, 8));
}

/** At most 31 bytes keeps the packed value below the field modulus. */
function packedAscii(text: string): Bytes32 {
  return rightAlign(new TextEncoder().encode(text));
}

/** The leaf's tree, a lineage moves between trees while its address stays in the address tree. */
export interface LeafTree {
  readonly tree: Address;
  readonly treeId: TreeId;
}

/** The unspent version of a lineage. */
export interface LiveEntry extends LeafTree {
  readonly entry: ListEntry;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
  readonly txSignature: Signature;
  readonly slot: bigint;
}

export type EntryIndexer = Pick<
  IndexerReader,
  "getEncryptedUtxosByTags" | "getShieldedTransactionsByNullifiers"
>;

/** Where namespace records hash, a successor leaf is trusted only under its own tree id. */
export interface RingRecordTrees {
  readonly addressTreeId: TreeId;
  readonly resolveTreeId: (tree: Address) => TreeId | Promise<TreeId>;
}

export interface ReadRingEntryInput extends RingRecordTrees {
  readonly indexer: EntryIndexer;
  readonly namespace: Address;
  readonly listId: ListId;
  readonly member: Member;
}

/** Mirrors Rust `ReadEntry::read`, undefined when never claimed, a cleared entry still reads back. */
export async function readRingEntry(
  input: ReadRingEntryInput,
  context?: RequestContext,
): Promise<LiveEntry | undefined> {
  const [live] = await readRingEntryLineages(
    {
      indexer: input.indexer,
      addressTreeId: input.addressTreeId,
      resolveTreeId: input.resolveTreeId,
      lookups: [{ namespace: input.namespace, listId: input.listId, member: input.member }],
    },
    context,
  );
  return live;
}

export interface ReadRingEntriesInput extends RingRecordTrees {
  readonly indexer: EntryIndexer;
  readonly namespace: Address;
  readonly pageLimit?: number;
}

/** The owner tag of an output is unauthenticated, the tag scan only names candidate pairs. */
export async function readRingEntries(
  input: ReadRingEntriesInput,
  context?: RequestContext,
): Promise<readonly LiveEntry[]> {
  const tag = decodeAddress(input.namespace);
  const pairs = new Map<string, EntryPair>();
  await collectPages(
    "getEncryptedUtxosByTags",
    (cursor) =>
      input.indexer.getEncryptedUtxosByTags(
        {
          tags: [tag],
          ...(cursor === undefined ? {} : { cursor }),
          ...(input.pageLimit === undefined ? {} : { limit: input.pageLimit }),
        },
        undefined,
        context,
      ),
    (page) => {
      for (const match of page.matches) {
        const entry = tryDecodeListEntry(match.outputSlot.payload);
        if (entry === undefined) continue;
        pairs.set(pairKey(entry), { listId: entry.listId, member: entry.member });
      }
    },
  );
  const lineages = await readRingEntryLineages(
    {
      indexer: input.indexer,
      addressTreeId: input.addressTreeId,
      resolveTreeId: input.resolveTreeId,
      lookups: [...pairs.values()].map((pair) => ({ ...pair, namespace: input.namespace })),
    },
    context,
  );
  return Object.freeze(lineages.filter((live) => live !== undefined));
}

type EntryPair = Readonly<{ listId: ListId; member: Member }>;

function pairKey(pair: EntryPair): string {
  return `${pair.listId}:${bytesKey(pair.member)}`;
}

function tryDecodeListEntry(outputData: Uint8Array): ListEntry | undefined {
  try {
    return decodeListEntry(outputData);
  } catch {
    return undefined;
  }
}

interface Head {
  readonly namespace: RingListNamespace;
  readonly pair: EntryPair;
  readonly address: Bytes32;
  live: LiveEntry | undefined;
  nullifier: Bytes32;
  ended: boolean;
}

export interface RingEntryLookup extends EntryPair {
  readonly namespace: Address;
}

export interface ReadRingEntryLineagesInput extends RingRecordTrees {
  readonly indexer: EntryIndexer;
  readonly lookups: readonly RingEntryLookup[];
}

/** Mirrors Rust `Lineages::fetch`, one walk for every lookup, a head nobody spent is live. */
export async function readRingEntryLineages(
  input: ReadRingEntryLineagesInput,
  context?: RequestContext,
): Promise<readonly (LiveEntry | undefined)[]> {
  const namespaces = new Map<Address, RingListNamespace>();
  const heads: Head[] = input.lookups.map((lookup) => {
    const namespace =
      namespaces.get(lookup.namespace) ??
      RingListNamespace.of(lookup.namespace, input.addressTreeId);
    namespaces.set(lookup.namespace, namespace);
    const address = namespace.entryAddress(lookup);
    return { namespace, pair: lookup, address, live: undefined, nullifier: address, ended: false };
  });
  for (;;) {
    const open = heads.filter((head) => !head.ended);
    if (open.length === 0) break;
    const spenders = await fetchSpenders(
      input.indexer,
      open.map((head) => head.nullifier),
      context,
    );
    for (const head of open) {
      const spender = spenderOf(spenders, head.nullifier);
      if (spender === undefined) {
        head.ended = true;
        continue;
      }
      const successor = await successorIn(spender, (slot) =>
        decodeSuccessor({ head, slot, resolveTreeId: input.resolveTreeId }),
      );
      if (successor === undefined) {
        throw new RingError("RING_ENTRY_LINEAGE_BROKEN", {
          details: {
            listId: head.pair.listId,
            member: bytesKey(head.pair.member),
            version: head.live === undefined ? 0n : head.live.entry.version + 1n,
          },
        });
      }
      head.nullifier = successor.nullifier;
      head.live = { ...successor, txSignature: spender.txSignature, slot: spender.slot };
    }
  }
  return heads.map((head) => head.live);
}

async function fetchSpenders(
  indexer: EntryIndexer,
  nullifiers: readonly Bytes32[],
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const spenders: IndexedShieldedTransaction[] = [];
  await collectPages(
    "getShieldedTransactionsByNullifiers",
    (cursor) =>
      indexer.getShieldedTransactionsByNullifiers(
        { nullifiers, ...(cursor === undefined ? {} : { cursor }) },
        undefined,
        context,
      ),
    (page) => spenders.push(...page.transactions),
  );
  return spenders;
}

function spenderOf(
  spenders: readonly IndexedShieldedTransaction[],
  nullifier: Bytes32,
): IndexedShieldedTransaction | undefined {
  return spenders.find((transaction) =>
    transaction.nullifiers.some((candidate) => equalBytes(candidate, nullifier)),
  );
}

/** The first output in any tree `decode` accepts. */
async function successorIn<T>(
  spender: IndexedShieldedTransaction,
  decode: (slot: OutputSlot) => Promise<T | undefined>,
): Promise<T | undefined> {
  for (const slot of spender.outputSlots) {
    const candidate = await decode(slot);
    if (candidate !== undefined) return candidate;
  }
  return undefined;
}

/** Content is trusted only after it reproduces the on-chain commitment. */
async function decodeSuccessor(
  input: Readonly<{
    head: Head;
    slot: OutputSlot;
    resolveTreeId: RingRecordTrees["resolveTreeId"];
  }>,
): Promise<Omit<LiveEntry, "txSignature" | "slot"> | undefined> {
  const { head, slot } = input;
  const entry = tryDecodeListEntry(slot.payload);
  if (entry === undefined) return undefined;
  if (entry.listId !== head.pair.listId || !equalBytes(entry.member, head.pair.member)) {
    return undefined;
  }
  const tree = slot.outputContext.tree;
  const treeId = await input.resolveTreeId(tree);
  const hashes = head.namespace.entryHashes(entry, treeId);
  if (!equalBytes(hashes.utxoHash, slot.outputContext.hash)) return undefined;
  return { entry, utxoHash: hashes.utxoHash, nullifier: hashes.nullifier, tree, treeId };
}

interface CursorPage {
  readonly nextCursor?: Uint8Array | undefined;
  readonly scannedThrough?: Uint8Array | undefined;
}

/** A terminal page still names a cursor, only `scannedThrough` ends the round. */
async function collectPages<P extends CursorPage>(
  method: string,
  request: (cursor: Uint8Array | undefined) => Promise<P>,
  absorb: (page: P) => void,
): Promise<void> {
  const seen = new Set<string>();
  let cursor: Uint8Array | undefined;
  for (;;) {
    const page = await request(cursor);
    absorb(page);
    const next = page.scannedThrough === undefined ? page.nextCursor : undefined;
    if (next === undefined) return;
    const key = bytesKey(next);
    if (seen.has(key)) {
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: { method, path: "$.nextCursor" },
      });
    }
    seen.add(key);
    cursor = next;
  }
}
