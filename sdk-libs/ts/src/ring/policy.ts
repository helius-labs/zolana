import type { Address } from "@solana/kit";

import { ownerHash } from "../keypair/hash.js";
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
import { ZERO_NULLIFIER_PK } from "../interface/program.js";
import type { TreeId } from "../transaction/utxo.js";
import type { Bytes32 } from "../interface/types.js";
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

export type RuleSource = Readonly<{
  kind: "lists";
  present: readonly ListId[];
  absent: readonly ListId[];
}>;

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
    throw ruleTableInvalid("EmptyLists");
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
    const { present, absent } = rule.source;
    if (present.length + absent.length === 0) throw ruleTableInvalid("EmptyLists");
    if ((listBits(present) & listBits(absent)) !== 0) throw ruleTableInvalid("ListInBothSets");
  } else {
    throw ruleTableInvalid("InlineNotAsset");
  }
  if (rule.guard.kind === "aboveAmount") {
    if (rule.subject === "sender") throw ruleTableInvalid("SenderGuard");
    if (rule.guard.amount === 0n) throw ruleTableInvalid("ZeroThreshold");
  }
  if (rule.guard.kind === "aboveAmountByAsset") {
    if (rule.subject !== "outputOwner") throw ruleTableInvalid("PerAssetGuardNotOwner");
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
  let perAssetGuard = false;
  for (const rule of rules) {
    const signature = ruleSignature(rule);
    if (signatures.has(signature)) throw ruleTableInvalid("DuplicateRule");
    signatures.add(signature);
    if (rule.guard.kind === "aboveAmountByAsset") perAssetGuard = true;
  }
  const pool = inlineAssets.length;
  if (!perAssetGuard && pool > 0) throw ruleTableInvalid("PoolWithoutInlineRule");
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
export const RING_POLICY_VERSION = 10;

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

function entryInvalid(reason: string): RingError {
  return new RingError("RING_ENTRY_INVALID", { details: { reason } });
}

const POLICY_TABLE_DOMAIN = packedAscii("zolana:ring-policy:policy:v1");

/** Reserved namespace owner hash, excluded from transfers by the policy circuit. */
export function ringNamespaceOwnerHash(namespacePda: Address): Bytes32 {
  return ownerHash(
    solanaOwnerIdentity(addressBytes(namespacePda, "namespacePda")) as Bytes32,
    ZERO_NULLIFIER_PK,
  ) as Bytes32;
}

function fieldU8(value: number): Bytes32 {
  return rightAlign(Uint8Array.of(value));
}

function fieldU64(value: bigint): Bytes32 {
  return rightAlign(bigIntBytes(value, 8));
}

/** At most 31 bytes keeps the packed value below the field modulus. */
function packedAscii(text: string): Bytes32 {
  return rightAlign(new TextEncoder().encode(text));
}

/** A pool tree and its committed protocol id. */
export interface LeafTree {
  readonly tree: Address;
  readonly treeId: TreeId;
}
