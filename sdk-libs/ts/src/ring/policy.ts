import type { Address, Signature } from "@solana/kit";

import { ClientError } from "../client/error.js";
import type { IndexerReader } from "../client/ports.js";
import { hashBytes } from "../hasher/index.js";
import { Reader } from "../interface/internal.js";
import { ADDRESS_DOMAIN, UTXO_DOMAIN } from "../interface/program.js";
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

import type { RingPolicyConfig } from "./codecs.js";
import { RingError } from "./error.js";
import { ringNamespaceOwnerHash } from "./transfer.js";

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
  return 1 << (id - 1);
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

export interface RuleTable {
  readonly rules: readonly Rule[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
}

const RULE_SLOTS = 16;
const INLINE_ASSET_SLOTS = 8;
/** A circuit width. */
const ANSWER_SLOTS = 10;
/** Rust `GUARANTEED_LOAD`. */
const GUARANTEED_SENDERS = 1;
const GUARANTEED_OUTPUTS = 4;

const SUBJECTS: readonly RuleSubject[] = ["outputOwner", "sender", "exitDestination", "asset"];

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
  config: Pick<RingPolicyConfig, "rules" | "inlineAssets" | "inlineLimits">,
): RuleTable {
  if (config.rules.length > RULE_SLOTS) throw ruleTableInvalid("TooManyRules");
  if (config.inlineAssets.length > INLINE_ASSET_SLOTS) {
    throw ruleTableInvalid("TooManyInlineAssets");
  }
  if (config.inlineAssets.some((asset) => equalBytes(asset, ZERO_32))) {
    throw ruleTableInvalid("ZeroInlineAsset");
  }
  const rules = config.rules.map(decodeRule);
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
  const pool = config.inlineAssets.length;
  if (inlineRule && pool === 0) throw ruleTableInvalid("InlineWithoutPool");
  if (!inlineRule && !perAssetGuard && pool > 0) throw ruleTableInvalid("PoolWithoutInlineRule");
  if (ownerGuard && !(unguardedInline && pool === 1)) {
    throw ruleTableInvalid("OwnerGuardWithoutInlineAsset");
  }
  if (config.inlineLimits.length !== pool) throw ruleTableInvalid("MissingAssetLimit");
  if (perAssetGuard) {
    if (pool === 0 || config.inlineLimits.some((limit) => limit === 0n)) {
      throw ruleTableInvalid("MissingAssetLimit");
    }
    const assets = new Set(config.inlineAssets.map((asset) => bytesKey(asset)));
    if (assets.size !== pool) throw ruleTableInvalid("DuplicateInlineAsset");
  } else if (config.inlineLimits.some((limit) => limit !== 0n)) {
    throw ruleTableInvalid("AssetLimitWithoutGuard");
  }
  const answers = rules.reduce((total, rule) => total + maxAnswers(rule), 0);
  if (answers > ANSWER_SLOTS) throw ruleTableInvalid("TooManyAnswers");
  return Object.freeze({
    rules: Object.freeze(rules),
    inlineAssets: config.inlineAssets,
    inlineLimits: config.inlineLimits,
  });
}

function ruleSignature(rule: Rule): string {
  const [present, absent] =
    rule.source.kind === "lists"
      ? [listBits(rule.source.present), listBits(rule.source.absent)]
      : [0, 0];
  return `${rule.subject}:${present}:${absent}`;
}

function maxAnswers(rule: Rule): number {
  if (rule.source.kind === "inlineAssets") return 0;
  switch (rule.subject) {
    case "sender":
      return GUARANTEED_SENDERS;
    case "outputOwner":
    case "asset":
      return GUARANTEED_OUTPUTS;
    case "exitDestination":
      return 0;
  }
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

declare const memberBrand: unique symbol;
/** Mirrors Rust `Member`, never zero. */
export type Member = Bytes32 & { readonly [memberBrand]: true };

/** Mirrors Rust `Member::owner_tag`, the derivation `zolana-ring list add` applies to `--owner`. */
export function memberOfTag(tag: Uint8Array): Member {
  if (tag.length !== 32) throw entryInvalid("tagLength");
  return checkedMember(hashBytes(tag) as Bytes32);
}

/** Mirrors Rust `Member::asset`, the mint as the UTXO asset field. */
export function memberOfAsset(mint: Address): Member {
  return memberOfTag(decodeAddress(mint));
}

function checkedMember(bytes: Bytes32): Member {
  if (equalBytes(bytes, ZERO_32)) throw entryInvalid("zeroMember");
  return bytes as Member;
}

export type EntryState = "active" | "cleared";

const ENTRY_STATES: readonly EntryState[] = ["active", "cleared"];

/** Mirrors Rust `ListEntry`, the version doubles as the UTXO blinding. */
export interface ListEntry {
  readonly listId: ListId;
  readonly member: Member;
  readonly state: EntryState;
  readonly version: bigint;
  readonly contentHash: Bytes32;
}

const LIST_ENTRY_LEN = 74;

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
  reader.done();
  return Object.freeze({ listId, member, state, version, contentHash });
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

/** Mirrors Rust `ListNamespace`. */
export class RingListNamespace {
  readonly address: Address;
  readonly ownerHash: Bytes32;

  private constructor(address: Address, ownerHash: Bytes32) {
    this.address = address;
    this.ownerHash = ownerHash;
  }

  static of(namespace: Address): RingListNamespace {
    return new RingListNamespace(namespace, ringNamespaceOwnerHash(namespace));
  }

  /** One address lineage per `(listId, member)` pair under one namespace. */
  entryAddress(input: Readonly<{ listId: ListId; member: Member }>): Bytes32 {
    const seed = entrySeed(input);
    return entryNullifier(this.addressUtxoHash(seed), seed);
  }

  entryHashes(entry: ListEntry): EntryHashes {
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
    const blinding = fieldU64(entry.version);
    const utxoHash = poseidon([
      fieldU16(UTXO_DOMAIN),
      hashBytes(decodeAddress(SOL_MINT)),
      ZERO_32,
      dataHash,
      ringHash(),
      poseidon([this.ownerHash, blinding]),
    ]);
    return Object.freeze({
      address,
      dataHash,
      utxoHash,
      nullifier: entryNullifier(utxoHash, blinding),
    });
  }

  /** The address slot commitment, its blinding is the entry seed. */
  private addressUtxoHash(seed: Bytes32): Bytes32 {
    return poseidon([
      fieldU16(ADDRESS_DOMAIN),
      ZERO_32,
      ZERO_32,
      ZERO_32,
      ringHash(),
      poseidon([this.ownerHash, seed]),
    ]);
  }
}

function entrySeed(input: Readonly<{ listId: ListId; member: Member }>): Bytes32 {
  return poseidon([POLICY_ADDRESS_DOMAIN, fieldU8(input.listId), input.member]);
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

/** The unspent version of a lineage. */
export interface LiveEntry {
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

export interface ReadRingEntryInput {
  readonly indexer: EntryIndexer;
  /** Only outputs in this tree continue a lineage. */
  readonly entriesTree: Address;
  readonly namespace: Address;
  readonly listId: ListId;
  readonly member: Member;
}

/** Mirrors Rust `ReadEntry::read`, undefined when never claimed, a cleared entry still reads back. */
export async function readRingEntry(
  input: ReadRingEntryInput,
  context?: RequestContext,
): Promise<LiveEntry | undefined> {
  const [live] = await walkLineages(
    {
      indexer: input.indexer,
      entriesTree: input.entriesTree,
      namespace: RingListNamespace.of(input.namespace),
      pairs: [{ listId: input.listId, member: input.member }],
    },
    context,
  );
  return live;
}

export interface ReadRingEntriesInput {
  readonly indexer: EntryIndexer;
  readonly entriesTree: Address;
  readonly namespace: Address;
  readonly pageLimit?: number;
}

/** The owner tag of an output is unauthenticated, the tag scan only names candidate pairs. */
export async function readRingEntries(
  input: ReadRingEntriesInput,
  context?: RequestContext,
): Promise<readonly LiveEntry[]> {
  const namespace = RingListNamespace.of(input.namespace);
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
        if (match.outputSlot.outputContext.tree !== input.entriesTree) continue;
        const entry = tryDecodeListEntry(match.outputSlot.payload);
        if (entry === undefined) continue;
        pairs.set(pairKey(entry), { listId: entry.listId, member: entry.member });
      }
    },
  );
  const lineages = await walkLineages(
    {
      indexer: input.indexer,
      entriesTree: input.entriesTree,
      namespace,
      pairs: [...pairs.values()],
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
  readonly pair: EntryPair;
  readonly address: Bytes32;
  live: LiveEntry | undefined;
  nullifier: Bytes32;
  ended: boolean;
}

/** Mirrors Rust `LineageWalk`, a head nobody spent is live. */
async function walkLineages(
  input: Readonly<{
    indexer: EntryIndexer;
    entriesTree: Address;
    namespace: RingListNamespace;
    pairs: readonly EntryPair[];
  }>,
  context: RequestContext | undefined,
): Promise<readonly (LiveEntry | undefined)[]> {
  const heads: Head[] = input.pairs.map((pair) => {
    const address = input.namespace.entryAddress(pair);
    return { pair, address, live: undefined, nullifier: address, ended: false };
  });
  for (;;) {
    const open = heads.filter((head) => !head.ended);
    if (open.length === 0) break;
    const spenders: IndexedShieldedTransaction[] = [];
    await collectPages(
      "getShieldedTransactionsByNullifiers",
      (cursor) =>
        input.indexer.getShieldedTransactionsByNullifiers(
          {
            nullifiers: open.map((head) => head.nullifier),
            ...(cursor === undefined ? {} : { cursor }),
          },
          undefined,
          context,
        ),
      (page) => spenders.push(...page.transactions),
    );
    for (const head of open) {
      const spender = spenders.find((transaction) =>
        transaction.nullifiers.some((nullifier) => equalBytes(nullifier, head.nullifier)),
      );
      if (spender === undefined) {
        head.ended = true;
        continue;
      }
      const successor = spender.outputSlots
        .filter((slot) => slot.outputContext.tree === input.entriesTree)
        .map((slot) => decodeSuccessor(input.namespace, head, slot))
        .find((candidate) => candidate !== undefined);
      if (successor === undefined) {
        throw new RingError("RING_ENTRY_LINEAGE_BROKEN", {
          details: {
            listId: head.pair.listId,
            member: bytesKey(head.pair.member),
            version: head.live === undefined ? 0 : Number(head.live.entry.version + 1n),
          },
        });
      }
      head.nullifier = successor.nullifier;
      head.live = { ...successor, txSignature: spender.txSignature, slot: spender.slot };
    }
  }
  return heads.map((head) => head.live);
}

/** Content is trusted only after it reproduces the on-chain commitment. */
function decodeSuccessor(
  namespace: RingListNamespace,
  head: Head,
  slot: OutputSlot,
): Omit<LiveEntry, "txSignature" | "slot"> | undefined {
  const entry = tryDecodeListEntry(slot.payload);
  if (entry === undefined) return undefined;
  if (entry.listId !== head.pair.listId || !equalBytes(entry.member, head.pair.member)) {
    return undefined;
  }
  const hashes = namespace.entryHashes(entry);
  if (!equalBytes(hashes.utxoHash, slot.outputContext.hash)) return undefined;
  return { entry, utxoHash: hashes.utxoHash, nullifier: hashes.nullifier };
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
