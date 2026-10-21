import type {
  ChainReader,
  IndexerReader,
  KitRpcAccess,
  RingRecordReader,
} from "../client/ports.js";
import { initializePoseidon } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { mergePaddedInputCount } from "../interface/constants.js";
import { MAX_RING_MEMBER_BATCH } from "../interface/indexer-limits.js";
import { addressBytes } from "../interface/internal.js";
import { MEMBER_REGISTRY_CAPACITY } from "../interface/member-registry.js";
import type { Address, Bytes16, Bytes32, RequestContext, Signature } from "../interface/types.js";
import { mergeOutputBlinding, mergeOutputKey } from "../keypair/merge/index.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import { ringIdField } from "../keypair/ring-stream.js";
import type { X25519Keypair } from "../keypair/x25519.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
} from "../transaction/instructions/transact.js";
import { equal, poseidon } from "../transaction/internal.js";
import {
  MERGE_OUTPUT_BODY_LENGTH,
  decryptMergeOutput,
  readMergeOutputBody,
} from "../transaction/serialization/merge.js";
import { ownerUtxoHash, ringIdUtxoHash, type TreeId } from "../transaction/utxo.js";

import { registryCurrentRoot } from "./codecs.js";
import { fetchRingMemberRegistry } from "./config.js";
import { RingError } from "./error.js";
import { readRingHistory, scanLimits, type ScanLimits } from "./history.js";
import {
  openRingMergeDisclosure,
  type RingMergeDisclosure,
  type RingMergeOpening,
} from "./merge-disclosure.js";
import { MemberOpeningRead } from "./member-registry.js";
import { RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";
import { memberOfTag } from "./policy.js";
import { openNullifierKey } from "./register-key.js";

export type RingMergeAuditReader = KitRpcAccess &
  Pick<ChainReader, "getAccount"> &
  Pick<IndexerReader, "getShieldedTransactionsByTags"> &
  Pick<RingRecordReader, "getRingMemberRecords">;

/** Rust `MergeKeys`, what the auditor holds of the merge owner beyond the opening. */
export type MergeKeys =
  /** The registry escrow opened the nullifier key, the merged note's nullifier follows. */
  | Readonly<{ kind: "escrowed"; nullifier: Bytes32 }>
  /** Every spent commitment an anonymous merge disclosed, padding zero. */
  | Readonly<{ kind: "disclosed"; inputCommitments: readonly Bytes32[] }>;

/** Rust `AuditedMerge`, a merge output whose raw amount, mint and blinding reproduce its settled leaf. */
export interface AuditedRingMerge {
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
  /** The registry member hash, the merge proof does not disclose the signing key's curve. */
  readonly ownerMember: Bytes32;
  /** The confirmed `RegisterKey` signer or the disclosed owner, absent in older indexer projections. */
  readonly ownerPublicKey?: Address;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly inputNullifiers: readonly Bytes32[];
  readonly keys: MergeKeys;
}

/** Rust `UnresolvedMerge`, a confirmed merge no authenticated registration opened. */
export interface UnresolvedRingMerge {
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
}

export interface RingMergeAuditPage {
  readonly opened: readonly AuditedRingMerge[];
  readonly unresolved: readonly UnresolvedRingMerge[];
  /** Set only when the page cap stopped the history scan. */
  readonly nextCursor?: Uint8Array;
}

const DEFAULT_MAX_MEMBER_PAGES = Math.ceil(
  Number(MEMBER_REGISTRY_CAPACITY - 1n) / MAX_RING_MEMBER_BATCH,
);

/** Mirrors Rust `MergeAudit`, final registry keys let the chain's current root cover every earlier merge. */
export async function auditRingMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
    pageSize?: number;
    maxPages?: number;
    maxMemberPages?: number;
    /** Bounds the keys tried on unopened merges, a merge ciphertext names no owner. */
    maxCandidateAttempts?: number;
  }>,
  context?: RequestContext,
): Promise<RingMergeAuditPage> {
  await initializePoseidon();
  const limits = scanLimits(input);
  const maxMemberPages = input.maxMemberPages ?? DEFAULT_MAX_MEMBER_PAGES;
  for (const [name, value] of [
    ["maxMemberPages", maxMemberPages],
    ["maxCandidateAttempts", input.maxCandidateAttempts ?? 1],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1)
      throw new RingError("RING_RPC", { details: { reason: "invalid scan limit", name, value } });
  }
  const registry = await fetchRingMemberRegistry(input.client, input.ringProgramId, context);
  const tip = {
    root: registryCurrentRoot(registry).root,
    rootIndex: registry.historyCursor,
    nextIndex: registry.nextIndex,
  };
  const history = await confirmedMerges(input, limits, context);
  let attempts = 0;
  const opened: AuditedRingMerge[] = [];
  const pending: PendingMerge[] = [];
  for (const merge of history.merges) {
    if (merge.disclosure === undefined) pending.push({ merge });
    else opened.push(openDisclosed(input, merge, merge.disclosure));
  }
  if (pending.length > 0)
    await scanRegistry(input, tip, maxMemberPages, context, (member, key, ownerPublicKey) => {
      for (const candidate of pending) {
        if (candidate.opened !== undefined) continue;
        if (input.maxCandidateAttempts !== undefined && attempts >= input.maxCandidateAttempts)
          throw new RingError("RING_RECOVERY_INCOMPLETE", { details: { reason: "work budget" } });
        attempts += 1;
        const opened = openEscrowed(input.ringProgramId, candidate.merge, {
          member,
          key,
          ...(ownerPublicKey === undefined ? {} : { ownerPublicKey }),
        });
        if (opened !== undefined) candidate.opened = opened;
      }
      // Each opening reproduced its settled commitment, later leaves cannot change it.
      return pending.every((candidate) => candidate.opened !== undefined);
    });
  const unresolved: UnresolvedRingMerge[] = [];
  for (const candidate of pending) {
    if (candidate.opened !== undefined) opened.push(candidate.opened);
    else
      unresolved.push(
        Object.freeze({
          signature: candidate.merge.transaction.txSignature,
          eventIndex: candidate.merge.eventIndex,
          outputCommitment: candidate.merge.outputCommitment,
        }),
      );
  }
  return Object.freeze({
    opened: Object.freeze(opened),
    unresolved: Object.freeze(unresolved),
    ...(history.nextCursor === undefined ? {} : { nextCursor: history.nextCursor }),
  });
}

/** Rust `DisclosedMerge::open`, the disclosure must reproduce the settled leaf. */
export function openDisclosedMerge(
  input: Readonly<{
    auditor: X25519Keypair;
    disclosure: RingMergeDisclosure;
    salt: Bytes16;
    width: number;
    ringId: Bytes32;
    ringDataHash: Bytes32;
    treeId: TreeId;
    outputCommitment: Bytes32;
  }>,
): RingMergeOpening {
  const opening = openRingMergeDisclosure(input.auditor, input.disclosure, input.salt);
  if (opening.inputCommitments.length !== input.width)
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "merge disclosure width" } });
  const commitment = ringIdUtxoHash({
    owner: poseidon([memberOfTag(addressBytes(opening.ownerKey)), opening.nullifierPublicKey]),
    asset: opening.mint,
    amount: opening.amount,
    blinding: opening.outputBlinding,
    treeId: input.treeId,
    ringDataHash: input.ringDataHash,
    ringId: input.ringId,
  });
  if (!equal(commitment, input.outputCommitment))
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "merge disclosure output" } });
  return opening;
}

/** @internal One confirmed ring merge whose public fields were checked before any key is tried. */
export interface ConfirmedMerge {
  readonly transaction: IndexedShieldedTransaction;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly width: number;
  /** Set exactly for an anonymous ring, whose program verified it before SPP settled. */
  readonly disclosure?: RingMergeDisclosure;
}

interface PendingMerge {
  readonly merge: ConfirmedMerge;
  opened?: AuditedRingMerge;
}

/** The chain's newest registry root, every record page is read under it. */
interface RegistryTip {
  readonly root: Bytes32;
  readonly rootIndex: number;
  readonly nextIndex: number;
}

async function confirmedMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
  }>,
  limits: ScanLimits,
  context: RequestContext | undefined,
): Promise<{ merges: readonly ConfirmedMerge[]; nextCursor?: Uint8Array }> {
  const merges: ConfirmedMerge[] = [];
  const seen = new Set<string>();
  const nextCursor = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      origin: input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits,
    },
    (confirmed, eventIndex) => {
      if (confirmed.kind !== "merge") return;
      const event = `${confirmed.transaction.txSignature}:${String(eventIndex)}`;
      if (seen.has(event))
        throw new RingError("RING_ORIGIN_DECODE", { details: { reason: "duplicate merge" } });
      seen.add(event);
      merges.push(confirmedMerge(confirmed.transaction, eventIndex, confirmed.disclosure));
    },
    context,
  );
  return { merges, ...(nextCursor === undefined ? {} : { nextCursor }) };
}

/** @internal Rust `validate_confirmed_merge_fields`, a malformed public field is an audit error, not a key miss. */
export function confirmedMerge(
  transaction: IndexedShieldedTransaction,
  eventIndex: number,
  disclosure: RingMergeDisclosure | undefined,
): ConfirmedMerge {
  const slot = transaction.outputSlots[0];
  const firstNullifier = transaction.nullifiers[0];
  const width = mergePaddedInputCount(transaction.nullifiers.length);
  const body = slot === undefined ? undefined : readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  if (
    slot === undefined ||
    firstNullifier === undefined ||
    transaction.outputSlots.length !== 1 ||
    width === undefined ||
    body === undefined ||
    ringDataHash === undefined ||
    body.encrypted.length !== MERGE_OUTPUT_BODY_LENGTH ||
    !isCanonicalField(firstNullifier) ||
    !isCanonicalField(slot.outputContext.hash) ||
    !isCanonicalField(ringDataHash) ||
    !ciphertextChunks(body.encrypted).every(isCanonicalField)
  )
    throw new RingError("RING_ORIGIN_DECODE", { details: { reason: "ring merge output" } });
  return Object.freeze({
    transaction,
    eventIndex,
    outputCommitment: slot.outputContext.hash,
    ringDataHash,
    width,
    ...(disclosure === undefined ? {} : { disclosure }),
  });
}

/** The 32-byte ciphertext elements behind the 16-byte salt. */
function ciphertextChunks(encrypted: Uint8Array): readonly Uint8Array[] {
  return Array.from({ length: (encrypted.length - 16) / 32 }, (_, index) =>
    encrypted.subarray(16 + 32 * index, 48 + 32 * index),
  );
}

/** @internal Rust `MergeOutput::disclose`. */
export function disclosedMergeOpening(
  input: Readonly<{ ringProgramId: Address; auditor: X25519Keypair }>,
  merge: ConfirmedMerge,
  disclosure: RingMergeDisclosure,
): RingMergeOpening {
  const slot = merge.transaction.outputSlots[0]!;
  const encrypted = readMergeOutputBody(slot.payload)!.encrypted;
  return openDisclosedMerge({
    auditor: input.auditor,
    disclosure,
    salt: encrypted.slice(0, 16) as Bytes16,
    width: merge.width,
    ringId: ringIdField(input.ringProgramId),
    ringDataHash: merge.ringDataHash,
    treeId: slot.outputContext.treeId,
    outputCommitment: merge.outputCommitment,
  });
}

function openDisclosed(
  input: Readonly<{ ringProgramId: Address; auditor: X25519Keypair }>,
  merge: ConfirmedMerge,
  disclosure: RingMergeDisclosure,
): AuditedRingMerge {
  const opening = disclosedMergeOpening(input, merge, disclosure);
  return Object.freeze({
    signature: merge.transaction.txSignature,
    eventIndex: merge.eventIndex,
    outputCommitment: merge.outputCommitment,
    ownerMember: memberOfTag(addressBytes(opening.ownerKey)),
    ownerPublicKey: opening.ownerKey,
    mint: opening.mint,
    amount: opening.amount,
    blinding: opening.outputBlinding,
    ringDataHash: merge.ringDataHash,
    inputNullifiers: merge.transaction.nullifiers,
    keys: Object.freeze({ kind: "disclosed", inputCommitments: opening.inputCommitments }),
  });
}

/** Rust `open_candidate`, the settled commitment alone decides whether the key's member owns it. */
function openEscrowed(
  ring: Address,
  merge: ConfirmedMerge,
  registered: Readonly<{ member: Bytes32; key: NullifierKey; ownerPublicKey?: Address }>,
): AuditedRingMerge | undefined {
  const opening = recoverMergeOpening(
    { member: registered.member, nullifierKey: registered.key, ringProgramId: ring },
    merge.transaction,
  );
  if (opening === undefined) return undefined;
  return Object.freeze({
    signature: merge.transaction.txSignature,
    eventIndex: merge.eventIndex,
    outputCommitment: merge.outputCommitment,
    ownerMember: registered.member,
    ...(registered.ownerPublicKey === undefined
      ? {}
      : { ownerPublicKey: registered.ownerPublicKey }),
    mint: opening.asset,
    amount: opening.amount,
    blinding: opening.blinding,
    ringDataHash: merge.ringDataHash,
    inputNullifiers: merge.transaction.nullifiers,
    keys: Object.freeze({ kind: "escrowed", nullifier: opening.nullifier }),
  });
}

/** A verified merge opening when only the registered member hash is known. */
export interface MergeAuditorOpening {
  readonly member: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
  readonly ringDataHash?: Bytes32;
}

/** The merge output the member's key decrypts, `undefined` unless it reproduces the settled commitment. */
export function recoverMergeOpening(
  input: Readonly<{ member: Bytes32; nullifierKey: NullifierKey; ringProgramId: Address }>,
  transaction: IndexedShieldedTransaction,
): MergeAuditorOpening | undefined {
  const firstNullifier = transaction.nullifiers[0];
  const slot = transaction.outputSlots[0];
  if (
    firstNullifier === undefined ||
    slot === undefined ||
    mergePaddedInputCount(transaction.nullifiers.length) === undefined
  )
    return undefined;
  const body = readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  if (body === undefined || ringDataHash === undefined) return undefined;
  const outputKey = mergeOutputKey(input.nullifierKey, firstNullifier);
  let plaintext;
  try {
    plaintext = decryptMergeOutput(body.encrypted, outputKey);
  } catch {
    return undefined;
  } finally {
    outputKey.fill(0);
  }
  const blinding = mergeOutputBlinding(input.nullifierKey, firstNullifier);
  const commitment = ownerUtxoHash({
    owner: poseidon([input.member, input.nullifierKey.publicKey()]),
    asset: plaintext.mint,
    amount: plaintext.amount,
    blinding,
    treeId: slot.outputContext.treeId,
    ringDataHash,
    ringProgramId: input.ringProgramId,
  });
  if (!equal(commitment, slot.outputContext.hash)) return undefined;
  return Object.freeze({
    member: input.member,
    asset: plaintext.mint,
    amount: plaintext.amount,
    blinding,
    outputContext: slot.outputContext,
    nullifier: input.nullifierKey.nullifier(slot.outputContext.hash, blinding),
    ...(ringDataHash.some((byte) => byte !== 0) ? { ringDataHash } : {}),
  });
}

/** Rust `MergeAudit::scan_registry`, every record authenticated at the chain's root until `visit` stops. */
async function scanRegistry(
  input: Readonly<{ client: RingMergeAuditReader; ringProgramId: Address; auditor: X25519Keypair }>,
  tip: RegistryTip,
  maxMemberPages: number,
  context: RequestContext | undefined,
  visit: (member: Bytes32, key: NullifierKey, ownerPublicKey: Address | undefined) => boolean,
): Promise<void> {
  let startIndex = 1;
  for (let read = 0; startIndex < tip.nextIndex; read++) {
    if (read === maxMemberPages)
      throw new RingError("RING_RECOVERY_INCOMPLETE", { details: { reason: "member pages" } });
    const page = await input.client.getRingMemberRecords(
      {
        ringProgramId: input.ringProgramId,
        expectedRoot: tip.root,
        expectedNextIndex: tip.nextIndex,
        startIndex,
        limit: MAX_RING_MEMBER_BATCH,
      },
      context,
    );
    const endIndex = Math.min(startIndex + MAX_RING_MEMBER_BATCH, tip.nextIndex);
    if (
      !equal(page.root.root, tip.root) ||
      page.root.rootIndex !== tip.rootIndex ||
      page.root.nextIndex !== tip.nextIndex ||
      page.records.length !== endIndex - startIndex ||
      page.records.some((row, offset) => row.path.index !== startIndex + offset) ||
      page.nextLeafIndex !== (endIndex < tip.nextIndex ? endIndex : undefined)
    )
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { startIndex } });
    for (const { record, path, sealedKey } of page.records) {
      const ownerPublicKey = sealedKey?.owner;
      if (
        ownerPublicKey !== undefined &&
        !equal(memberOfTag(addressBytes(ownerPublicKey)), record.member)
      )
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "owner" } });
      const read = MemberOpeningRead.verify(
        { kind: "present", record, path, ...(sealedKey === undefined ? {} : { sealedKey }) },
        tip.root,
        record.member,
      );
      if (record.escrowKey.every((byte) => byte === 0)) continue;
      if (sealedKey === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "sealed key" } });
      const key = openNullifierKey(sealedKey, input.auditor);
      try {
        if (read.escrowed(key.publicKey()) === undefined)
          throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
            details: { reason: "escrow key" },
          });
        if (visit(record.member, key, ownerPublicKey)) return;
      } finally {
        key.destroy();
      }
    }
    startIndex = endIndex;
  }
}
