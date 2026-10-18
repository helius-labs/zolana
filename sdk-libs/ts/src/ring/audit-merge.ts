import type {
  ChainReader,
  IndexerReader,
  KitRpcAccess,
  RingMemberRegistryReader,
} from "../client/ports.js";
import { ClientError } from "../client/error.js";
import type { Address, Bytes32, RequestContext, Signature } from "../interface/types.js";
import type { X25519Secret } from "../keypair/x25519.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import { initializePoseidon } from "../hasher/index.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
} from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import { Utxo } from "../transaction/utxo.js";
import { bytesKey } from "../wallet/internal.js";
import { addressBytes } from "../interface/internal.js";

import { fetchRingMemberRegistryRoot } from "./config.js";
import { RingError } from "./error.js";
import {
  openNullifierKey,
  openRingSealedKey,
  readSealedKey,
  registersKey,
} from "./member-registry.js";
import { MEMBER_REGISTRY_CAPACITY, verifyMemberOpening } from "./member-registry-tree.js";
import { CachedTransactionOrigin, RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";
import { memberOfIdentity, memberOfTag } from "./policy.js";
import { recoverMergeOpening, type MergeAuditorOpening } from "./recover.js";
import { ringTreeIdResolver } from "./trees.js";

export type RingMergeAuditReader = KitRpcAccess &
  Pick<ChainReader, "getAccount"> &
  Pick<IndexerReader, "getShieldedTransactionsByTags"> &
  Pick<RingMemberRegistryReader, "getRingMemberRecord" | "getRingMemberRecords">;

/** A confirmed merge output reconstructed from a verified registered owner key. */
export interface AuditedRingMerge {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly source: ShieldedAddress;
  readonly utxo: Utxo;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
}

/** Every other confirmed merge remains visible by its committed output. */
export interface UnresolvedRingMerge {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly outputContext: OutputContext;
}

/** Authenticated contents of a merge when the registry exposes only its owner hash. */
export interface AuditedRingMergeOpening extends MergeAuditorOpening {
  readonly signature: Signature;
  readonly slot: bigint;
  /** Confirmed RegisterKey signer when the indexer retained that lineage. */
  readonly ownerPublicKey?: Address;
}

export interface RingMergeAuditPage {
  readonly openings: readonly AuditedRingMergeOpening[];
  readonly merges: readonly AuditedRingMerge[];
  readonly unresolved: readonly UnresolvedRingMerge[];
  readonly unavailableMembers: readonly Bytes32[];
  readonly nextCursor?: Uint8Array;
}

const MAX_CONFIRMED_ROWS_PER_BATCH = 4096;

/**
 * Scans confirmed ring merges against a chain-pinned registry. The paged
 * registry discovers keys, while optional addresses turn raw openings into UTXOs.
 * Every merge without a verified opening is returned as unresolved.
 */
export async function auditRingMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    auditor: X25519Secret;
    members?: readonly ShieldedAddress[];
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
    pageSize?: number;
    maxPages?: number;
    memberPageSize?: number;
    maxMemberPages?: number;
  }>,
  context?: RequestContext,
): Promise<RingMergeAuditPage> {
  await initializePoseidon();
  const pageSize = input.pageSize ?? 100;
  const maxPages = input.maxPages ?? 32;
  const memberPageSize = input.memberPageSize ?? 100;
  const maxMemberPages =
    input.maxMemberPages ?? Math.ceil(Number(MEMBER_REGISTRY_CAPACITY - 1n) / memberPageSize);
  for (const [name, value] of [
    ["pageSize", pageSize],
    ["maxPages", maxPages],
    ["memberPageSize", memberPageSize],
    ["maxMemberPages", maxMemberPages],
  ] as const) {
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      (name === "pageSize" && value > Number(PAGE_LIMIT)) ||
      (name === "memberPageSize" && value > 100)
    ) {
      throw new RingError("RING_RPC", {
        details: { reason: "invalid scan limit", name, value },
      });
    }
  }
  if (pageSize * maxPages > MAX_CONFIRMED_ROWS_PER_BATCH)
    throw new RingError("RING_RPC", {
      details: { reason: "confirmed merge batch exceeds memory bound" },
    });
  const registry = await fetchRingMemberRegistryRoot(input.client, input.ringProgramId, context);
  // A history page is bounded, while the member registry may hold 2^20 leaves.
  // Keep confirmed merges and stream one recovered member key at a time.
  const history = await confirmedMerges(input, pageSize, maxPages, context);
  if (history.transactions.length === 0)
    return Object.freeze({
      openings: Object.freeze([]),
      merges: Object.freeze([]),
      unresolved: Object.freeze([]),
      unavailableMembers: Object.freeze([]),
      ...(history.nextCursor === undefined ? {} : { nextCursor: history.nextCursor }),
    });
  const results = new Map<
    number,
    {
      opening: MergeAuditorOpening;
      source?: ShieldedAddress;
      ownerPublicKey?: Address;
    }
  >();
  const resolveTreeId = ringTreeIdResolver(input.client, [], context);
  const treeIds = new Map<Address, number>();
  const unavailableMembers = new Map<string, Bytes32>();
  const seenCandidates = new Set<string>();
  const openedMembers = new Set<string>();
  const tryKey = async (
    member: Bytes32,
    key: NullifierKey,
    source?: ShieldedAddress,
    ownerPublicKey?: Address,
  ) => {
    try {
      for (const [index, transaction] of history.transactions.entries()) {
        if (results.has(index)) continue;
        const opening = await recoverMergeOpening(
          {
            member,
            nullifierKey: key,
            ringProgramId: input.ringProgramId,
            resolveTreeId,
          },
          transaction,
          treeIds,
        );
        if (opening !== undefined)
          results.set(index, {
            opening,
            ...(source === undefined ? {} : { source }),
            ...(ownerPublicKey === undefined ? {} : { ownerPublicKey }),
          });
      }
    } finally {
      key.destroy();
    }
  };
  for (const source of input.members ?? []) {
    const member = memberOfIdentity(source.signingPublicKey.ownerProofInputHash());
    const ownerPublicKey = source.solanaAddress();
    const nullifierPublicKey = source.nullifierPublicKey;
    const identity = bytesKey(member);
    if (seenCandidates.has(identity)) continue;
    seenCandidates.add(identity);
    let record: Awaited<ReturnType<typeof readSealedKey>>;
    try {
      record = await readSealedKey(
        { client: input.client, ringProgramId: input.ringProgramId, member, registry },
        context ?? {},
      );
    } catch (cause) {
      if (
        !(cause instanceof ClientError) ||
        cause.code !== "CLIENT_MEMBER_REGISTRY_MEMBER_UNREGISTERED"
      )
        throw cause;
      unavailableMembers.set(identity, member);
      continue;
    }
    if (!registersKey(record, nullifierPublicKey)) {
      unavailableMembers.set(identity, member);
      continue;
    }
    let key: NullifierKey;
    try {
      key = openNullifierKey(record.sealed, input.auditor);
    } catch {
      unavailableMembers.set(identity, member);
      continue;
    }
    let matches: boolean;
    try {
      matches = equal(key.publicKey(), nullifierPublicKey);
    } catch {
      key.destroy();
      unavailableMembers.set(identity, member);
      continue;
    }
    if (!matches) {
      key.destroy();
      unavailableMembers.set(identity, member);
      continue;
    }
    await tryKey(member, key, source, ownerPublicKey);
    openedMembers.add(identity);
  }
  const listMembers = input.client.getRingMemberRecords;
  if (listMembers === undefined && input.members === undefined)
    throw new RingError("RING_RPC", {
      details: { reason: "member registry enumeration unavailable" },
    });
  if (listMembers !== undefined) {
    let startIndex = 1n;
    let memberPages = 0;
    while (startIndex < registry.nextIndex) {
      if (memberPages++ >= maxMemberPages) throw new RingError("RING_RECOVERY_INCOMPLETE");
      const response = await listMembers.call(
        input.client,
        {
          ringProgramId: input.ringProgramId,
          expectedRoot: registry.root,
          expectedNextIndex: registry.nextIndex,
          startIndex,
          limit: memberPageSize,
        },
        context,
      );
      const endIndex =
        startIndex + BigInt(memberPageSize) < registry.nextIndex
          ? startIndex + BigInt(memberPageSize)
          : registry.nextIndex;
      if (
        !equal(response.root, registry.root) ||
        response.rootIndex !== registry.historyCursor ||
        response.nextIndex !== registry.nextIndex ||
        response.records.length !== Number(endIndex - startIndex) ||
        response.nextLeafIndex !== (endIndex < registry.nextIndex ? endIndex : null)
      )
        throw new RingError("RING_MEMBER_REGISTRY_STALE");
      for (const [offset, entry] of response.records.entries()) {
        if (entry.index !== startIndex + BigInt(offset))
          throw new RingError("RING_MEMBER_REGISTRY_INVALID");
        const { record } = entry;
        verifyMemberOpening(registry.root, record.member, {
          present: true,
          record,
          index: entry.index,
          path: entry.path,
        });
        if (
          record.ownerPublicKey !== undefined &&
          record.ownerPublicKey !== null &&
          !equal(memberOfTag(addressBytes(record.ownerPublicKey)), record.member)
        )
          throw new RingError("RING_MEMBER_REGISTRY_INVALID");
        if (record.escrowKey.every((byte) => byte === 0)) continue;
        const identity = bytesKey(record.member);
        if (openedMembers.has(identity)) continue;
        if (record.ephemeralPublicKey === null || record.ciphertext === null) {
          unavailableMembers.set(identity, record.member);
          continue;
        }
        let key: NullifierKey;
        try {
          key = openRingSealedKey(
            {
              member: memberOfIdentity(record.member),
              sealed: {
                ephemeralPublicKey: record.ephemeralPublicKey,
                ciphertext: record.ciphertext,
              },
              root: registry.root,
              next: record.next,
              lists: record.lists,
              escrowKey: record.escrowKey,
              index: entry.index,
              proof: entry.path,
            },
            input.auditor,
          );
        } catch {
          unavailableMembers.set(identity, record.member);
          continue;
        }
        await tryKey(record.member, key, undefined, record.ownerPublicKey ?? undefined);
        openedMembers.add(identity);
        unavailableMembers.delete(identity);
      }
      startIndex = endIndex;
    }
  }
  const openings: AuditedRingMergeOpening[] = [];
  const merges: AuditedRingMerge[] = [];
  const unresolved: UnresolvedRingMerge[] = [];
  for (const [index, transaction] of history.transactions.entries()) {
    const outputContext = transaction.outputSlots[0]!.outputContext;
    const result = results.get(index);
    if (result === undefined) {
      unresolved.push({
        signature: transaction.txSignature,
        slot: transaction.slot,
        outputContext,
      });
      continue;
    }
    const { opening, source, ownerPublicKey } = result;
    openings.push({
      signature: transaction.txSignature,
      slot: transaction.slot,
      ...opening,
      ...(ownerPublicKey === undefined ? {} : { ownerPublicKey }),
    });
    if (source !== undefined)
      merges.push({
        signature: transaction.txSignature,
        slot: transaction.slot,
        source,
        utxo: new Utxo({
          owner: source.signingPublicKey,
          asset: opening.asset,
          amount: opening.amount,
          blinding: opening.blinding,
          ringProgramId: input.ringProgramId,
        }),
        outputContext,
        nullifier: opening.nullifier,
      });
  }
  return Object.freeze({
    openings: Object.freeze(openings),
    merges: Object.freeze(merges),
    unresolved: Object.freeze(unresolved),
    unavailableMembers: Object.freeze([...unavailableMembers.values()]),
    ...(history.nextCursor === undefined ? {} : { nextCursor: history.nextCursor }),
  });
}

async function confirmedMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
  }>,
  pageSize: number,
  maxPages: number,
  context?: RequestContext,
): Promise<
  Readonly<{ transactions: readonly IndexedShieldedTransaction[]; nextCursor?: Uint8Array }>
> {
  const origin = new CachedTransactionOrigin(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
  );
  const transactions: IndexedShieldedTransaction[] = [];
  const seenEvents = new Set<string>();
  let cursor = input.cursor;
  for (let page = 0; page < maxPages; page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      {
        tags: [],
        ringProgramId: input.ringProgramId,
        limit: pageSize,
        ...(cursor === undefined ? {} : { cursor }),
      },
      undefined,
      context,
    );
    if (response.transactions.length > pageSize)
      throw new RingError("RING_RPC", {
        details: { reason: "merge history page exceeds requested limit" },
      });
    for (const indexed of response.transactions) {
      const transaction = await origin.confirmedTransaction(indexed, input.ringProgramId, context);
      const kind =
        transaction === undefined
          ? undefined
          : await origin.confirmedEventKind(transaction, input.ringProgramId, context);
      if (kind !== "merge" || transaction === undefined) continue;
      if (
        transaction.proofless ||
        transaction.txViewingPublicKey !== undefined ||
        transaction.salt !== undefined ||
        transaction.outputSlots.length !== 1
      )
        throw new RingError("RING_ORIGIN_DECODE", {
          details: { reason: "confirmed merge shape is invalid" },
        });
      const event = `${transaction.txSignature}:${transaction.eventIndex}`;
      if (seenEvents.has(event))
        throw new RingError("RING_RPC", {
          details: { reason: "duplicate confirmed merge in history" },
        });
      seenEvents.add(event);
      transactions.push(transaction);
    }
    const next = response.scannedThrough === undefined ? response.nextCursor : undefined;
    if (next === undefined) return { transactions };
    if (cursor !== undefined && equal(cursor, next))
      throw new RingError("RING_RPC", {
        details: { reason: "merge scan cursor did not advance" },
      });
    cursor = next;
  }
  return { transactions, ...(cursor === undefined ? {} : { nextCursor: cursor }) };
}
