import { X25519Keypair } from "../keypair/x25519.js";
import type { Address } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import { mergePaddedInputCount } from "../interface/constants.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import { readRingDepositCapsule } from "./deposit-capsule.js";
import { mergeOutputBlinding, mergeOutputKey } from "../keypair/merge/index.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";

import type { AssetRegistry } from "../transaction/asset.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
} from "../transaction/instructions/transact.js";
import { U64_MAX, bytesToBigInt, equal, poseidon } from "../transaction/internal.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import { UTXO_DOMAIN } from "../interface/program.js";
import { EncryptedScheme, readOutputData } from "../transaction/serialization/codecs.js";
import { decryptMergeOutput, readMergeOutputBody } from "../transaction/serialization/merge.js";
import { decodeRingDepositOutput } from "../transaction/serialization/ring-deposit.js";
import { Utxo, ownerUtxoHash, type TreeId } from "../transaction/utxo.js";
import type { WalletUtxo } from "../transaction/wallet/state.js";
import { bytesKey } from "../wallet/internal.js";
import { auditRing, nextScanCursor, type RingAuditReader } from "./audit.js";
import type { RingMode } from "./codecs.js";
import { RingError } from "./error.js";
import {
  CachedTransactionOrigin,
  RpcTransactionOrigin,
  type TransactionOrigin,
  type AuditedDepositSource,
} from "./origin.js";
import { openRingDepositOpening } from "./deposit-audit.js";

export type RingRecoveryClient = RingAuditReader &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;

/** Reconstructs member notes from auditor disclosure and nullifier material. */
export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: X25519Keypair;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  /** The ring's on-chain mode, `"off"` when omitted. An anonymous ring matches notes by the disclosed owner. */
  readonly mode?: RingMode;
  /** The raw id a note's leaf is committed under. */
  readonly resolveTreeId: (tree: Address) => TreeId | Promise<TreeId>;
  readonly origin?: TransactionOrigin;
  /** Confirms audited capsule bytes before exposing a deposit owner. Defaults to the Solana RPC. */
  readonly depositSource?: AuditedDepositSource;
  readonly pageSize?: number;
  readonly maxPages?: number;
}

/** Separates recovered unspent notes from unresolved coverage. */
export interface RecoveredRingNotes {
  readonly notes: readonly WalletUtxo[];
  /** Commitments no rebuilt opening reproduces. */
  readonly unopened: readonly Bytes32[];
  /** Recipient encrypted deposits with unknown spend status. */
  readonly unsupportedDeposits: readonly Bytes32[];
}

/** Retains a verified note opening while its spend status is resolved. */
export interface MergeRecoveryCandidate {
  readonly utxo: Utxo;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}

export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RecoveredRingNotes> {
  // 1. Bind nullifier material to the requested member before scanning history.
  if (!equal(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const rpcOrigin = new RpcTransactionOrigin(input.client.solanaRpc);
  const origin = new CachedTransactionOrigin(input.origin ?? rpcOrigin);
  const depositSource = input.depositSource ?? rpcOrigin;
  const page = await auditRing(
    {
      client: input.client,
      auditor: input.auditor,
      ringProgramId: input.ringProgramId,
      assets: input.assets,
      ...(input.mode === undefined ? {} : { mode: input.mode }),
      origin,
      ...(input.pageSize === undefined ? {} : { pageSize: input.pageSize }),
      ...(input.maxPages === undefined ? {} : { maxPages: input.maxPages }),
    },
    context,
  );
  if (page.nextCursor !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  const treeIds = new Map<Address, TreeId>();
  // 2. Rebuild disclosed openings and retain unresolved commitments explicitly.
  const deposits = await recoverDeposits(input, origin, depositSource, treeIds, context);
  const unsupportedDeposits = deposits.unsupported;
  const candidates: MergeRecoveryCandidate[] = deposits.candidates;
  const unopened: Bytes32[] = [];
  const unopenedNullifiers = new Map<string, Bytes32>();
  const seen = new Set(candidates.map((candidate) => bytesKey(candidate.outputContext.hash)));
  const sourceOwnerHash = input.source.ownerHash();
  const ringHash = hashBytes(addressBytes(input.ringProgramId));
  for (const transaction of page.transactions) {
    for (const [slotIndex, opening] of transaction.outputOpenings.entries()) {
      if (
        bytesToBigInt(opening.domain) !== BigInt(UTXO_DOMAIN) ||
        !equal(opening.ownerHash, sourceOwnerHash) ||
        !equal(opening.ringProgramId, ringHash)
      )
        continue;
      const outputContext = transaction.outputContexts[slotIndex];
      if (outputContext === undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
      const key = bytesKey(outputContext.hash);
      if (seen.has(key)) continue;
      seen.add(key);
      const nullifier = input.nullifierKey.nullifier(outputContext.hash, opening.blinding);
      const asset = input.assets.addressForField(opening.asset);
      const amount = bytesToBigInt(opening.amount);
      if (amount > U64_MAX) throw new RingError("RING_AUDIT_OUTPUT_MISMATCH");
      if (asset === undefined) {
        unopened.push(outputContext.hash);
        unopenedNullifiers.set(key, nullifier);
        continue;
      }
      let treeId = treeIds.get(outputContext.tree);
      if (treeId === undefined) {
        treeId = await input.resolveTreeId(outputContext.tree);
        treeIds.set(outputContext.tree, treeId);
      }
      // Recipient metadata is unproved. It must not change spend eligibility.
      const utxo = new Utxo({
        owner: input.source.signingPublicKey,
        asset,
        amount,
        blinding: opening.blinding,
        ringProgramId: input.ringProgramId,
      });
      const hashes = {
        ...(isZero(opening.dataHash) ? {} : { dataHash: opening.dataHash }),
        ...(isZero(opening.ringDataHash) ? {} : { ringDataHash: opening.ringDataHash }),
      };
      if (
        !equal(
          utxo.hash(input.source.nullifierPublicKey, treeId, hashes.dataHash, hashes.ringDataHash),
          outputContext.hash,
        )
      ) {
        unopened.push(outputContext.hash);
        unopenedNullifiers.set(key, nullifier);
        continue;
      }
      candidates.push({ utxo, outputContext, nullifier, ...hashes });
    }
  }
  const spent = new Set<string>();
  const pending = new Map<string, IndexedShieldedTransaction>();
  const queries = [
    ...candidates.map((candidate) => candidate.nullifier),
    ...unopenedNullifiers.values(),
  ];
  const budget = { remaining: input.maxPages ?? 32 };
  let scanned = 0;
  // 3. Follow spends until every recoverable merge successor has been checked.
  while (scanned < queries.length) {
    const batch = queries.slice(scanned, scanned + Number(PAGE_LIMIT));
    scanned += batch.length;
    const requested = new Set(batch.map(bytesKey));
    for (const indexed of await spendingTransactions(input.client, batch, budget, context)) {
      const transaction = await origin.confirmedTransaction(indexed, input.ringProgramId, context);
      if (transaction === undefined) continue;
      if (!transaction.nullifiers.some((nullifier) => requested.has(bytesKey(nullifier)))) continue;
      for (const nullifier of transaction.nullifiers) spent.add(bytesKey(nullifier));
      const slot = transaction.outputSlots[0];
      if (
        transaction.proofless ||
        transaction.txViewingPublicKey !== undefined ||
        transaction.salt !== undefined ||
        transaction.outputSlots.length !== 1 ||
        slot === undefined
      )
        continue;
      const hash = bytesKey(slot.outputContext.hash);
      if (!seen.has(hash)) pending.set(hash, transaction);
    }
    // Each merge output decrypts from its own transaction, so one pass settles it.
    for (const [hash, transaction] of pending) {
      const candidate = await recoverMerge(input, transaction, treeIds);
      if (candidate === undefined) continue;
      seen.add(hash);
      candidates.push(candidate);
      queries.push(candidate.nullifier);
      pending.delete(hash);
    }
  }
  for (const transaction of pending.values()) {
    const slot = transaction.outputSlots[0];
    if (slot !== undefined) unopened.push(slot.outputContext.hash);
  }
  // 4. Return only unspent candidates without hiding recovery gaps.
  const notes = candidates
    .filter((candidate) => !spent.has(bytesKey(candidate.nullifier)))
    .map((candidate) =>
      Object.freeze({
        utxo: candidate.utxo,
        outputContext: candidate.outputContext,
        nullifier: candidate.nullifier,
        ...(candidate.dataHash === undefined ? {} : { dataHash: candidate.dataHash }),
        ...(candidate.ringDataHash === undefined ? {} : { ringDataHash: candidate.ringDataHash }),
        spent: false,
      }),
    );
  return Object.freeze({
    notes: Object.freeze(notes),
    unopened: Object.freeze(
      unopened.filter((hash) => {
        const nullifier = unopenedNullifiers.get(bytesKey(hash));
        return nullifier === undefined || !spent.has(bytesKey(nullifier));
      }),
    ),
    unsupportedDeposits: Object.freeze(unsupportedDeposits),
  });
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

async function recoverDeposits(
  input: RingRecoveryParams,
  origin: TransactionOrigin,
  depositSource: AuditedDepositSource,
  treeIds: Map<Address, TreeId>,
  context?: RequestContext,
): Promise<{ unsupported: Bytes32[]; candidates: MergeRecoveryCandidate[] }> {
  const found = new Map<string, Bytes32>();
  const candidates = new Map<string, MergeRecoveryCandidate>();
  let cursor: Uint8Array | undefined;
  for (let page = 0; page < (input.maxPages ?? 32); page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      {
        tags: [],
        ringProgramId: input.ringProgramId,
        limit: input.pageSize ?? 100,
        ...(cursor === undefined ? {} : { cursor }),
      },
      undefined,
      context,
    );
    for (const indexed of response.transactions) {
      const transaction = await origin.confirmedTransaction(indexed, input.ringProgramId, context);
      if (transaction === undefined) continue;
      if (!transaction.proofless) continue;
      for (const [slotIndex, slot] of transaction.outputSlots.entries()) {
        const commitment = slot.outputContext.hash;
        let deposit;
        try {
          const frame = readOutputData(slot.payload);
          if (frame.scheme !== EncryptedScheme.ringDeposit || frame.encoding !== "encrypted") {
            found.set(bytesKey(commitment), commitment);
            continue;
          }
          deposit = decodeRingDepositOutput(frame.body);
        } catch {
          found.set(bytesKey(commitment), commitment);
          continue;
        }
        if (deposit.ringProgramId !== input.ringProgramId || transaction.eventIndex === undefined) {
          found.set(bytesKey(commitment), commitment);
          continue;
        }
        let opening;
        const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
        if (capsule !== undefined) {
          const confirmed = (
            await depositSource.confirmedDeposits(
              transaction.txSignature,
              transaction.eventIndex,
              input.ringProgramId,
              context,
            )
          )[slotIndex];
          if (confirmed === undefined) {
            found.set(bytesKey(slot.outputContext.hash), slot.outputContext.hash);
            continue;
          }
          opening = openRingDepositOpening(
            capsule,
            input.auditor,
            deposit.ownerUtxoHash,
            confirmed,
          );
        }
        if (opening === undefined) {
          found.set(bytesKey(slot.outputContext.hash), slot.outputContext.hash);
          continue;
        }
        try {
          if (!equal(opening.ownerHash, input.source.ownerHash())) continue;
          let treeId = treeIds.get(slot.outputContext.tree);
          if (treeId === undefined) {
            treeId = await input.resolveTreeId(slot.outputContext.tree);
            treeIds.set(slot.outputContext.tree, treeId);
          }
          const utxo = new Utxo({
            owner: input.source.signingPublicKey,
            asset: deposit.asset,
            amount: deposit.amount,
            blinding: opening.blinding,
            ringProgramId: deposit.ringProgramId,
          });
          if (
            !equal(
              utxo.hash(
                input.source.nullifierPublicKey,
                treeId,
                deposit.dataHash,
                deposit.ringDataHash,
              ),
              slot.outputContext.hash,
            )
          )
            throw new RingError("RING_AUDIT_MESSAGE");
          candidates.set(bytesKey(slot.outputContext.hash), {
            utxo,
            outputContext: slot.outputContext,
            nullifier: utxo.nullifier(slot.outputContext.hash, input.nullifierKey),
            ...(deposit.dataHash === undefined ? {} : { dataHash: deposit.dataHash }),
            ringDataHash: deposit.ringDataHash,
          });
        } finally {
          opening.ownerHash.fill(0);
          opening.blinding.fill(0);
        }
      }
    }
    const next = nextScanCursor(cursor, response);
    if (next === undefined)
      return {
        unsupported: [...found.values()],
        candidates: [...candidates.values()],
      };
    cursor = next;
  }
  throw new RingError("RING_RECOVERY_INCOMPLETE");
}

async function spendingTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">,
  nullifiers: readonly Bytes32[],
  budget: { remaining: number },
  context?: RequestContext,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  let cursor: Uint8Array | undefined;
  for (;;) {
    if (budget.remaining <= 0) throw new RingError("RING_RECOVERY_INCOMPLETE");
    budget.remaining--;
    const page = await client.getShieldedTransactionsByNullifiers(
      { nullifiers, ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    transactions.push(...page.transactions);
    const next = nextScanCursor(cursor, page);
    if (next === undefined) return transactions;
    cursor = next;
  }
}

/**
 * Decrypts a ring merge's output from its own transaction: the proof binds the
 * ciphertext of the output's amount and mint, so the owner needs none of the
 * merge's inputs, whichever notes the ring folded in. The cipher is
 * unauthenticated, so the rebuilt output still has to match the commitment.
 */
export async function recoverMerge(
  input: Pick<RingRecoveryParams, "source" | "nullifierKey" | "ringProgramId" | "resolveTreeId">,
  transaction: IndexedShieldedTransaction,
  treeIds: Map<Address, TreeId>,
): Promise<MergeRecoveryCandidate | undefined> {
  const opening = await recoverMergeOpening(
    {
      member: input.source.signingPublicKey.ownerProofInputHash(),
      nullifierKey: input.nullifierKey,
      ringProgramId: input.ringProgramId,
      resolveTreeId: input.resolveTreeId,
    },
    transaction,
    treeIds,
  );
  if (opening === undefined) return undefined;
  const utxo = new Utxo({
    owner: input.source.signingPublicKey,
    asset: opening.asset,
    amount: opening.amount,
    blinding: opening.blinding,
    ringProgramId: input.ringProgramId,
  });
  return {
    utxo,
    outputContext: opening.outputContext,
    nullifier: opening.nullifier,
    ...(opening.ringDataHash === undefined ? {} : { ringDataHash: opening.ringDataHash }),
  };
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

export async function recoverMergeOpening(
  input: Readonly<{
    member: Bytes32;
    nullifierKey: NullifierKey;
    ringProgramId: Address;
    resolveTreeId: (tree: Address) => Promise<TreeId> | TreeId;
  }>,
  transaction: IndexedShieldedTransaction,
  treeIds: Map<Address, TreeId>,
): Promise<MergeAuditorOpening | undefined> {
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
  let treeId = treeIds.get(slot.outputContext.tree);
  if (treeId === undefined) {
    treeId = await input.resolveTreeId(slot.outputContext.tree);
    treeIds.set(slot.outputContext.tree, treeId);
  }
  if (
    !equal(
      ownerUtxoHash({
        owner: poseidon([input.member, input.nullifierKey.publicKey()]),
        asset: plaintext.mint,
        amount: plaintext.amount,
        blinding,
        treeId,
        ringDataHash,
        ringProgramId: input.ringProgramId,
      }),
      slot.outputContext.hash,
    )
  )
    return undefined;
  return {
    member: input.member,
    asset: plaintext.mint,
    amount: plaintext.amount,
    blinding,
    outputContext: slot.outputContext,
    nullifier: input.nullifierKey.nullifier(slot.outputContext.hash, blinding),
    ...(ringDataHash.some((byte) => byte !== 0) ? { ringDataHash } : {}),
  };
}
