import type { Address } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import { MERGE_SUPPORTED_INPUT_COUNTS } from "../interface/constants.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import { readRingDepositCapsule } from "./deposit-capsule.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../keypair/merge/index.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import type { AssetRegistry } from "../transaction/asset.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
} from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import { EncryptedScheme, readOutputData } from "../transaction/serialization/codecs.js";
import { decodeRingDepositOutput } from "../transaction/serialization/ring-deposit.js";
import { Utxo, type TreeId } from "../transaction/utxo.js";
import type { WalletUtxo } from "../transaction/wallet/state.js";
import { bytesKey } from "../wallet/internal.js";
import { auditRing, type AuditedRingOutput, type RingAuditReader } from "./audit.js";
import { RingError } from "./error.js";
import { CachedTransactionOrigin, RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";
import { memberOfTag } from "./policy.js";
import { openRingDepositOpening } from "./deposit-audit.js";

export type RingRecoveryClient = RingAuditReader &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;

/** Reconstructs member notes from auditor disclosure and nullifier material. */
export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: ViewingKey;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  /** The raw id a note's leaf is committed under. */
  readonly resolveTreeId: (tree: Address) => TreeId | Promise<TreeId>;
  /** Both hashes must reproduce the indexed commitment. */
  readonly resolveOutputHashes?: (
    output: AuditedRingOutput,
  ) =>
    | Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }>
    | undefined
    | Promise<Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }> | undefined>;
  readonly origin?: TransactionOrigin;
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
interface Candidate {
  readonly utxo: Utxo;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RecoveredRingNotes> {
  // 1. Bind nullifier material to the requested member before scanning history.
  if (!equal(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const origin = new CachedTransactionOrigin(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
  );
  const sourceMember = memberOfTag(input.source.confidentialViewTag());
  const page = await auditRing(
    {
      client: input.client,
      auditor: input.auditor,
      ringProgramId: input.ringProgramId,
      assets: input.assets,
      origin,
      ...(input.pageSize === undefined ? {} : { pageSize: input.pageSize }),
      ...(input.maxPages === undefined ? {} : { maxPages: input.maxPages }),
    },
    context,
  );
  if (page.nextCursor !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  const treeIds = new Map<Address, TreeId>();
  // 2. Rebuild disclosed openings and retain unresolved commitments explicitly.
  const deposits = await recoverDeposits(input, origin, treeIds, context);
  const unsupportedDeposits = deposits.unsupported;
  const candidates: Candidate[] = deposits.candidates;
  const unopened: Bytes32[] = [];
  const unopenedNullifiers = new Map<string, Bytes32>();
  const seen = new Set(candidates.map((candidate) => bytesKey(candidate.outputContext.hash)));
  for (const transaction of page.transactions) {
    for (const output of transaction.outputs) {
      if (
        output.ringProgramId !== input.ringProgramId ||
        !output.recipientViewingPublicKey.equals(input.source.viewingPublicKey) ||
        !equal(memberOfTag(output.ownerTag), sourceMember)
      )
        continue;
      const { outputContext } = output;
      const opening = transaction.outputOpenings[output.slotIndex];
      if (opening === undefined) {
        unopened.push(outputContext.hash);
        continue;
      }
      const key = bytesKey(outputContext.hash);
      if (seen.has(key)) continue;
      seen.add(key);
      let treeId = treeIds.get(outputContext.tree);
      if (treeId === undefined) {
        treeId = await input.resolveTreeId(outputContext.tree);
        treeIds.set(outputContext.tree, treeId);
      }
      const utxo = new Utxo({
        owner: input.source.signingPublicKey,
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        data: output.data,
        ...(output.ringProgramId === undefined ? {} : { ringProgramId: output.ringProgramId }),
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
        unopenedNullifiers.set(
          bytesKey(outputContext.hash),
          utxo.nullifier(outputContext.hash, input.nullifierKey),
        );
        continue;
      }
      candidates.push({
        utxo,
        outputContext,
        nullifier: utxo.nullifier(outputContext.hash, input.nullifierKey),
        ...(hashes?.dataHash === undefined
          ? {}
          : { dataHash: new Uint8Array(hashes.dataHash) as Bytes32 }),
        ...(hashes?.ringDataHash === undefined
          ? {}
          : { ringDataHash: new Uint8Array(hashes.ringDataHash) as Bytes32 }),
      });
    }
  }
  const spent = new Set<string>();
  const byNullifier = new Map(
    candidates.map((candidate) => [bytesKey(candidate.nullifier), candidate]),
  );
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
    for (const transaction of await spendingTransactions(input.client, batch, budget, context)) {
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
      if (
        !seen.has(hash) &&
        transaction.eventIndex !== undefined &&
        (await origin.ringInvoked(
          transaction.txSignature,
          transaction.eventIndex,
          input.ringProgramId,
          context,
        ))
      )
        pending.set(hash, transaction);
    }
    let progressed = true;
    while (progressed) {
      progressed = false;
      for (const [hash, transaction] of pending) {
        const candidate = await recoverMerge(input, transaction, byNullifier, treeIds);
        if (candidate === undefined) continue;
        seen.add(hash);
        candidates.push(candidate);
        queries.push(candidate.nullifier);
        byNullifier.set(bytesKey(candidate.nullifier), candidate);
        pending.delete(hash);
        progressed = true;
      }
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
  treeIds: Map<Address, TreeId>,
  context?: RequestContext,
): Promise<{ unsupported: Bytes32[]; candidates: Candidate[] }> {
  const tag = input.source.viewingPublicKey.x();
  const found = new Map<string, Bytes32>();
  const candidates = new Map<string, Candidate>();
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
    for (const transaction of response.transactions) {
      if (!transaction.proofless) continue;
      for (const slot of transaction.outputSlots) {
        let deposit;
        try {
          const frame = readOutputData(slot.payload);
          if (frame.scheme !== EncryptedScheme.ringDeposit || frame.encoding !== "encrypted")
            continue;
          deposit = decodeRingDepositOutput(frame.body);
        } catch {
          continue;
        }
        if (
          deposit.ringProgramId !== input.ringProgramId ||
          transaction.eventIndex === undefined ||
          !(await origin.ringInvoked(
            transaction.txSignature,
            transaction.eventIndex,
            input.ringProgramId,
            context,
          ))
        )
          continue;
        let opening;
        try {
          const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
          if (capsule !== undefined)
            opening = openRingDepositOpening(capsule, input.auditor, deposit.ownerUtxoHash);
        } catch {
          opening = undefined;
        }
        if (opening === undefined) {
          if (equal(slot.viewTag, tag))
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
    if (response.scannedThrough !== undefined || response.nextCursor === undefined)
      return { unsupported: [...found.values()], candidates: [...candidates.values()] };
    if (cursor !== undefined && equal(cursor, response.nextCursor))
      throw new RingError("RING_RPC", {
        details: { reason: "deposit scan cursor did not advance" },
      });
    cursor = response.nextCursor;
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
    if (page.scannedThrough !== undefined || page.nextCursor === undefined) return transactions;
    if (cursor !== undefined && equal(cursor, page.nextCursor))
      throw new RingError("RING_RPC", {
        details: { reason: "nullifier scan cursor did not advance" },
      });
    cursor = page.nextCursor;
  }
}

async function recoverMerge(
  input: RingRecoveryParams,
  transaction: IndexedShieldedTransaction,
  known: ReadonlyMap<string, Candidate>,
  treeIds: Map<Address, TreeId>,
): Promise<Candidate | undefined> {
  const firstNullifier = transaction.nullifiers[0];
  const slot = transaction.outputSlots[0];
  if (
    firstNullifier === undefined ||
    slot === undefined ||
    !MERGE_SUPPORTED_INPUT_COUNTS.includes(transaction.nullifiers.length) ||
    slot.payload.length !== 32
  )
    return undefined;
  const first = known.get(bytesKey(firstNullifier));
  if (first === undefined || first.utxo.ringProgramId !== input.ringProgramId) return undefined;
  const real = new Set<string>();
  let padded = false;
  let amount = 0n;
  for (const [index, nullifier] of transaction.nullifiers.entries()) {
    if (equal(nullifier, mergeDummyNullifier(input.nullifierKey, firstNullifier, index))) {
      padded = true;
      continue;
    }
    const key = bytesKey(nullifier);
    const predecessor = known.get(key);
    if (
      padded ||
      real.has(key) ||
      predecessor === undefined ||
      predecessor.utxo.asset !== first.utxo.asset ||
      predecessor.utxo.ringProgramId !== input.ringProgramId ||
      predecessor.utxo.data.utxoData() !== undefined ||
      predecessor.dataHash?.some((byte) => byte !== 0)
    )
      return undefined;
    real.add(key);
    amount += predecessor.utxo.amount;
    if (amount > U64_MAX) return undefined;
  }
  const ringDataHash = new Uint8Array(slot.payload) as Bytes32;
  const utxo = new Utxo({
    owner: input.source.signingPublicKey,
    asset: first.utxo.asset,
    amount,
    blinding: mergeOutputBlinding(input.nullifierKey, firstNullifier),
    ringProgramId: input.ringProgramId,
  });
  let treeId = treeIds.get(slot.outputContext.tree);
  if (treeId === undefined) {
    treeId = await input.resolveTreeId(slot.outputContext.tree);
    treeIds.set(slot.outputContext.tree, treeId);
  }
  if (
    !equal(
      utxo.hash(input.source.nullifierPublicKey, treeId, undefined, ringDataHash),
      slot.outputContext.hash,
    )
  )
    return undefined;
  return {
    utxo,
    outputContext: slot.outputContext,
    nullifier: utxo.nullifier(slot.outputContext.hash, input.nullifierKey),
    ...(ringDataHash.some((byte) => byte !== 0) ? { ringDataHash } : {}),
  };
}
