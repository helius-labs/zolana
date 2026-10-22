import type { Address } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import { solanaOwnerIdentity } from "../hasher/index.js";
import { mergePaddedInputCount } from "../interface/constants.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import { ownerHash } from "../keypair/hash.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { X25519Keypair } from "../keypair/x25519.js";
import type { AssetRegistry } from "../transaction/asset.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
} from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import { Utxo } from "../transaction/utxo.js";
import type { WalletUtxo } from "../transaction/wallet/state.js";
import { bytesKey } from "../wallet/internal.js";

import { auditRing, nextScanCursor, type KnownUtxo, type RingAuditReader } from "./audit.js";
import { recoverMergeOpening } from "./audit-merge.js";
import { createdDepositUtxo, createdRingUtxos } from "./created.js";
import { openRingDepositOpening, ringDepositOutput } from "./deposit-audit.js";
import { readRingDepositCapsule } from "./deposit-capsule.js";
import { RingError } from "./error.js";
import { readRingHistory, scanLimits, type ScanLimits } from "./history.js";
import { RpcTransactionOrigin, type ConfirmedDeposit, type TransactionOrigin } from "./origin.js";

export type RingRecoveryClient = RingAuditReader &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;

/** Mirrors Rust `MemberRecovery`, a source member's notes from the auditor's view and its nullifier key. */
export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: X25519Keypair;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  readonly origin?: TransactionOrigin;
  readonly pageSize?: number;
  /** Bounds each history scan and all spentness queries together. */
  readonly maxPages?: number;
}

/** Mirrors Rust `RecoveredNotes`, verified unspent notes with the coverage left unresolved. */
export interface RecoveredRingNotes {
  readonly notes: readonly WalletUtxo[];
  /** Commitments that cannot yet become spendable notes, unknown mints among them. */
  readonly unopened: readonly Bytes32[];
  /** Tagged deposits whose ownership and spentness are unknown. */
  readonly unsupportedDeposits: readonly Bytes32[];
  /** Verified mints missing from the asset registry, their notes stay in `unopened`. */
  readonly unknownMints: readonly Address[];
}

export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RecoveredRingNotes> {
  if (!equal(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const history: RecoveryHistory = {
    origin: input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    limits: scanLimits({
      pageSize: input.pageSize ?? Number(PAGE_LIMIT),
      maxPages: input.maxPages,
    }),
  };
  const found = new Found();
  // Deposits are found by ring, never by their recipient view tags.
  const unsupportedDeposits = await recoverDeposits(input, history, found, context);
  const sourceKey = input.source.confidentialViewTag();
  const page = await auditRing(
    {
      client: input.client,
      auditor: input.auditor,
      ringProgramId: input.ringProgramId,
      assets: input.assets,
      origin: history.origin,
      knownUtxos: { utxo: (commitment) => found.created.get(bytesKey(commitment)) },
      escrowedKeys: {
        nullifierPk: (ownerKey) =>
          equal(ownerKey, sourceKey) ? input.source.nullifierPublicKey : undefined,
      },
      ...(input.pageSize === undefined ? {} : { pageSize: input.pageSize }),
      ...(input.maxPages === undefined ? {} : { maxPages: input.maxPages }),
    },
    context,
  );
  if (page.nextCursor !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  const sourceOwner = input.source.ownerHash();
  for (const transaction of page.transactions) {
    // Any unopened slot but another owner's escrow miss could hide a source UTXO.
    const error = transaction.payloadErrors.find(({ kind }) => kind !== "escrowUnknown");
    if (error !== undefined)
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
        details: { reason: "unopened", slotIndex: error.slotIndex },
      });
    for (const output of transaction.outputs) {
      if (output.opening.kind !== "ring") continue;
      const { utxo } = output.opening;
      const context = output.outputContext;
      if (
        !equal(ownerHash(solanaOwnerIdentity(utxo.ownerKey), utxo.nullifierPk), sourceOwner) ||
        !found.claim(context.hash)
      )
        continue;
      const mint = registeredMint(input.assets, utxo.mint);
      if (mint === undefined) {
        // Ownership and spentness stay known without the asset preimage.
        if (utxo.mint !== undefined) found.unknownMints.add(utxo.mint);
        found.unresolve(context.hash, input.nullifierKey.nullifier(context.hash, utxo.blinding));
        continue;
      }
      const opened = sourceWalletUtxo(input, {
        utxo: new Utxo({
          owner: input.source.signingPublicKey,
          asset: mint,
          amount: utxo.amount,
          blinding: utxo.blinding,
          ringProgramId: input.ringProgramId,
        }),
        outputContext: context,
        hashes: { dataHash: utxo.dataHash, ringDataHash: utxo.ringDataHash },
      });
      if (opened.opens) found.candidates.push(opened.utxo);
      else found.unresolve(context.hash, opened.utxo.nullifier);
    }
  }
  const spent = await followSpends(input, history, found, context);
  return Object.freeze({
    notes: Object.freeze(found.candidates.filter((note) => !spent.has(bytesKey(note.nullifier)))),
    unopened: Object.freeze(
      found.unresolved
        .filter(({ nullifier }) => nullifier === undefined || !spent.has(bytesKey(nullifier)))
        .map(({ commitment }) => commitment),
    ),
    unsupportedDeposits: Object.freeze(unsupportedDeposits),
    unknownMints: Object.freeze([...found.unknownMints]),
  });
}

interface RecoveryHistory {
  readonly origin: TransactionOrigin;
  readonly limits: ScanLimits;
}

/** Notes found so far, by the commitments already claimed. */
class Found {
  readonly candidates: WalletUtxo[] = [];
  /** Commitments without a verified opening, with their nullifier when the key derives one. */
  readonly unresolved: { readonly commitment: Bytes32; readonly nullifier?: Bytes32 }[] = [];
  readonly unknownMints = new Set<Address>();
  /** Every deposit and merge UTXO of an anonymous ring, its transfers spend them by hash. */
  readonly created = new Map<string, KnownUtxo>();
  readonly #seen = new Set<string>();

  /** `false` when the commitment was already claimed. */
  claim(commitment: Bytes32): boolean {
    const key = bytesKey(commitment);
    if (this.#seen.has(key)) return false;
    this.#seen.add(key);
    return true;
  }

  seen(commitment: Bytes32): boolean {
    return this.#seen.has(bytesKey(commitment));
  }

  unresolve(commitment: Bytes32, nullifier?: Bytes32): void {
    this.unresolved.push(
      Object.freeze({ commitment, ...(nullifier === undefined ? {} : { nullifier }) }),
    );
  }
}

/** Rust `SourceMember::wallet_utxo`, the UTXO at `outputContext` and whether it reproduces the leaf. */
function sourceWalletUtxo(
  input: Pick<RingRecoveryParams, "source" | "nullifierKey">,
  candidate: Readonly<{
    utxo: Utxo;
    outputContext: OutputContext;
    hashes: Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }>;
  }>,
): Readonly<{ utxo: WalletUtxo; opens: boolean }> {
  const { utxo, outputContext } = candidate;
  const dataHash = nonZero(candidate.hashes.dataHash);
  const ringDataHash = nonZero(candidate.hashes.ringDataHash);
  const walletUtxo: WalletUtxo = Object.freeze({
    utxo,
    outputContext,
    nullifier: utxo.nullifier(outputContext.hash, input.nullifierKey),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    spent: false,
  });
  const commitment = utxo.hash(
    input.source.nullifierPublicKey,
    outputContext.treeId,
    dataHash,
    ringDataHash,
  );
  return Object.freeze({ utxo: walletUtxo, opens: equal(commitment, outputContext.hash) });
}

/** Mirrors Rust `ring_history`, `deposited_utxos` and `CreatedUtxos::open` in one read. */
async function recoverDeposits(
  input: RingRecoveryParams,
  history: RecoveryHistory,
  found: Found,
  context: RequestContext | undefined,
): Promise<Bytes32[]> {
  const sourceOwner = input.source.ownerHash();
  const processed = new Set<string>();
  const unsupported: Bytes32[] = [];
  const stopped = await readRingHistory(
    { client: input.client, ringProgramId: input.ringProgramId, ...history },
    (confirmed) => {
      if (confirmed.kind === "merge") {
        for (const { commitment, utxo } of createdRingUtxos({
          confirmed,
          ringProgramId: input.ringProgramId,
          auditor: input.auditor,
        }))
          found.created.set(bytesKey(commitment), utxo);
        return;
      }
      if (confirmed.kind !== "deposit") return;
      for (const [slotIndex, slot] of confirmed.transaction.outputSlots.entries()) {
        const deposit = ringDepositOutput(slot.payload, input.ringProgramId);
        const commitment = slot.outputContext.hash;
        const key = bytesKey(commitment);
        if (deposit === undefined || processed.has(key) || found.seen(commitment)) continue;
        processed.add(key);
        const binding = confirmed.deposits.find(
          (candidate: ConfirmedDeposit) => candidate.slotIndex === slotIndex,
        );
        const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
        if (binding === undefined || capsule === undefined) {
          unsupported.push(commitment);
          continue;
        }
        let opening;
        try {
          opening = openRingDepositOpening(capsule, input.auditor, deposit.ownerUtxoHash, binding);
        } catch {
          unsupported.push(commitment);
          continue;
        }
        try {
          const created = createdDepositUtxo({
            ringProgramId: input.ringProgramId,
            slotIndex,
            slot,
            output: deposit,
            opening,
          });
          if (created !== undefined) found.created.set(key, created.utxo);
          if (!equal(opening.ownerHash, sourceOwner)) continue;
          // The deposit proof binds the raw mint, its commitment opens without the registry.
          const opened = sourceWalletUtxo(input, {
            utxo: new Utxo({
              owner: input.source.signingPublicKey,
              asset: deposit.asset,
              amount: deposit.amount,
              blinding: opening.blinding,
              ringProgramId: input.ringProgramId,
            }),
            outputContext: slot.outputContext,
            hashes: {
              ...(deposit.dataHash === undefined ? {} : { dataHash: deposit.dataHash }),
              ringDataHash: deposit.ringDataHash,
            },
          });
          if (!opened.opens)
            throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
          found.claim(commitment);
          if (registeredMint(input.assets, deposit.asset) !== undefined)
            found.candidates.push(opened.utxo);
          else {
            found.unknownMints.add(deposit.asset);
            found.unresolve(commitment, opened.utxo.nullifier);
          }
        } finally {
          opening.ownerHash.fill(0);
          opening.blinding.fill(0);
        }
      }
    },
    context,
  );
  if (stopped !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  return unsupported;
}

/** Mirrors Rust `follow_spends`, spent nullifiers and the merges that spent the source's notes. */
async function followSpends(
  input: RingRecoveryParams,
  { origin, limits }: RecoveryHistory,
  found: Found,
  context: RequestContext | undefined,
): Promise<Set<string>> {
  const spent = new Set<string>();
  const merges = new Map<string, IndexedShieldedTransaction>();
  const budget = { remaining: limits.maxPages };
  let queries = [
    ...found.candidates.map((candidate) => candidate.nullifier),
    ...found.unresolved.flatMap(({ nullifier }) => (nullifier === undefined ? [] : [nullifier])),
  ];
  for (;;) {
    const requested = new Set(queries.map(bytesKey));
    for (const indexed of await spendingTransactions(input.client, queries, budget, context)) {
      if (indexed.eventIndex === undefined)
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      const confirmed = await origin.confirmedTransaction(indexed, input.ringProgramId, context);
      if (confirmed === undefined) continue;
      const { transaction } = confirmed;
      if (!transaction.nullifiers.some((nullifier) => requested.has(bytesKey(nullifier)))) continue;
      for (const nullifier of transaction.nullifiers) spent.add(bytesKey(nullifier));
      const output = transaction.outputSlots[0];
      if (
        confirmed.kind !== "merge" ||
        output === undefined ||
        transaction.outputSlots.length !== 1 ||
        mergePaddedInputCount(transaction.nullifiers.length) === undefined
      )
        continue;
      merges.set(bytesKey(output.outputContext.hash), transaction);
    }
    const before = found.candidates.length;
    const unresolvedBefore = found.unresolved.length;
    for (const transaction of merges.values()) {
      const commitment = transaction.outputSlots[0]!.outputContext.hash;
      if (found.seen(commitment)) continue;
      const opening = recoverMergeOpening(
        {
          member: input.source.signingPublicKey.ownerProofInputHash(),
          nullifierKey: input.nullifierKey,
          ringProgramId: input.ringProgramId,
        },
        transaction,
      );
      if (opening === undefined) continue;
      found.claim(commitment);
      if (registeredMint(input.assets, opening.asset) === undefined) {
        found.unknownMints.add(opening.asset);
        found.unresolve(commitment, opening.nullifier);
        continue;
      }
      found.candidates.push(
        Object.freeze({
          utxo: new Utxo({
            owner: input.source.signingPublicKey,
            asset: opening.asset,
            amount: opening.amount,
            blinding: opening.blinding,
            ringProgramId: input.ringProgramId,
          }),
          outputContext: opening.outputContext,
          nullifier: opening.nullifier,
          ...(opening.ringDataHash === undefined ? {} : { ringDataHash: opening.ringDataHash }),
          spent: false,
        }),
      );
    }
    if (found.candidates.length === before && found.unresolved.length === unresolvedBefore) {
      for (const transaction of merges.values()) {
        const commitment = transaction.outputSlots[0]!.outputContext.hash;
        if (!found.seen(commitment)) found.unresolve(commitment);
      }
      return spent;
    }
    queries = [
      ...found.candidates.slice(before).map((candidate) => candidate.nullifier),
      ...found.unresolved
        .slice(unresolvedBefore)
        .flatMap(({ nullifier }) => (nullifier === undefined ? [] : [nullifier])),
    ];
  }
}

/** Every transaction spending one of `nullifiers`, `budget` bounds the queries. */
async function spendingTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">,
  nullifiers: readonly Bytes32[],
  budget: { remaining: number },
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  for (let start = 0; start < nullifiers.length; start += Number(PAGE_LIMIT)) {
    const batch = nullifiers.slice(start, start + Number(PAGE_LIMIT));
    let cursor: Uint8Array | undefined;
    for (;;) {
      if (budget.remaining <= 0) throw new RingError("RING_RECOVERY_INCOMPLETE");
      budget.remaining--;
      const page = await client.getShieldedTransactionsByNullifiers(
        { nullifiers: batch, ...(cursor === undefined ? {} : { cursor }) },
        undefined,
        context,
      );
      transactions.push(...page.transactions);
      const next = nextScanCursor(cursor, page);
      if (next === undefined) break;
      cursor = next;
    }
  }
  return transactions;
}

/** The mint the registry knows, `undefined` for an absent or unregistered one. */
function registeredMint(assets: AssetRegistry, mint: Address | undefined): Address | undefined {
  if (mint === undefined) return undefined;
  try {
    assets.assetId(mint);
    return mint;
  } catch {
    return undefined;
  }
}

function nonZero(hash: Bytes32 | undefined): Bytes32 | undefined {
  return hash === undefined || hash.every((byte) => byte === 0) ? undefined : hash;
}
