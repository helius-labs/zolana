import type { DepositPayloadDecoder } from "../transaction/serialization/ring-deposit.js";
import {
  getAddressEncoder,
  getBase64Decoder,
  getBase64Encoder,
  type Base64EncodedBytes,
} from "@solana/kit";

import { runKitRpc } from "../client/kit.js";
import { initializePoseidon } from "../hasher/index.js";
import type { IndexerReader, KitRpcAccess } from "../client/ports.js";
import { ClientError } from "../client/error.js";
import {
  DEFAULT_INDEXER_POLL_CONFIG,
  type IndexerPollConfig,
  type IndexerRpcConfig,
} from "../client/retry.js";
import { decodeSplAssetRegistry } from "../interface/accounts.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import { StateDiscriminator } from "../interface/state.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { TransactionError } from "../transaction/error.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import {
  checkKeysIdentity,
  checkViewingPublicKeys,
  type RingKeys,
  type ShieldedKeys,
} from "../transaction/wallet/keys.js";
import type {
  AnonymousRingReport,
  RingDeliveredCandidate,
} from "../transaction/wallet/anonymous.js";
import { AnonymousRingState } from "../transaction/wallet/anonymous-state.js";
import {
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "../transaction/wallet/state.js";
import { decryptTransactions, resolvePendingNotes } from "../transaction/wallet/sync.js";

import { scanAnonymousRing } from "./anonymous-sync.js";
import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey } from "./internal.js";
import {
  collectProoflessDeposits,
  collectShieldedTransactions,
  collectShieldedTransactionsByNullifiers,
  shieldedTransactionKey,
} from "./collect.js";
import {
  advanceSessionCursors,
  beginSyncSession,
  ensureSessionAsset,
  sealSyncDelta,
  sessionCursor,
  type WalletSyncSession,
} from "./sync-session.js";

const addressEncoder = getAddressEncoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();

/** Kit access is required only when the wallet holds a mint the registry cannot resolve. */
export interface SyncClient extends Pick<
  IndexerReader,
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
  | "getShieldedTransactionsByTags"
> {
  readonly solanaRpc?: KitRpcAccess["solanaRpc"];
  readonly commitment?: KitRpcAccess["commitment"];
  /** The client's own indexer config, the fallback for an unset `requireSlot` and `retry`. */
  readonly indexerConfig?: IndexerRpcConfig;
}

export interface SyncWalletConfig {
  readonly depositPayloadDecoder?: DepositPayloadDecoder;
  /** Stable tags and nullifiers per indexer request. Defaults to 64. */
  readonly queryChunk?: number;
  /** Rows requested per indexer page. Defaults to Photon's maximum, 1000. */
  readonly pageLimit?: number;
  /**
   * Slot the indexer must have persisted before its answers are used. Unset
   * applies the client's configured `indexerConfig.requireSlot`, if any.
   */
  readonly requireSlot?: bigint;
  /** Unset applies the client's configured `indexerConfig.poll`. */
  readonly retry?: IndexerPollConfig;
}

export interface SplAssetRegistration {
  readonly assetId: bigint;
  readonly mint: Address;
}

/** Every on-chain SPL asset registration, an unsupported or partial scan fails, never reads as empty. */
export async function fetchSplAssetRegistrations(
  registryRpc: KitRpcAccess,
  context?: RequestContext,
): Promise<readonly SplAssetRegistration[]> {
  const accounts = await runKitRpc("getProgramAccounts", context, (abortSignal) =>
    registryRpc.solanaRpc
      .getProgramAccounts(SHIELDED_POOL_PROGRAM_ID, {
        commitment: registryRpc.commitment,
        encoding: "base64",
        filters: [
          { dataSize: 48n },
          {
            memcmp: {
              offset: 0n,
              encoding: "base64",
              bytes: base64Decoder.decode(
                Uint8Array.of(StateDiscriminator.splAssetRegistry),
              ) as Base64EncodedBytes,
            },
          },
        ],
      })
      .send({ abortSignal }),
  );

  // The filters matched only asset registries, an account that fails to
  // decode means the RPC did not honour the query and the whole listing is
  // suspect.
  const registrations: SplAssetRegistration[] = [];
  for (const [index, { account }] of accounts.entries()) {
    const invalid = (cause?: unknown) =>
      new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: { method: "getProgramAccounts", path: `$.result[${String(index)}]` },
        ...(cause === undefined ? {} : { cause }),
      });
    if (account.owner !== SHIELDED_POOL_PROGRAM_ID) throw invalid();
    try {
      const registry = decodeSplAssetRegistry(
        new Uint8Array(base64Encoder.encode(account.data[0])),
      );
      registrations.push({ assetId: registry.assetId, mint: registry.mint });
    } catch (cause) {
      throw invalid(cause);
    }
  }
  return Object.freeze(registrations);
}

export async function backfillAssetRegistry(
  wallet: Wallet,
  registryRpc: KitRpcAccess,
  context?: RequestContext,
): Promise<number> {
  let inserted = 0;
  for (const { assetId, mint } of await fetchSplAssetRegistrations(registryRpc, context)) {
    if (wallet.ensureAsset(assetId, mint)) inserted++;
  }
  return inserted;
}

function positiveInteger(value: number, field: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", { details: { field, value } });
  }
  return value;
}

/**
 * The stable tags a wallet asks the indexer about: one shielded-identity
 * signing tag for confidential transactions and one bootstrap tag per held
 * viewing key for deposits and key rotation. The bootstrap tag is the key's
 * u-coordinate, so the public keys are enough to derive it.
 *
 * Keys that do not belong to this wallet are refused here rather than by the
 * decrypt pass further down, because a tag is a query the indexer sees: a
 * wallet handed the wrong keys must not publish any of them before the
 * mismatch is noticed.
 */
function walletQueryTags(wallet: Wallet, keys: ShieldedKeys): readonly Bytes32[] {
  checkKeysIdentity(keys, wallet.identity);
  const held = checkViewingPublicKeys(keys, wallet.identity);
  const tags = new Map<string, Bytes32>();
  const add = (tag: Bytes32): void => {
    tags.set(bytesKey(tag), tag);
  };
  add(wallet.identity.signingPublicKey.confidentialViewTag());
  for (const key of held) add(key.x());
  return [...tags.values()];
}

/**
 * Nullifiers of unspent UTXOs.
 *
 * A nullifier appears at most once on chain, so once its spend is known the
 * answer is final. Cost tracks the unspent count, not history.
 */
function walletQueryNullifiers(wallet: Wallet): readonly Bytes32[] {
  const nullifiers = new Map<string, Bytes32>();
  for (const entry of wallet.utxos()) {
    if (entry.spent) continue;
    nullifiers.set(bytesKey(entry.nullifier), entry.nullifier);
  }
  return [...nullifiers.values()];
}

/** An output under an unknown id or field is not stored, a commit would skip it until a rescan. */
function unknownAssets(report: SyncReport): boolean {
  return report.unknownAssetIds.length > 0 || report.unknownAssetFields.length > 0;
}

/** A pending note stays durable, only a client that reads the chain backfills its mint. */
function needsRegistry(
  input: Readonly<{ report: SyncReport; wallet: Wallet; client: SyncClient }>,
): boolean {
  const { report, wallet, client } = input;
  return (
    unknownAssets(report) ||
    walletHasUnknownMint(wallet) ||
    (wallet.pendingNotes().length > 0 && readsChain(client))
  );
}

function readsChain(client: SyncClient): boolean {
  return client.solanaRpc !== undefined && client.commitment !== undefined;
}

function walletHasUnknownMint(wallet: Wallet): boolean {
  const registry = wallet.registry;
  for (const entry of wallet.utxos()) {
    try {
      registry.assetId(entry.utxo.asset);
    } catch (error) {
      if (error instanceof TransactionError && error.code === "TRANSACTION_UNKNOWN_MINT") {
        return true;
      }
      throw error;
    }
  }
  return false;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareAddresses(left: Address, right: Address): number {
  const leftBytes = addressEncoder.encode(left);
  const rightBytes = addressEncoder.encode(right);
  for (let index = 0; index < leftBytes.length; index++) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function compareBySlotThenSignature(
  left: IndexedShieldedTransaction,
  right: IndexedShieldedTransaction,
): number {
  if (left.slot !== right.slot) return left.slot < right.slot ? -1 : 1;
  return (
    compareStrings(left.txSignature, right.txSignature) ||
    compareStrings(shieldedTransactionKey(left), shieldedTransactionKey(right))
  );
}

/**
 * Deposits are ordered by their leaf position first so that replaying a sync
 * inserts them in tree order regardless of which page surfaced them.
 *
 * Rust sorts an `Option`, where `None` comes first, and compares the tree as an
 * address, which orders by its 32 bytes. Base58 and byte order disagree once the
 * encodings differ in length, so a slot with no output must sort first and the
 * tree must be compared decoded.
 */
function compareDeposits(
  left: IndexedShieldedTransaction,
  right: IndexedShieldedTransaction,
): number {
  const leftSlot = left.outputSlots[0]?.outputContext;
  const rightSlot = right.outputSlots[0]?.outputContext;
  if (leftSlot === undefined || rightSlot === undefined) {
    return Number(leftSlot !== undefined) - Number(rightSlot !== undefined);
  }
  const tree = compareAddresses(leftSlot.tree, rightSlot.tree);
  if (tree !== 0) return tree;
  if (leftSlot.leafIndex !== rightSlot.leafIndex) {
    return leftSlot.leafIndex < rightSlot.leafIndex ? -1 : 1;
  }
  return compareBySlotThenSignature(left, right);
}

/**
 * Buckets keys by the position their stream was last read to.
 *
 * A chunk carries one cursor, so keys at different positions cannot share a
 * request. `undefined` (never queried) is its own group.
 */
function groupByResumePoint(
  keys: readonly Bytes32[],
  cursorFor: (key: Bytes32) => Uint8Array | undefined,
): readonly { readonly from: Uint8Array | undefined; readonly keys: Bytes32[] }[] {
  const groups = new Map<string, { from: Uint8Array | undefined; keys: Bytes32[] }>();
  for (const key of keys) {
    const from = cursorFor(key);
    const groupKey = from === undefined ? "" : bytesKey(from);
    const group = groups.get(groupKey);
    if (group === undefined) groups.set(groupKey, { from, keys: [key] });
    else group.keys.push(key);
  }
  return [...groups.values()];
}

/** The anonymous rings one sync reads, a ring the wallet never scanned starts at its creation epoch. */
export interface AnonymousRingSyncInput {
  /** The chain slot every stream is read through, its epoch is read again next time. */
  readonly slot: bigint;
  /** Rings the wallet starts tracking at their config's `creationEpoch`, every tracked ring is read too. */
  readonly start?: readonly Readonly<{ ring: Address; creationEpoch: bigint }>[];
}

export type SyncWalletInput = Readonly<{
  wallet: Wallet;
  client: SyncClient;
  config?: SyncWalletConfig;
}> &
  (
    | Readonly<{ keys: ShieldedKeys; anonymousRings?: undefined }>
    | Readonly<{ keys: RingKeys; anonymousRings: AnonymousRingSyncInput }>
  );

export async function syncWallet(
  input: SyncWalletInput,
  context?: RequestContext,
): Promise<SyncReport> {
  return runLockedWalletSync(input, context, (report) => report);
}

/**
 * `after` runs inside the wallet's sync queue, once the commit landed and the
 * key session closed, no later sync starts before it settles.
 * @internal
 */
export async function runLockedWalletSync<T>(
  input: SyncWalletInput,
  context: RequestContext | undefined,
  after: (report: SyncReport) => T | Promise<T>,
): Promise<T> {
  await initializePoseidon();
  // Writes stage in a session and commit once, a failed sync changes nothing.
  return input.wallet._withSyncLock(async () => after(await runWalletSync(input, context)));
}

async function runWalletSync(
  input: SyncWalletInput,
  context?: RequestContext,
): Promise<SyncReport> {
  const { keys } = input;
  try {
    const chunkSize = positiveInteger(input.config?.queryChunk ?? 64, "queryChunk");
    const pageLimit = positiveInteger(input.config?.pageLimit ?? 1_000, "pageLimit", 1_000);
    const clientConfig = input.client.indexerConfig;
    const poll = input.config?.retry ?? clientConfig?.poll ?? DEFAULT_INDEXER_POLL_CONFIG;
    const decryptConfig = {
      syncedAt: BigInt(Math.floor(Date.now() / 1_000)),
      ...(input.config?.depositPayloadDecoder === undefined
        ? {}
        : { depositPayloadDecoder: input.config.depositPayloadDecoder }),
    };
    const validatedPoll = Object.freeze({ ...poll, numRetries: Math.max(poll.numRetries, 1) });
    const ungated: IndexerRpcConfig = Object.freeze({ poll: validatedPoll });
    const requireSlot = input.config?.requireSlot ?? clientConfig?.requireSlot;
    // Freshness is established ONCE per sync, on the first indexer request, not on
    // every request. Applying it per request meant paying the wait per tag chunk,
    // per collector, per page.
    let pendingGate: IndexerRpcConfig | undefined =
      requireSlot === undefined ? undefined : Object.freeze({ poll: validatedPoll, requireSlot });
    const nextRpcConfig = (): IndexerRpcConfig => {
      if (pendingGate === undefined) return ungated;
      const gate = pendingGate;
      pendingGate = undefined;
      return gate;
    };
    const session = beginSyncSession(input.wallet);
    const transactions = new Map<string, IndexedShieldedTransaction>();
    const deposits = new Map<string, IndexedShieldedTransaction>();
    const tags = walletQueryTags(session.staging, keys);
    // Tags are grouped by where each was last read to, because a chunk can only
    // carry one cursor. Mixing a tag at the tip with one learned this sync would
    // resume the new tag from the old one's position and skip its history
    // permanently -- which is why the watermarks are per tag, not per wallet.
    // `undefined` (never queried) is its own group.
    for (const stream of ["transactions", "proofless"] as const) {
      const groups = groupByResumePoint(tags, (tag) =>
        sessionCursor(session, stream, bytesKey(tag)),
      );

      for (const group of groups) {
        for (let offset = 0; offset < group.keys.length; offset += chunkSize) {
          const chunk = group.keys.slice(offset, offset + chunkSize);
          const collect =
            stream === "transactions" ? collectShieldedTransactions : collectProoflessDeposits;
          const furthest = await collect(
            {
              indexer: input.client,
              chunk,
              pageLimit,
              nextRpcConfig,
              out: stream === "transactions" ? transactions : deposits,
              from: group.from,
            },
            context,
          );
          if (furthest !== undefined) {
            advanceSessionCursors(session, stream, chunk, furthest);
          }
        }
      }
    }

    const scanNullifiers = async (nullifiers: readonly Bytes32[]): Promise<void> => {
      const groups = groupByResumePoint(nullifiers, (nullifier) =>
        sessionCursor(session, "nullifiers", bytesKey(nullifier)),
      );

      for (const group of groups) {
        for (let offset = 0; offset < group.keys.length; offset += chunkSize) {
          const chunk = group.keys.slice(offset, offset + chunkSize);
          const furthest = await collectShieldedTransactionsByNullifiers(
            {
              indexer: input.client,
              chunk,
              pageLimit,
              nextRpcConfig,
              out: transactions,
              ...(group.from === undefined ? {} : { start: group.from }),
            },
            context,
          );
          if (furthest !== undefined) {
            advanceSessionCursors(session, "nullifiers", chunk, furthest);
          }
        }
      }
    };

    const queriedNullifiers = new Set<string>();
    const initialNullifiers = walletQueryNullifiers(session.staging);
    for (const nullifier of initialNullifiers) queriedNullifiers.add(bytesKey(nullifier));
    await scanNullifiers(initialNullifiers);

    const orderedTransactions = (): readonly IndexedShieldedTransaction[] => [
      ...[...transactions.values()].sort(compareBySlotThenSignature),
      ...[...deposits.values()].sort(compareDeposits),
    ];
    let ordered = orderedTransactions();
    let report = await decryptTransactions({
      wallet: session.staging,
      keys,
      transactions: ordered,
      config: decryptConfig,
      context,
    });
    let registryRefreshed = false;
    if (needsRegistry({ report, wallet: session.staging, client: input.client })) {
      registryRefreshed = true;
      if ((await backfillSessionRegistry(session, input.client, context)) > 0) {
        report = await decryptTransactions({
          wallet: session.staging,
          keys,
          transactions: ordered,
          config: decryptConfig,
          context,
        });
      }
    }
    // An admitted note joins the follow-up nullifier scan of the same sync.
    await resolvePendingNotes({ wallet: session.staging, keys, context });

    // A transaction found by a stable tag can create a UTXO that another
    // device already spent. Query each newly discovered nullifier once, then
    // stop: this is an explicit bounded backstop rather than a generic round
    // loop that re-queries the same stable tags.
    const followUpNullifiers = walletQueryNullifiers(session.staging).filter(
      (nullifier) => !queriedNullifiers.has(bytesKey(nullifier)),
    );
    for (const nullifier of followUpNullifiers) queriedNullifiers.add(bytesKey(nullifier));
    const beforeFollowUp = transactions.size;
    await scanNullifiers(followUpNullifiers);
    if (transactions.size !== beforeFollowUp) {
      ordered = orderedTransactions();
      report = await decryptTransactions({
        wallet: session.staging,
        keys,
        transactions: ordered,
        config: decryptConfig,
        context,
      });
      if (
        !registryRefreshed &&
        needsRegistry({ report, wallet: session.staging, client: input.client })
      ) {
        if ((await backfillSessionRegistry(session, input.client, context)) > 0) {
          report = await decryptTransactions({
            wallet: session.staging,
            keys,
            transactions: ordered,
            config: decryptConfig,
            context,
          });
        }
      }
    }

    // Exact tag lookups per epoch, each ring's state is the watermark.
    if (input.anonymousRings !== undefined) {
      const delivered: RingDeliveredCandidate[] = [];
      try {
        const depositTags: Bytes32[] = [];
        const reports: AnonymousRingReport[] = [];
        for (const start of input.anonymousRings.start ?? []) {
          if (session.staging.anonymousRing(start.ring) === undefined)
            session.staging._setAnonymousRing(
              AnonymousRingState.create(start.ring, start.creationEpoch),
            );
        }
        for (const state of session.staging.anonymousRings()) {
          const scan = await scanAnonymousRing(
            {
              keys: input.keys,
              indexer: input.client,
              state,
              slot: input.anonymousRings.slot,
              // A default-ring note funds an anonymous payment too, its spend carries the ring change.
              knownNullifiers: session.staging
                .utxos()
                .filter(
                  (entry) =>
                    entry.utxo.ringProgramId === undefined ||
                    entry.utxo.ringProgramId === state.ring,
                )
                .map((entry) => entry.nullifier),
              pageLimit,
              nextRpcConfig,
              depositPayloadDecoder: input.config?.depositPayloadDecoder,
            },
            context,
          );
          for (const tx of scan.transactions) transactions.set(shieldedTransactionKey(tx), tx);
          for (const tx of scan.deposits) deposits.set(shieldedTransactionKey(tx), tx);
          delivered.push(...scan.candidates);
          depositTags.push(...scan.depositTags);
          session.staging._setAnonymousRing(scan.state);
          reports.push(
            Object.freeze({
              ring: state.ring,
              notes: scan.notes,
              anchors: scan.anchors.map(({ addressIndex, epoch, asset, amount }) =>
                Object.freeze({ addressIndex, epoch, asset, amount }),
              ),
              scannedEpoch: scan.state.scannedEpoch,
            }),
          );
        }
        // The pass opens a candidate only on the object it reads, the last read of its transaction.
        const candidates = delivered.map((candidate) => {
          const read = transactions.get(shieldedTransactionKey(candidate.transaction));
          return read === undefined || read === candidate.transaction
            ? candidate
            : Object.freeze({ ...candidate, transaction: read });
        });
        ordered = orderedTransactions();
        report = await decryptTransactions({
          wallet: session.staging,
          keys,
          transactions: ordered,
          config: decryptConfig,
          delivered: candidates,
          depositTags,
          context,
        });
        await resolvePendingNotes({ wallet: session.staging, keys, context });
        const spendNullifiers = walletQueryNullifiers(session.staging).filter(
          (nullifier) => !queriedNullifiers.has(bytesKey(nullifier)),
        );
        for (const nullifier of spendNullifiers) queriedNullifiers.add(bytesKey(nullifier));
        const beforeSpends = transactions.size;
        await scanNullifiers(spendNullifiers);
        if (transactions.size !== beforeSpends) {
          ordered = orderedTransactions();
          report = await decryptTransactions({
            wallet: session.staging,
            keys,
            transactions: ordered,
            config: decryptConfig,
            delivered: candidates,
            depositTags,
            context,
          });
        }
        report = Object.freeze({ ...report, anonymousRings: Object.freeze(reports) });
      } finally {
        for (const candidate of delivered) candidate.slotSecret.fill(0);
      }
    }
    // A pending note commits with the wallet, only an unknown id or field loses a UTXO.
    if (unknownAssets(report) || walletHasUnknownMint(session.staging)) {
      throw new WalletError("WALLET_UNRESOLVED_ASSET", {
        details: { unknownAssetIds: report.unknownAssetIds.map(String) },
      });
    }
    input.wallet._commitSync(sealSyncDelta(session), session.baseRevision);
    return report;
  } catch (cause) {
    throw wrapWalletError("WALLET_SYNC", cause);
  }
}

async function backfillSessionRegistry(
  session: WalletSyncSession,
  client: SyncClient,
  context?: RequestContext,
): Promise<number> {
  if (client.solanaRpc === undefined || client.commitment === undefined) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", {
      details: { field: client.solanaRpc === undefined ? "solanaRpc" : "commitment" },
    });
  }
  const registryRpc: KitRpcAccess = { solanaRpc: client.solanaRpc, commitment: client.commitment };
  let inserted = 0;
  for (const { assetId, mint } of await fetchSplAssetRegistrations(registryRpc, context)) {
    if (ensureSessionAsset(session, assetId, mint)) inserted++;
  }
  return inserted;
}

export function getPrivateTokenBalances(wallet: Wallet): readonly AssetBalance[] {
  return wallet.balances(true);
}

export function getPrivateTransactions(wallet: Wallet): readonly PrivateTransaction[] {
  return wallet.privateTransactions();
}
