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
import { decodeOutputData } from "../transaction/serialization/codecs.js";
import {
  checkKeysIdentity,
  checkViewingPublicKeys,
  type RingTagKeys,
  type ShieldedKeys,
} from "../transaction/wallet/keys.js";
import {
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "../transaction/wallet/state.js";
import { decryptTransactions } from "../transaction/wallet/sync.js";

import { AnonymousStreams, type AnonymousRingState } from "./anonymous-sync.js";
import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey } from "./internal.js";
import { readChunk } from "./paging.js";
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

/** A pending anonymous note names its mint, the registry backfill registers it. */
function unresolvedAssets(report: SyncReport): boolean {
  return (
    report.unknownAssetIds.length > 0 ||
    report.unknownAssetFields.length > 0 ||
    report.pendingAssets.length > 0
  );
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

/**
 * Rust admits any payload `decode_output_data` accepts, not only one already
 * flagged proofless: the deposit's own `ProoflessOutput` parse happens later, in
 * the wallet, and screening on the scheme here would drop a deposit the wallet
 * can still read.
 */
function isDecodablePayload(payload: Uint8Array): boolean {
  try {
    decodeOutputData(payload);
    return true;
  } catch {
    return false;
  }
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
 * Photon can emit multiple shielded events in one Solana transaction. The
 * current wire response does not expose its event index, so the committed
 * output contexts (or nullifiers for an outputless event) form the stable
 * event identity instead of collapsing every event under the signature.
 */
function shieldedTransactionKey(transaction: IndexedShieldedTransaction): string {
  return [
    transaction.txSignature,
    ...transaction.outputSlots.map(
      ({ outputContext }) =>
        `${outputContext.tree}:${String(outputContext.leafIndex)}:${bytesKey(outputContext.hash)}`,
    ),
    ...transaction.nullifiers.map(bytesKey),
  ].join("|");
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

interface CollectByTagsInput {
  readonly indexer: Pick<
    IndexerReader,
    "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags"
  >;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** Where this group of tags was read to last sync, or undefined for never. */
  readonly from: Uint8Array | undefined;
}

async function collectShieldedTransactions(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getShieldedTransactionsByTags", input.from, async (cursor) => {
    const response = await input.indexer.getShieldedTransactionsByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.nextRpcConfig(),
      context,
    );
    for (const transaction of response.transactions) {
      // Photon can surface a proofless deposit here before flagging it. Those
      // are collected from the encrypted-utxo endpoint instead, so taking them
      // twice would store the same UTXO under two keys.
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
}

async function collectProoflessDeposits(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getEncryptedUtxosByTags", input.from, async (cursor) => {
    const response = await input.indexer.getEncryptedUtxosByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.nextRpcConfig(),
      context,
    );
    for (const match of response.matches) {
      if (match.txViewingPk !== undefined || match.salt !== undefined) continue;
      const key = [
        match.txSignature,
        match.outputSlot.outputContext.tree,
        String(match.outputSlot.outputContext.leafIndex),
        bytesKey(match.outputSlot.outputContext.hash),
      ].join("|");
      if (input.out.has(key)) continue;
      if (!isDecodablePayload(match.outputSlot.payload)) continue;
      input.out.set(
        key,
        Object.freeze({
          slot: match.slot,
          txSignature: match.txSignature,
          outputSlots: Object.freeze([match.outputSlot]),
          messages: Object.freeze([]),
          nullifiers: Object.freeze([]),
          proofless: true,
        }),
      );
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
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

interface CollectByNullifiersInput {
  readonly indexer: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** Where this chunk was read to last time, if it has been read before. */
  readonly start?: Uint8Array;
}

/**
 * Returns how far the scan reached, or `undefined` if the indexer did not say.
 *
 * The position comes from `scannedThrough`, not from the rows: an unspent
 * nullifier matches nothing, so there is no last row to take a position from.
 * An indexer that does not report it leaves the caller starting from zero next
 * time, which is exactly the old behaviour.
 */
async function collectShieldedTransactionsByNullifiers(
  input: CollectByNullifiersInput,
  context?: RequestContext,
): Promise<Uint8Array | undefined> {
  return readChunk("getShieldedTransactionsByNullifiers", input.start, async (cursor) => {
    const response = await input.indexer.getShieldedTransactionsByNullifiers(
      {
        nullifiers: input.chunk,
        limit: input.pageLimit,
        ...(cursor === undefined ? {} : { cursor }),
      },
      input.nextRpcConfig(),
      context,
    );
    for (const transaction of response.transactions) {
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return {
      nextCursor: response.nextCursor,
      scannedThrough: response.scannedThrough,
    };
  });
}

export type SyncWalletInput = Readonly<{
  wallet: Wallet;
  client: SyncClient;
  config?: SyncWalletConfig;
}> &
  (
    | Readonly<{ keys: ShieldedKeys; anonymousRing?: undefined }>
    | Readonly<{ keys: RingTagKeys; anonymousRing: AnonymousRingState }>
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
    if (unresolvedAssets(report) || walletHasUnknownMint(session.staging)) {
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
        (unresolvedAssets(report) || walletHasUnknownMint(session.staging))
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

    // Exact lookups with no cursor, every sync walks the streams from the start.
    if (input.anonymousRing !== undefined) {
      const streams = new AnonymousStreams(
        input.keys,
        input.keys.address().viewingPublicKey,
        input.anonymousRing,
      );
      for (;;) {
        const tags = await streams.nextWindows(context);
        const windowRows = new Map<string, IndexedShieldedTransaction>();
        const windowDeposits = new Map<string, IndexedShieldedTransaction>();
        for (let offset = 0; offset < tags.length; offset += chunkSize) {
          const chunk = tags.slice(offset, offset + chunkSize);
          const collect = (
            collector: typeof collectShieldedTransactions,
            out: Map<string, IndexedShieldedTransaction>,
          ) =>
            collector(
              { indexer: input.client, chunk, pageLimit, nextRpcConfig, out, from: undefined },
              context,
            );
          await collect(collectShieldedTransactions, windowRows);
          await collect(collectProoflessDeposits, windowDeposits);
        }
        streams.observe([...windowRows.values(), ...windowDeposits.values()]);
        let moved = false;
        for (const [key, tx] of windowRows) {
          if (!transactions.has(key)) {
            transactions.set(key, tx);
            moved = true;
          }
        }
        for (const [key, tx] of windowDeposits) {
          if (!deposits.has(key)) {
            deposits.set(key, tx);
            moved = true;
          }
        }
        const owned = new Set(session.staging.utxos().map((entry) => bytesKey(entry.nullifier)));
        if (await streams.routeChange(transactions.values(), owned, context)) moved = true;
        if (moved) {
          ordered = orderedTransactions();
          report = await decryptTransactions({
            wallet: session.staging,
            keys,
            transactions: ordered,
            config: decryptConfig,
            anonymous: streams.routes,
            context,
          });
          streams.record();
        }
        const newNullifiers = walletQueryNullifiers(session.staging).filter(
          (nullifier) => !queriedNullifiers.has(bytesKey(nullifier)),
        );
        for (const nullifier of newNullifiers) queriedNullifiers.add(bytesKey(nullifier));
        const beforeSpends = transactions.size;
        await scanNullifiers(newNullifiers);
        if (transactions.size !== beforeSpends) moved = true;
        if (!moved && streams.isDone()) break;
      }
      report = Object.freeze({ ...report, anonymousRing: streams.finish() });
    }
    // An unresolved asset means a fetched UTXO was not stored. A commit would
    // advance the cursors past it and lose the UTXO until a full rescan.
    if (unresolvedAssets(report) || walletHasUnknownMint(session.staging)) {
      throw new WalletError("WALLET_UNRESOLVED_ASSET", {
        details: {
          unknownAssetIds: report.unknownAssetIds.map(String),
          pendingMints: report.pendingAssets.map((note) => note.utxo.asset),
        },
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
