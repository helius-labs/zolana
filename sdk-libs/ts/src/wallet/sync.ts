import {
  getAddressEncoder,
  getBase64Decoder,
  getBase64Encoder,
  type Base64EncodedBytes,
} from "@solana/kit";

import { runKitRpc } from "../client/kit.js";
import type { ZolanaClient } from "../client/client.js";
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
import type { WalletSyncMaterial } from "../transaction/wallet/authority.js";
import {
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "../transaction/wallet/state.js";
import { decryptTransactions } from "../transaction/wallet/sync.js";

import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey } from "./internal.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";

const addressEncoder = getAddressEncoder();
const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();

type SyncClient = Pick<
  ZolanaClient,
  | "solanaRpc"
  | "commitment"
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
  | "getShieldedTransactionsByTags"
>;

export interface SyncWalletConfig {
  /** Stable tags and nullifiers per indexer request. Defaults to 64. */
  readonly queryChunk?: number;
  /** Rows requested per indexer page. Defaults to Photon's maximum, 1000. */
  readonly pageLimit?: number;
  /** Slot the indexer must have persisted before its answers are used. */
  readonly requireSlot?: bigint;
  readonly retry?: IndexerPollConfig;
}

export async function backfillAssetRegistry(
  wallet: Wallet,
  registryRpc: Pick<ZolanaClient, "solanaRpc" | "commitment">,
  context?: RequestContext,
): Promise<number> {
  let accounts;
  try {
    accounts = await runKitRpc("getProgramAccounts", context, (abortSignal) =>
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
  } catch (error) {
    if (error instanceof ClientError && error.code === "CLIENT_UNSUPPORTED_RPC_METHOD") return 0;
    throw error;
  }

  let inserted = 0;
  for (const { account } of accounts) {
    if (account.owner !== SHIELDED_POOL_PROGRAM_ID) continue;
    try {
      const registry = decodeSplAssetRegistry(
        new Uint8Array(base64Encoder.encode(account.data[0])),
      );
      wallet.registerAsset(registry.assetId, registry.mint);
      inserted++;
    } catch {
      continue;
    }
  }
  return inserted;
}

function positiveInteger(value: number, field: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", { details: { field, value } });
  }
  return value;
}

/** Rust compares the whole `ShieldedAddress`, which is these three keys. */
function sameIdentity(material: WalletSyncMaterial, wallet: Wallet): boolean {
  return (
    bytesKey(material.identity.signingPublicKey.toBytes()) ===
      bytesKey(wallet.identity.signingPublicKey.toBytes()) &&
    bytesKey(material.identity.nullifierPublicKey) ===
      bytesKey(wallet.identity.nullifierPublicKey) &&
    bytesKey(material.identity.viewingPublicKey.toBytes()) ===
      bytesKey(wallet.identity.viewingPublicKey.toBytes())
  );
}

/**
 * The stable tags a wallet asks the indexer about: one shielded-identity
 * signing tag for confidential transactions and one bootstrap tag per retained
 * viewing key for deposits and key rotation.
 *
 * Material that does not belong to this wallet is refused here rather than by
 * the decrypt pass further down, because a tag is a query the indexer sees: a
 * wallet handed the wrong keys must not publish any of them before the
 * mismatch is noticed.
 */
function walletQueryTags(wallet: Wallet, material: WalletSyncMaterial): readonly Bytes32[] {
  if (!sameIdentity(material, wallet)) {
    throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
  }
  const current = bytesKey(wallet.identity.viewingPublicKey.toBytes());
  if (!material.viewingKeys.some((key) => bytesKey(key.publicKey().toBytes()) === current)) {
    throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
  }
  const tags = new Map<string, Bytes32>();
  const add = (tag: Bytes32): void => {
    tags.set(bytesKey(tag), tag);
  };
  add(material.identity.signingPublicKey.confidentialViewTag());
  for (const key of material.viewingKeys) add(key.recipientBootstrapViewTag());
  return [...tags.values()];
}

/** Every note nullifier is queried, including notes already marked spent. */
function walletQueryNullifiers(wallet: Wallet): readonly Bytes32[] {
  const nullifiers = new Map<string, Bytes32>();
  for (const entry of wallet.utxos()) {
    nullifiers.set(bytesKey(entry.nullifier), entry.nullifier);
  }
  return [...nullifiers.values()];
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

function checkedNextCursor(
  method: string,
  cursor: Uint8Array | undefined,
  seen: Set<string>,
): Uint8Array | undefined {
  if (cursor === undefined) return undefined;
  const key = bytesKey(cursor);
  if (seen.has(key)) {
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method, path: "$.next_cursor" },
    });
  }
  seen.add(key);
  return cursor;
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
  readonly indexer: Pick<ZolanaClient, "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags">;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
}

async function collectShieldedTransactions(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<void> {
  let cursor: Uint8Array | undefined;
  const seenCursors = new Set<string>();
  do {
    const response = await input.indexer.getShieldedTransactionsByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.nextRpcConfig(),
      context,
    );
    for (const transaction of response.transactions) {
      // Photon can surface a proofless deposit here before flagging it. Those
      // are collected from the encrypted-utxo endpoint instead, so taking them
      // twice would store the same note under two keys.
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    cursor = checkedNextCursor("getShieldedTransactionsByTags", response.nextCursor, seenCursors);
  } while (cursor !== undefined);
}

async function collectProoflessDeposits(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<void> {
  let cursor: Uint8Array | undefined;
  const seenCursors = new Set<string>();
  do {
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
    cursor = checkedNextCursor("getEncryptedUtxosByTags", response.nextCursor, seenCursors);
  } while (cursor !== undefined);
}

interface CollectByNullifiersInput {
  readonly indexer: Pick<ZolanaClient, "getShieldedTransactionsByNullifiers">;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
}

async function collectShieldedTransactionsByNullifiers(
  input: CollectByNullifiersInput,
  context?: RequestContext,
): Promise<void> {
  let cursor: Uint8Array | undefined;
  const seenCursors = new Set<string>();
  do {
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
    cursor = checkedNextCursor(
      "getShieldedTransactionsByNullifiers",
      response.nextCursor,
      seenCursors,
    );
  } while (cursor !== undefined);
}

export async function syncWallet(
  input: Readonly<{
    wallet: Wallet;
    authority: WalletAuthority;
    client: SyncClient;
    config?: SyncWalletConfig;
  }>,
  context?: RequestContext,
): Promise<SyncReport> {
  try {
    const chunkSize = positiveInteger(input.config?.queryChunk ?? 64, "queryChunk");
    const pageLimit = positiveInteger(input.config?.pageLimit ?? 1_000, "pageLimit", 1_000);
    const poll = input.config?.retry ?? DEFAULT_INDEXER_POLL_CONFIG;
    const syncedAt = BigInt(Math.floor(Date.now() / 1_000));
    const validatedPoll = Object.freeze({ ...poll, numRetries: Math.max(poll.numRetries, 1) });
    const ungated: IndexerRpcConfig = Object.freeze({ poll: validatedPoll });
    const requireSlot = input.config?.requireSlot;
    // Freshness is established once per sync, on the first indexer request. A
    // per-request gate would pay the wait for every tag chunk, collector, and page.
    let pendingGate: IndexerRpcConfig | undefined =
      requireSlot === undefined ? undefined : Object.freeze({ poll: validatedPoll, requireSlot });
    const nextRpcConfig = (): IndexerRpcConfig => {
      if (pendingGate === undefined) return ungated;
      const gate = pendingGate;
      pendingGate = undefined;
      return gate;
    };
    const material = await input.authority.syncMaterial();
    const transactions = new Map<string, IndexedShieldedTransaction>();
    const deposits = new Map<string, IndexedShieldedTransaction>();
    const tags = walletQueryTags(input.wallet, material);
    for (let offset = 0; offset < tags.length; offset += chunkSize) {
      const chunk = tags.slice(offset, offset + chunkSize);
      await collectShieldedTransactions(
        { indexer: input.client, chunk, pageLimit, nextRpcConfig, out: transactions },
        context,
      );
      await collectProoflessDeposits(
        { indexer: input.client, chunk, pageLimit, nextRpcConfig, out: deposits },
        context,
      );
    }

    const queriedNullifiers = new Set<string>();
    const initialNullifiers = walletQueryNullifiers(input.wallet);
    for (const nullifier of initialNullifiers) queriedNullifiers.add(bytesKey(nullifier));
    for (let offset = 0; offset < initialNullifiers.length; offset += chunkSize) {
      await collectShieldedTransactionsByNullifiers(
        {
          indexer: input.client,
          chunk: initialNullifiers.slice(offset, offset + chunkSize),
          pageLimit,
          nextRpcConfig,
          out: transactions,
        },
        context,
      );
    }

    const orderedTransactions = (): readonly IndexedShieldedTransaction[] => [
      ...[...transactions.values()].sort(compareBySlotThenSignature),
      ...[...deposits.values()].sort(compareDeposits),
    ];
    let ordered = orderedTransactions();
    let report = await decryptTransactions({
      wallet: input.wallet,
      authority: input.authority,
      transactions: ordered,
      config: { syncedAt },
    });
    let registryRefreshed = false;
    if (
      report.unknownAssetIds.length > 0 ||
      report.unknownAssetFields.length > 0 ||
      walletHasUnknownMint(input.wallet)
    ) {
      registryRefreshed = true;
      if ((await backfillAssetRegistry(input.wallet, input.client, context)) > 0) {
        report = await decryptTransactions({
          wallet: input.wallet,
          authority: input.authority,
          transactions: ordered,
          config: { syncedAt },
        });
      }
    }

    // A transaction found by a stable tag can create a note that another
    // device already spent. Query each newly discovered nullifier once, then
    // stop, so the backstop stays bounded.
    const followUpNullifiers = walletQueryNullifiers(input.wallet).filter(
      (nullifier) => !queriedNullifiers.has(bytesKey(nullifier)),
    );
    const beforeFollowUp = transactions.size;
    for (let offset = 0; offset < followUpNullifiers.length; offset += chunkSize) {
      await collectShieldedTransactionsByNullifiers(
        {
          indexer: input.client,
          chunk: followUpNullifiers.slice(offset, offset + chunkSize),
          pageLimit,
          nextRpcConfig,
          out: transactions,
        },
        context,
      );
    }
    if (transactions.size !== beforeFollowUp) {
      ordered = orderedTransactions();
      report = await decryptTransactions({
        wallet: input.wallet,
        authority: input.authority,
        transactions: ordered,
        config: { syncedAt },
      });
      if (
        !registryRefreshed &&
        (report.unknownAssetIds.length > 0 ||
          report.unknownAssetFields.length > 0 ||
          walletHasUnknownMint(input.wallet))
      ) {
        if ((await backfillAssetRegistry(input.wallet, input.client, context)) > 0) {
          report = await decryptTransactions({
            wallet: input.wallet,
            authority: input.authority,
            transactions: ordered,
            config: { syncedAt },
          });
        }
      }
    }
    return report;
  } catch (cause) {
    throw wrapWalletError("WALLET_SYNC", cause);
  }
}

export function getPrivateTokenBalances(wallet: Wallet): readonly AssetBalance[] {
  return wallet.balances(true);
}

export function getPrivateTransactions(wallet: Wallet): readonly PrivateTransaction[] {
  return wallet.privateTransactions();
}
