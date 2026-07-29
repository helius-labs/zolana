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
import type { ViewingKeyLike } from "../keypair/shielded.js";
import { TransactionError } from "../transaction/error.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { decodeOutputData } from "../transaction/serialization/codecs.js";
import type { WalletSyncMaterial } from "../transaction/wallet/authority.js";
import {
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type ViewingKeyEntry,
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
  "solanaRpc" | "commitment" | "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags"
>;

export interface SyncWalletConfig {
  readonly tagWindow?: bigint;
  readonly tagQueryChunk?: number;
  readonly pageLimit?: number;
  readonly rounds?: number;
  readonly waitForIndexer?: boolean;
  readonly retry?: IndexerPollConfig;
}

export interface SyncWalletReport extends SyncReport {
  /** False when the configured round bound was reached while discovery was still advancing. */
  readonly complete: boolean;
  readonly rounds: number;
}

/**
 * Per-viewing-key counters that extend the queried tag ranges past the scan
 * window. These counters are owned by the wallet state.
 */
export type {
  CounterpartyCounter,
  ViewingKeyEntry as ViewingKeyCounters,
} from "../transaction/wallet/state.js";

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

function atLeastOne(value: number, field: string): number {
  if (!Number.isSafeInteger(value)) {
    throw new WalletError("WALLET_INVALID_SYNC_CONFIG", { details: { field, value } });
  }
  return Math.max(value, 1);
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

function viewingKeyCounters(wallet: Wallet, key: ViewingKeyLike): ViewingKeyEntry | undefined {
  const publicKey = bytesKey(key.publicKey().toBytes());
  return wallet.viewingKeyHistory.find(
    (entry) => bytesKey(entry.viewingPublicKey.toBytes()) === publicKey,
  );
}

/**
 * Every tag the wallet must ask the indexer about. Counters extend each family
 * past the window because a counterparty may have advanced its own counter
 * further than this wallet has scanned; the two shared families are the only
 * way notes from a known sender or to a known recipient surface at all.
 *
 * Material that does not belong to this wallet is refused here rather than by
 * the decrypt pass further down, because a tag is a query the indexer sees: a
 * wallet handed the wrong keys would otherwise publish a full window of them
 * before anything noticed.
 */
function walletQueryTags(
  wallet: Wallet,
  material: WalletSyncMaterial,
  window: bigint,
): readonly Bytes32[] {
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
  for (const key of material.viewingKeys) {
    const counters = viewingKeyCounters(wallet, key);
    add(key.recipientBootstrapViewTag());
    for (let n = 0n; n < (counters?.txCount ?? 0n) + window; n++) add(key.senderViewTag(n));
    for (let n = 0n; n < (counters?.requestCount ?? 0n) + window; n++) {
      add(key.recipientRequestViewTag(n));
    }
    for (const sender of counters?.knownSenders ?? []) {
      for (let n = 0n; n < sender.count + window; n++) {
        add(key.recipientSharedViewTag(sender.counterparty, n));
      }
    }
    for (const recipient of counters?.knownRecipients ?? []) {
      for (let n = 0n; n < recipient.count + window; n++) {
        add(key.sendSharedViewTag(recipient.counterparty, n));
      }
    }
  }
  return [...tags.values()];
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

interface CollectInput {
  readonly indexer: Pick<ZolanaClient, "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags">;
  readonly chunk: readonly Bytes32[];
  readonly pageLimit: number;
  readonly rpcConfig: IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
}

async function collectShieldedTransactions(
  input: CollectInput,
  context?: RequestContext,
): Promise<void> {
  let cursor: Uint8Array | undefined;
  const seenCursors = new Set<string>();
  do {
    const response = await input.indexer.getShieldedTransactionsByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.rpcConfig,
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
  input: CollectInput,
  context?: RequestContext,
): Promise<void> {
  let cursor: Uint8Array | undefined;
  const seenCursors = new Set<string>();
  do {
    const response = await input.indexer.getEncryptedUtxosByTags(
      { tags: input.chunk, limit: input.pageLimit, ...(cursor === undefined ? {} : { cursor }) },
      input.rpcConfig,
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

export async function syncWallet(
  input: Readonly<{
    wallet: Wallet;
    authority: WalletAuthority;
    client: SyncClient;
    config?: SyncWalletConfig;
  }>,
  context?: RequestContext,
): Promise<SyncWalletReport> {
  try {
    const tagWindow = input.config?.tagWindow ?? 64n;
    // Rust carries the window in a `u64`, so only a value outside that range is
    // a config error here. A zero window is rejected one layer down, by the same
    // `syncWithMaterial` guard Rust reaches, and keeping it there is what makes
    // both languages raise the same error for it.
    if (tagWindow < 0n || tagWindow > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_INVALID_SYNC_CONFIG", {
        details: { field: "tagWindow", value: tagWindow.toString() },
      });
    }
    const chunkSize = atLeastOne(input.config?.tagQueryChunk ?? 64, "tagQueryChunk");
    const pageLimit = atLeastOne(input.config?.pageLimit ?? 100, "pageLimit");
    const rounds = atLeastOne(input.config?.rounds ?? 6, "rounds");
    const poll = input.config?.retry ?? DEFAULT_INDEXER_POLL_CONFIG;
    const syncedAt = BigInt(Math.floor(Date.now() / 1_000));
    const rpcConfig: IndexerRpcConfig = Object.freeze({
      waitForIndexer: input.config?.waitForIndexer ?? false,
      poll: Object.freeze({ ...poll, numRetries: Math.max(poll.numRetries, 1) }),
    });
    const material = await input.authority.syncMaterial();
    const transactions = new Map<string, IndexedShieldedTransaction>();
    const deposits = new Map<string, IndexedShieldedTransaction>();
    let report: SyncReport;
    let ordered: readonly IndexedShieldedTransaction[] = [];
    let round = 0;
    let complete = false;

    do {
      const before = [transactions.size, deposits.size] as const;
      // Rebuilt every round: notes stored by the previous round advance the
      // wallet's counters, which widens the tag ranges queried next.
      const tags = walletQueryTags(input.wallet, material, tagWindow);
      for (let offset = 0; offset < tags.length; offset += chunkSize) {
        const chunk = tags.slice(offset, offset + chunkSize);
        await collectShieldedTransactions(
          { indexer: input.client, chunk, pageLimit, rpcConfig, out: transactions },
          context,
        );
        await collectProoflessDeposits(
          { indexer: input.client, chunk, pageLimit, rpcConfig, out: deposits },
          context,
        );
      }

      ordered = [
        ...[...transactions.values()].sort(compareBySlotThenSignature),
        ...[...deposits.values()].sort(compareDeposits),
      ];
      report = await decryptTransactions({
        wallet: input.wallet,
        authority: input.authority,
        transactions: ordered,
        config: { tagWindow, syncedAt },
      });
      round++;
      if (before[0] === transactions.size && before[1] === deposits.size) {
        complete = true;
        break;
      }
    } while (round < rounds);
    const needsRegistryBackfill =
      report.unknownAssetIds.length > 0 ||
      report.unknownAssetFields.length > 0 ||
      walletHasUnknownMint(input.wallet);
    if (!needsRegistryBackfill) {
      return Object.freeze({ ...report, complete, rounds: round });
    }

    const inserted = await backfillAssetRegistry(input.wallet, input.client, context);
    if (inserted === 0) {
      return Object.freeze({ ...report, complete: false, rounds: round });
    }
    report = await decryptTransactions({
      wallet: input.wallet,
      authority: input.authority,
      transactions: ordered,
      config: { tagWindow, syncedAt },
    });
    // The retry can reveal a counterparty whose shared tag stream was not part
    // of this fetch. Returning incomplete makes the continuation explicit.
    return Object.freeze({ ...report, complete: false, rounds: round });
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
