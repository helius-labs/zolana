import { nextPageToken, validatePage } from "../interface/page.js";
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
import { bytesKey } from "../interface/bytes.js";
import { checkedBytes } from "../keypair/bytes.js";
import { decodeBatch } from "../interface/decode.js";
import { decodeSplAssetRegistry } from "../interface/accounts.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import { StateDiscriminator } from "../interface/state.js";
import type {
  Address,
  Bytes32,
  HistoryFilters,
  PaginationToken,
  RequestContext,
} from "../interface/types.js";
import { TransactionError } from "../transaction/error.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { decodeOutputData } from "../transaction/serialization/codecs.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import {
  checkKeysIdentity,
  checkViewingPublicKeys,
  type DeriveRequest,
  type ShieldedKeys,
} from "../transaction/wallet/keys.js";
import {
  type AssetBalance,
  type PrivateTransaction,
  type SyncReport,
  type Wallet,
} from "../transaction/wallet/state.js";
import { decryptTransactions } from "../transaction/wallet/sync.js";

import { WalletError, wrapWalletError } from "./error.js";
import {
  advanceSessionCheckpoints,
  beginSyncSession,
  ensureSessionAsset,
  sealSyncDelta,
  sessionCheckpoint,
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
  /** Stable tags and nullifiers per indexer request. Defaults to 64. */
  readonly queryChunk?: number;
  /**
   * Solana transactions requested per indexer page, halved for the rest of the
   * sync while a page is too large. Defaults to Photon's maximum, 1000.
   */
  readonly pageLimit?: number;
  /**
   * Slot the indexer must have persisted before its answers are used. Unset
   * applies the client's configured `indexerConfig.requireSlot`, if any.
   */
  readonly requireSlot?: bigint;
  /** Unset applies the client's configured `indexerConfig.poll`. */
  readonly retry?: IndexerPollConfig;
}

/** What `syncWallet` found, the decrypt counters and the sender view tag position. */
export interface WalletSyncReport extends SyncReport {
  /**
   * The next unused sender view tag index of the current viewing key: one past
   * the highest index whose tag the wallet's history carries, or 0. A
   * policy-ring transfer tags the sender's own outputs with
   * `ViewingKey.senderViewTag(nextSenderTxCount)` through
   * `ConfidentialTransfer.withSenderViewTag`.
   */
  readonly nextSenderTxCount: bigint;
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
 * Output contexts and nullifiers identify both indexed events and synthesized
 * proofless deposits, which have no event index. A signature alone would
 * collapse multiple events in one transaction.
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
  /** Halved in place when a page is too large, so the rest of the sync asks for less. */
  readonly pageLimit: { value: number };
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** The slot this group of tags was read through last sync, or undefined for never. */
  readonly checkpoint: bigint | undefined;
}

/** The controls of one page of a resumable scan. */
interface ScanControls {
  readonly paginationToken?: PaginationToken;
  readonly filters?: HistoryFilters;
  readonly limit: number;
}

/** One indexer page, reduced to what a resumable scan needs. */
interface ScanPage {
  readonly context: { readonly slot: bigint };
  readonly data: readonly { readonly slot: bigint; readonly signature: string }[];
  readonly paginationToken: PaginationToken | null;
}

/**
 * Reads a chunk's history above its checkpoint and returns the next
 * checkpoint, the final page's snapshot slot. Photon commits each block with
 * its transactions, so that page proves every match at or below the slot was
 * returned. Tokens only continue this scan, they are never persisted.
 */
async function readChunk(
  method: string,
  scan: Pick<CollectByTagsInput, "checkpoint" | "pageLimit" | "nextRpcConfig">,
  request: (controls: ScanControls, rpcConfig: IndexerRpcConfig) => Promise<ScanPage>,
): Promise<bigint> {
  const invalid = (path: string) => () =>
    new ClientError("CLIENT_INVALID_RPC_RESPONSE", { details: { method, path } });
  const filters = scan.checkpoint === undefined ? undefined : { slot: { gt: scan.checkpoint } };
  let token: PaginationToken | undefined;
  // Taken once per page, so a retried page keeps the sync's freshness gate.
  let rpcConfig = scan.nextRpcConfig();
  for (;;) {
    const controls: ScanControls = {
      ...(filters === undefined ? {} : { filters }),
      ...(token === undefined ? {} : { paginationToken: token }),
      limit: scan.pageLimit.value,
    };
    let page: ScanPage;
    try {
      page = await request(controls, rpcConfig);
    } catch (error) {
      // Too large for the SDK or Photon: ask for the same page at half the limit.
      const tooLarge =
        error instanceof ClientError && error.code === "CLIENT_INDEXER_RESPONSE_TOO_LARGE";
      if (!tooLarge || controls.limit === 1) throw error;
      scan.pageLimit.value = Math.floor(controls.limit / 2);
      continue;
    }
    try {
      validatePage(page, { ...controls, limit: BigInt(controls.limit) });
    } catch {
      throw invalid("$")();
    }
    const next = nextPageToken(page, token, invalid("$.paginationToken"));
    if (next === null) return page.context.slot;
    token = next;
    rpcConfig = scan.nextRpcConfig();
  }
}

async function collectShieldedTransactions(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<bigint> {
  const method = "getShieldedTransactionsByTags";
  return readChunk(method, input, async (controls, rpcConfig) => {
    const response = await input.indexer.getShieldedTransactionsByTags(
      { tags: input.chunk, ...controls },
      rpcConfig,
      context,
    );
    for (const transaction of response.data.flatMap((item) => item.events)) {
      // Photon can surface a proofless deposit here before flagging it. Those
      // are collected from the encrypted-utxo endpoint instead, so taking them
      // twice would store the same UTXO under two keys.
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return response;
  });
}

async function collectProoflessDeposits(
  input: CollectByTagsInput,
  context?: RequestContext,
): Promise<bigint> {
  const method = "getEncryptedUtxosByTags";
  return readChunk(method, input, async (controls, rpcConfig) => {
    const response = await input.indexer.getEncryptedUtxosByTags(
      { tags: input.chunk, ...controls },
      rpcConfig,
      context,
    );
    for (const match of response.data.flatMap((item) => item.outputs)) {
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
    return response;
  });
}

/**
 * Buckets keys by the checkpoint their stream was last read through.
 *
 * A chunk carries one slot filter, so keys at different checkpoints cannot
 * share a request. `undefined` (never queried) is its own group.
 */
function groupByCheckpoint(
  keys: readonly Bytes32[],
  checkpointFor: (key: Bytes32) => bigint | undefined,
): readonly { readonly checkpoint: bigint | undefined; readonly keys: Bytes32[] }[] {
  const groups = new Map<bigint | undefined, { checkpoint: bigint | undefined; keys: Bytes32[] }>();
  for (const key of keys) {
    const checkpoint = checkpointFor(key);
    const group = groups.get(checkpoint);
    if (group === undefined) groups.set(checkpoint, { checkpoint, keys: [key] });
    else group.keys.push(key);
  }
  return [...groups.values()];
}

interface CollectByNullifiersInput {
  readonly indexer: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;
  readonly chunk: readonly Bytes32[];
  /** Halved in place when a page is too large, so the rest of the sync asks for less. */
  readonly pageLimit: { value: number };
  readonly nextRpcConfig: () => IndexerRpcConfig;
  readonly out: Map<string, IndexedShieldedTransaction>;
  /** The slot this chunk was read through last time, if it has been read before. */
  readonly checkpoint: bigint | undefined;
}

/**
 * Returns the slot the scan reached. An unspent nullifier matches nothing, so
 * the checkpoint comes from the snapshot, not from a row.
 */
async function collectShieldedTransactionsByNullifiers(
  input: CollectByNullifiersInput,
  context?: RequestContext,
): Promise<bigint> {
  const method = "getShieldedTransactionsByNullifiers";
  return readChunk(method, input, async (controls, rpcConfig) => {
    const response = await input.indexer.getShieldedTransactionsByNullifiers(
      { nullifiers: input.chunk, ...controls },
      rpcConfig,
      context,
    );
    for (const transaction of response.data.flatMap((item) => item.events)) {
      if (transaction.proofless) continue;
      const key = shieldedTransactionKey(transaction);
      if (!input.out.has(key)) input.out.set(key, transaction);
    }
    return response;
  });
}

/**
 * Indices a wallet sweeps past the highest sender view tag index it found. A
 * sender tag is used once and in order, so a run of this many unused indices
 * ends the sweep.
 */
const SENDER_VIEW_TAG_GAP = 100;

/** One held viewing key's sender view tags, by index. */
interface SenderTagSweep {
  readonly viewingPublicKey: X25519PublicKey;
  readonly tags: Bytes32[];
  /** Exclusive end of the indices this sync queries. */
  end: number;
  /** Exclusive end of the indices queried so far. */
  queried: number;
  /** One past the highest index in use, 0 when none is. */
  next: number;
}

/**
 * Sweeps the sender view tags of every held viewing key: index 0 through
 * `SENDER_VIEW_TAG_GAP` past the highest index found, again until a round
 * finds no new match. A match is an output slot or message carrying the tag.
 *
 * Every tag queried holds a checkpoint once the sync commits, so a resumed
 * sync reads only above it and would not see an earlier match again. A sweep
 * queries exactly `SENDER_VIEW_TAG_GAP` past its highest match, so the length
 * of the checkpointed run from index 0 restores that match.
 */
async function sweepSenderViewTags(
  input: Readonly<{
    held: readonly X25519PublicKey[];
    keys: ShieldedKeys;
    checkpointed: (tag: Bytes32) => boolean;
    scan: (tags: readonly Bytes32[]) => Promise<void>;
    transactions: () => Iterable<IndexedShieldedTransaction>;
  }>,
  context?: RequestContext,
): Promise<Readonly<{ matched: readonly Bytes32[]; nextTxCount: bigint }>> {
  const sweeps: SenderTagSweep[] = input.held.map((viewingPublicKey) => ({
    viewingPublicKey,
    tags: [],
    end: SENDER_VIEW_TAG_GAP,
    queried: 0,
    next: 0,
  }));
  const lookup = new Map<string, Readonly<{ sweep: SenderTagSweep; index: number }>>();
  const derive = async (): Promise<void> => {
    const requests: DeriveRequest[] = sweeps.flatMap((sweep) =>
      Array.from({ length: Math.max(sweep.end - sweep.tags.length, 0) }, (_, offset) => ({
        kind: "senderViewTag" as const,
        viewingPublicKey: sweep.viewingPublicKey,
        txCount: BigInt(sweep.tags.length + offset),
      })),
    );
    if (requests.length === 0) return;
    const answers = decodeBatch(
      await input.keys.derive(requests, context),
      requests.length,
      (entry) =>
        entry instanceof Uint8Array && entry.length === 32
          ? checkedBytes<Bytes32>(entry, 32, "sender view tag")
          : undefined,
      () => new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH"),
    );
    let next = 0;
    for (const sweep of sweeps) {
      while (sweep.tags.length < sweep.end) {
        const tag = answers[next++];
        if (tag === undefined) throw new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH");
        lookup.set(bytesKey(tag), { sweep, index: sweep.tags.length });
        sweep.tags.push(tag);
      }
    }
  };

  // Resume: the previous sweep ended GAP past its highest match.
  const resumed = new Set<SenderTagSweep>();
  for (;;) {
    await derive();
    let extended = false;
    for (const sweep of sweeps) {
      if (resumed.has(sweep)) continue;
      const run = sweep.tags.findIndex((tag) => !input.checkpointed(tag));
      if (run < 0) {
        sweep.end += SENDER_VIEW_TAG_GAP;
        extended = true;
        continue;
      }
      resumed.add(sweep);
      sweep.next = Math.max(run - SENDER_VIEW_TAG_GAP, 0);
      sweep.end = Math.max(run, SENDER_VIEW_TAG_GAP);
    }
    if (!extended) break;
  }

  const matched = new Map<string, Bytes32>();
  for (;;) {
    await derive();
    const pending = sweeps.flatMap((sweep) => sweep.tags.slice(sweep.queried, sweep.end));
    for (const sweep of sweeps) sweep.queried = Math.max(sweep.queried, sweep.end);
    await input.scan(pending);
    for (const transaction of input.transactions()) {
      for (const { viewTag } of [...transaction.outputSlots, ...transaction.messages]) {
        const key = bytesKey(viewTag);
        const hit = lookup.get(key);
        if (hit === undefined) continue;
        matched.set(key, viewTag);
        hit.sweep.next = Math.max(hit.sweep.next, hit.index + 1);
      }
    }
    let extended = false;
    for (const sweep of sweeps) {
      const end = sweep.next + SENDER_VIEW_TAG_GAP;
      if (end > sweep.end) {
        sweep.end = end;
        extended = true;
      }
    }
    if (!extended) break;
  }
  return Object.freeze({
    matched: Object.freeze([...matched.values()]),
    nextTxCount: BigInt(sweeps[0]?.next ?? 0),
  });
}

export interface SyncWalletInput {
  readonly wallet: Wallet;
  readonly keys: ShieldedKeys;
  readonly client: SyncClient;
  readonly config?: SyncWalletConfig;
}

export async function syncWallet(
  input: SyncWalletInput,
  context?: RequestContext,
): Promise<WalletSyncReport> {
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
  after: (report: WalletSyncReport) => T | Promise<T>,
): Promise<T> {
  await initializePoseidon();
  // Writes stage in a session and commit once, a failed sync changes nothing.
  return input.wallet._withSyncLock(async () =>
    after(await runWalletSync(input, input.keys, context)),
  );
}

async function runWalletSync(
  input: Readonly<{
    wallet: Wallet;
    client: SyncClient;
    config?: SyncWalletConfig;
  }>,
  keys: ShieldedKeys,
  context?: RequestContext,
): Promise<WalletSyncReport> {
  try {
    const chunkSize = positiveInteger(input.config?.queryChunk ?? 64, "queryChunk");
    const pageLimit = {
      value: positiveInteger(input.config?.pageLimit ?? 1_000, "pageLimit", 1_000),
    };
    const clientConfig = input.client.indexerConfig;
    const poll = input.config?.retry ?? clientConfig?.poll ?? DEFAULT_INDEXER_POLL_CONFIG;
    const decryptConfig = { syncedAt: BigInt(Math.floor(Date.now() / 1_000)) };
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
    // Tags are grouped by the slot each was last read through, because a chunk
    // carries one slot filter. Mixing a tag at the tip with one learned this
    // sync would resume the new tag from the old one's checkpoint and skip its
    // history permanently -- which is why checkpoints are per tag, not per
    // wallet. `undefined` (never queried) is its own group.
    const scanTags = async (
      stream: "transactions" | "proofless",
      streamTags: readonly Bytes32[],
    ): Promise<void> => {
      const groups = groupByCheckpoint(streamTags, (tag) =>
        sessionCheckpoint(session, stream, bytesKey(tag)),
      );

      for (const group of groups) {
        for (let offset = 0; offset < group.keys.length; offset += chunkSize) {
          const chunk = group.keys.slice(offset, offset + chunkSize);
          const collect =
            stream === "transactions" ? collectShieldedTransactions : collectProoflessDeposits;
          const checkpoint = await collect(
            {
              indexer: input.client,
              chunk,
              pageLimit,
              nextRpcConfig,
              out: stream === "transactions" ? transactions : deposits,
              checkpoint: group.checkpoint,
            },
            context,
          );
          advanceSessionCheckpoints(session, stream, chunk, checkpoint);
        }
      }
    };
    for (const stream of ["transactions", "proofless"] as const) await scanTags(stream, tags);
    // Sender change is never a proofless deposit, so its tags read one stream.
    const sender = await sweepSenderViewTags(
      {
        held: checkViewingPublicKeys(keys, session.staging.identity),
        keys,
        checkpointed: (tag) =>
          sessionCheckpoint(session, "transactions", bytesKey(tag)) !== undefined,
        scan: (senderTags) => scanTags("transactions", senderTags),
        transactions: () => transactions.values(),
      },
      context,
    );

    const scanNullifiers = async (nullifiers: readonly Bytes32[]): Promise<void> => {
      const groups = groupByCheckpoint(nullifiers, (nullifier) =>
        sessionCheckpoint(session, "nullifiers", bytesKey(nullifier)),
      );

      for (const group of groups) {
        for (let offset = 0; offset < group.keys.length; offset += chunkSize) {
          const chunk = group.keys.slice(offset, offset + chunkSize);
          const checkpoint = await collectShieldedTransactionsByNullifiers(
            {
              indexer: input.client,
              chunk,
              pageLimit,
              nextRpcConfig,
              out: transactions,
              checkpoint: group.checkpoint,
            },
            context,
          );
          advanceSessionCheckpoints(session, "nullifiers", chunk, checkpoint);
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
      senderViewTags: sender.matched,
    });
    let registryRefreshed = false;
    if (
      report.unknownAssetIds.length > 0 ||
      report.unknownAssetFields.length > 0 ||
      walletHasUnknownMint(session.staging)
    ) {
      registryRefreshed = true;
      if ((await backfillSessionRegistry(session, input.client, context)) > 0) {
        report = await decryptTransactions({
          wallet: session.staging,
          keys,
          transactions: ordered,
          config: decryptConfig,
          context,
          senderViewTags: sender.matched,
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
        senderViewTags: sender.matched,
      });
      if (
        !registryRefreshed &&
        (report.unknownAssetIds.length > 0 ||
          report.unknownAssetFields.length > 0 ||
          walletHasUnknownMint(session.staging))
      ) {
        if ((await backfillSessionRegistry(session, input.client, context)) > 0) {
          report = await decryptTransactions({
            wallet: session.staging,
            keys,
            transactions: ordered,
            config: decryptConfig,
            context,
            senderViewTags: sender.matched,
          });
        }
      }
    }
    // An unresolved asset means a fetched UTXO was not stored. A commit would
    // advance the checkpoints past it and lose the UTXO until a full rescan.
    if (
      report.unknownAssetIds.length > 0 ||
      report.unknownAssetFields.length > 0 ||
      walletHasUnknownMint(session.staging)
    ) {
      throw new WalletError("WALLET_UNRESOLVED_ASSET", {
        details: { unknownAssetIds: report.unknownAssetIds.map(String) },
      });
    }
    input.wallet._commitSync(sealSyncDelta(session), session.baseRevision);
    return Object.freeze({ ...report, nextSenderTxCount: sender.nextTxCount });
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
