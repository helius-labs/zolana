import type { Address, Bytes16, Bytes32, Bytes33, Signature } from "@zolana/interface";
import {
  P256PublicKey,
  type NullifierKey,
  type ShieldedPublicKey,
  type ViewingKeyLike,
} from "@zolana/keypair";

import { TransactionError } from "../error.js";
import { copy, decodeAddress, equal } from "../internal.js";
import type { IndexedShieldedTransaction, OutputContext } from "../instructions/transact.js";
import { SENDER_SLOT_COUNT } from "../instructions/transact.js";
import {
  EncryptedScheme,
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  confidentialUtxo,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  decryptAnonymous,
  decryptConfidential,
  decryptConfidentialAsSender,
  decryptMerge,
  mergeUtxo,
  prooflessUtxo,
  plaintextTransferUtxos,
  readOutputData,
  splitBundleUtxos,
  type ProoflessOutput,
} from "../serialization/codecs.js";
import { Utxo } from "../utxo.js";
import type { SyncWalletAuthority, WalletSyncMaterial } from "./authority.js";
import { SOL_MINT, type AssetRegistry } from "./asset.js";
import {
  SENDER_HISTORY_ROW_BASE,
  newViewingKeyEntry,
  type AssetBalance,
  type CounterpartyCounter,
  type PrivateTransaction,
  type PrivateTransactionDirection,
  type PrivateTransactionId,
  type PrivateTransactionKind,
  type SyncReport,
  type ViewingKeyEntry,
  type WalletUtxo,
  Wallet,
  hex,
} from "./state.js";

/**
 * Tags queried past each family's stored counter. A counterparty that has run
 * ahead by fewer than this many tags stays reachable on the next sync, so
 * lowering it can strand a wallet behind a fast sender.
 */
export const DEFAULT_TAG_WINDOW = 64n;

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export interface WalletSyncConfig {
  readonly tagWindow?: bigint;
  /** Recorded as `Wallet.lastSynced` once the sync commits, as `Wallet::sync` records `synced_at`. */
  readonly syncedAt?: bigint;
}

/**
 * The three guards `Wallet::sync_with_material_in_place` runs, in its order: a
 * material wrong in more than one way is rejected for the first of them, so the
 * nullifier key is checked after the viewing keys rather than beside the
 * identity it belongs to.
 */
function validateMaterial(wallet: Wallet, material: WalletSyncMaterial): void {
  if (
    !equal(
      material.identity.signingPublicKey.toBytes(),
      wallet.identity.signingPublicKey.toBytes(),
    ) ||
    !equal(material.identity.nullifierPublicKey, wallet.identity.nullifierPublicKey) ||
    !equal(material.identity.viewingPublicKey.toBytes(), wallet.identity.viewingPublicKey.toBytes())
  ) {
    throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
  }
  if (
    !material.viewingKeys.some((key) =>
      equal(key.publicKey().toBytes(), wallet.identity.viewingPublicKey.toBytes()),
    )
  ) {
    throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
  }
  if (!equal(material.nullifierKey.publicKey(), wallet.identity.nullifierPublicKey)) {
    throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
  }
}

/** One output slot of one fetched transaction, by position in both lists. */
interface Site {
  readonly transaction: number;
  readonly slot: number;
}

/**
 * Where each view tag the fetched slots carry can be opened, split the way a
 * wallet reads them: a sender bundle covers the whole transaction, every other
 * scheme is one recipient slot. A transaction no slot of which names a known
 * scheme is unparsed, which is the one count that does not depend on a key.
 */
interface TagIndex {
  readonly senderSites: ReadonlyMap<string, readonly number[]>;
  readonly recipientSites: ReadonlyMap<string, readonly Site[]>;
  readonly unparsedTransactions: number;
}

function pushInto<T>(into: Map<string, T[]>, tag: string, value: T): void {
  const existing = into.get(tag);
  if (existing === undefined) into.set(tag, [value]);
  else existing.push(value);
}

function buildTagIndex(transactions: readonly IndexedShieldedTransaction[]): TagIndex {
  const senderSites = new Map<string, number[]>();
  const recipientSites = new Map<string, Site[]>();
  let unparsedTransactions = 0;
  for (const [transaction, tx] of transactions.entries()) {
    let classified = false;
    for (const [index, slot] of tx.outputSlots.entries()) {
      let scheme: EncryptedScheme;
      try {
        scheme = readOutputData(slot.payload).scheme;
      } catch {
        continue;
      }
      const tag = hex(slot.viewTag);
      if (scheme === EncryptedScheme.anonymousSender || scheme === EncryptedScheme.split) {
        pushInto(senderSites, tag, transaction);
      } else {
        pushInto(recipientSites, tag, { transaction, slot: index });
      }
      classified = true;
    }
    if (!classified) unparsedTransactions++;
  }
  return { senderSites, recipientSites, unparsedTransactions };
}

/**
 * Walk one tag family from `start` in `window`-sized steps, extending as long
 * as a step still hits a slot, and return the highest index that did. A gap
 * shorter than the window never ends the scan, which is what lets a wallet
 * catch up with a counterparty that has run ahead.
 */
function scanStream(
  start: bigint,
  window: bigint,
  derive: (index: bigint) => Bytes32,
  visit: (tag: string) => boolean,
): bigint | undefined {
  let maxPresent: bigint | undefined;
  for (let base = start; ; base += window) {
    const end = base + window > U64_MAX ? U64_MAX : base + window;
    let hit = false;
    for (let n = base; n < end; n++) {
      if (!visit(hex(derive(n)))) continue;
      hit = true;
      maxPresent = n;
    }
    if (!hit || base + window > U64_MAX) return maxPresent;
  }
}

function nextCount(current: bigint, maxPresent: bigint | undefined): bigint {
  return maxPresent === undefined ? current : maxPresent + 1n;
}

function compareBigints(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Addresses order by their 32 bytes, which base58 text does not preserve. */
function compareAssets(left: Address, right: Address): number {
  const leftBytes = hex(decodeAddress(left));
  const rightBytes = hex(decodeAddress(right));
  return leftBytes < rightBytes ? -1 : leftBytes > rightBytes ? 1 : 0;
}

/** A rotated-in viewing key starts scanning from zero. */
function ensureViewingKeyEntries(
  history: readonly ViewingKeyEntry[],
  viewingKeys: readonly ViewingKeyLike[],
): readonly ViewingKeyEntry[] {
  const known = new Set(history.map((entry) => hex(entry.viewingPublicKey.toBytes())));
  const entries = [...history];
  for (const key of viewingKeys) {
    const id = hex(key.publicKey().toBytes());
    if (known.has(id)) continue;
    known.add(id);
    entries.push(newViewingKeyEntry(key.publicKey(), 0n));
  }
  return entries;
}

/** Counters keyed by counterparty, the shape `HashMap<P256Pubkey, u64>` holds. */
class CounterpartyCounters {
  readonly #counters = new Map<string, { counterparty: P256PublicKey; count: bigint }>();

  constructor(known: readonly CounterpartyCounter[]) {
    for (const entry of known) {
      this.#counters.set(hex(entry.counterparty.toBytes()), { ...entry });
    }
  }

  /** Adds a newly seen counterparty at zero, keeping a counter already held. */
  discover(counterparty: P256PublicKey): void {
    const id = hex(counterparty.toBytes());
    if (this.#counters.has(id)) return;
    this.#counters.set(id, { counterparty, count: 0n });
  }

  entries(): readonly CounterpartyCounter[] {
    return [...this.#counters.values()].map((entry) => Object.freeze({ ...entry }));
  }

  advance(scan: (counterparty: P256PublicKey, count: bigint) => bigint | undefined): void {
    // Snapshotted before the walk: a counterparty discovered by one shared-tag
    // scan is only scanned on the next sync, as it is in Rust.
    for (const entry of [...this.#counters.values()]) {
      entry.count = nextCount(entry.count, scan(entry.counterparty, entry.count));
    }
  }
}

/** What one decoded slot revealed about who the wallet transacted with. */
interface SlotOutcome {
  sender?: P256PublicKey;
  recipients: readonly P256PublicKey[];
}

/**
 * The identity of one history row. An indexed transaction carries its
 * signature untyped, so this is the single place the history narrows it.
 */
function historyId(tx: IndexedShieldedTransaction, index: bigint): PrivateTransactionId {
  return { signature: tx.txSignature as Signature, slot: tx.slot, index };
}

function rowKey(row: PrivateTransaction): string {
  return [
    row.id.signature,
    row.id.slot,
    row.id.index,
    row.kind,
    row.direction,
    row.status,
    row.asset,
    row.amount,
    row.counterpartyViewingPublicKey === undefined
      ? ""
      : hex(row.counterpartyViewingPublicKey.toBytes()),
  ].join("|");
}

/**
 * The notes and history rows one sync produces, accumulated across every
 * viewing key the authority supplied. This is the counterpart of Rust
 * `SyncCtx`: it owns the staged wallet contents so a rejection leaves the
 * wallet untouched, and it carries the report counters each decode step
 * advances.
 */
class SyncPass {
  readonly #owner: ShieldedPublicKey;
  readonly #nullifierPublicKey: Bytes32;
  readonly #nullifierKey: NullifierKey;
  readonly #selfViewingPublicKey: P256PublicKey;
  readonly #assets: AssetRegistry;
  readonly #transactions: readonly IndexedShieldedTransaction[];
  readonly #utxos: WalletUtxo[];
  readonly #rows: PrivateTransaction[];
  readonly #rowKeys: Set<string>;
  readonly #outputHashes: Set<string>;
  readonly #processedSlots = new Set<string>();
  readonly #processedOutbound = new Set<number>();
  readonly unknownAssetIds = new Set<bigint>();
  storedUtxos = 0;
  undecryptableCandidates = 0;

  constructor(
    input: Readonly<{
      material: WalletSyncMaterial;
      assets: AssetRegistry;
      transactions: readonly IndexedShieldedTransaction[];
      utxos: readonly WalletUtxo[];
      rows: readonly PrivateTransaction[];
    }>,
  ) {
    this.#owner = input.material.identity.signingPublicKey;
    this.#nullifierPublicKey = input.material.identity.nullifierPublicKey;
    this.#nullifierKey = input.material.nullifierKey;
    this.#selfViewingPublicKey = input.material.identity.viewingPublicKey;
    this.#assets = input.assets;
    this.#transactions = input.transactions;
    this.#utxos = [...input.utxos];
    this.#rows = [...input.rows];
    this.#rowKeys = new Set(this.#rows.map(rowKey));
    this.#outputHashes = new Set(this.#utxos.map((entry) => hex(entry.outputContext.hash)));
  }

  utxos(): readonly WalletUtxo[] {
    return this.#utxos;
  }

  rows(): readonly PrivateTransaction[] {
    return this.#rows;
  }

  #store(
    utxo: Utxo,
    outputContext: OutputContext,
    dataHash: Bytes32 | undefined,
    zoneDataHash: Bytes32 | undefined,
  ): void {
    if (!equal(utxo.owner.toBytes(), this.#owner.toBytes())) return;
    const outputId = hex(outputContext.hash);
    if (this.#outputHashes.has(outputId)) return;
    this.#utxos.push(
      Object.freeze({
        utxo,
        outputContext: Object.freeze({
          hash: copy(outputContext.hash),
          tree: outputContext.tree,
          leafIndex: outputContext.leafIndex,
        }),
        nullifier: utxo.nullifier(outputContext.hash, this.#nullifierKey),
        ...(dataHash === undefined ? {} : { dataHash }),
        ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
        spent: false,
      }),
    );
    this.#outputHashes.add(outputId);
    this.storedUtxos++;
  }

  /**
   * Store a note whose slot is not known in advance, by finding the slot whose
   * committed leaf its hash reproduces. The sender-side bundles carry their
   * change this way: one bundle describes several outputs spread across the
   * transaction.
   */
  #storeInTx(utxo: Utxo, tx: IndexedShieldedTransaction): void {
    const hash = utxo.hash(this.#nullifierPublicKey);
    const slot = tx.outputSlots.find((candidate) => equal(candidate.outputContext.hash, hash));
    if (slot === undefined) {
      this.undecryptableCandidates++;
      return;
    }
    this.#store(utxo, slot.outputContext, undefined, undefined);
  }

  /** Verify each 1:1 recipient note against the slot's committed leaf and store it. */
  #storeRecipientUtxos(
    utxos: readonly Utxo[],
    outputContext: OutputContext,
    dataHash: Bytes32 | undefined,
    zoneDataHash: Bytes32 | undefined,
  ): boolean {
    let stored = false;
    for (const utxo of utxos) {
      if (!equal(utxo.hash(this.#nullifierPublicKey, dataHash, zoneDataHash), outputContext.hash)) {
        this.undecryptableCandidates++;
        continue;
      }
      this.#store(utxo, outputContext, dataHash, zoneDataHash);
      stored = true;
    }
    return stored;
  }

  #record(row: PrivateTransaction): void {
    const key = rowKey(row);
    if (this.#rowKeys.has(key)) return;
    this.#rowKeys.add(key);
    this.#rows.push(Object.freeze({ ...row, id: Object.freeze({ ...row.id }) }));
  }

  /**
   * Record a candidate that failed to become notes. When the failure was an
   * unknown asset id, remember the id so the client sync layer can backfill the
   * registry and retry; that is the single seam where a stale registry surfaces
   * during decode.
   */
  #noteUndecryptable(error: unknown): void {
    if (error instanceof TransactionError && error.code === "TRANSACTION_UNKNOWN_ASSET") {
      const assetId = error.details?.["assetId"];
      if (typeof assetId === "string" && /^\d+$/u.test(assetId)) {
        this.unknownAssetIds.add(BigInt(assetId));
      }
    }
    this.undecryptableCandidates++;
  }

  #spentAmounts(nullifiers: readonly Bytes32[]): ReadonlyMap<Address, bigint> {
    const spent = new Set(nullifiers.map(hex));
    const byAsset = new Map<Address, bigint>();
    for (const entry of this.#utxos) {
      if (!spent.has(hex(entry.nullifier))) continue;
      const total = (byAsset.get(entry.utxo.asset) ?? 0n) + entry.utxo.amount;
      if (total > U64_MAX) throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
      byAsset.set(entry.utxo.asset, total);
    }
    return byAsset;
  }

  #recordReceived(
    tx: IndexedShieldedTransaction,
    slotIndex: number,
    sender: P256PublicKey | undefined,
    utxo: Utxo,
  ): void {
    const direction: PrivateTransactionDirection =
      sender !== undefined && equal(sender.toBytes(), this.#selfViewingPublicKey.toBytes())
        ? "selfTransfer"
        : "inbound";
    this.#record({
      id: historyId(tx, tx.outputSlots[slotIndex]?.outputContext.leafIndex ?? BigInt(slotIndex)),
      kind: "privateTransfer",
      direction,
      status: "confirmed",
      asset: utxo.asset,
      amount: utxo.amount,
      ...(sender === undefined ? {} : { counterpartyViewingPublicKey: sender }),
    });
  }

  #recordDeposit(tx: IndexedShieldedTransaction, outputContext: OutputContext, utxo: Utxo): void {
    this.#record({
      id: historyId(tx, outputContext.leafIndex),
      kind: "deposit",
      direction: "inbound",
      status: "confirmed",
      asset: utxo.asset,
      amount: utxo.amount,
    });
  }

  /**
   * One row per asset the transaction moved out, netted down by the change it
   * paid back to this wallet. A row whose net is zero is dropped but still
   * consumes its row index, so the surviving rows keep the indices they had.
   */
  #recordOutboundTransfer(
    tx: IndexedShieldedTransaction,
    spent: ReadonlyMap<Address, bigint>,
    change: readonly Utxo[],
    kind: PrivateTransactionKind,
    counterparty: P256PublicKey | undefined,
  ): void {
    const byAsset = new Map(spent);
    for (const utxo of change) {
      const total = byAsset.get(utxo.asset);
      if (total === undefined) continue;
      byAsset.set(utxo.asset, total > utxo.amount ? total - utxo.amount : 0n);
    }
    [...byAsset]
      .sort(([left], [right]) => compareAssets(left, right))
      .forEach(([asset, amount], row) => {
        if (amount === 0n) return;
        this.#record({
          id: historyId(tx, SENDER_HISTORY_ROW_BASE + BigInt(row)),
          kind,
          direction: "outbound",
          status: "confirmed",
          asset,
          amount,
          ...(counterparty === undefined ? {} : { counterpartyViewingPublicKey: counterparty }),
        });
      });
  }

  /** A split pays nobody, so every asset it spent stays with the wallet. */
  #recordSplit(tx: IndexedShieldedTransaction, spent: ReadonlyMap<Address, bigint>): void {
    [...spent]
      .sort(([left], [right]) => compareAssets(left, right))
      .forEach(([asset, amount], row) => {
        if (amount === 0n) return;
        this.#record({
          id: historyId(tx, SENDER_HISTORY_ROW_BASE + BigInt(row)),
          kind: "split",
          direction: "selfTransfer",
          status: "confirmed",
          asset,
          amount,
        });
      });
  }

  #recordMerge(tx: IndexedShieldedTransaction, outputContext: OutputContext, utxo: Utxo): void {
    this.#record({
      id: historyId(tx, outputContext.leafIndex),
      kind: "merge",
      direction: "selfTransfer",
      status: "confirmed",
      asset: utxo.asset,
      amount: utxo.amount,
    });
  }

  /**
   * Whether `key` is the viewing key that authored `tx`: the transaction
   * viewing key derived from the first nullifier reproduces the published one
   * only for the spending wallet.
   */
  #authored(tx: IndexedShieldedTransaction, key: ViewingKeyLike): boolean {
    const firstNullifier = tx.nullifiers[0];
    if (tx.txViewingPublicKey === undefined || firstNullifier === undefined) return false;
    return equal(
      key.transactionViewingKey(firstNullifier).publicKey().toBytes(),
      tx.txViewingPublicKey.toBytes(),
    );
  }

  /**
   * Reconstruct the outbound history of a confidential transfer the wallet
   * authored. The unified scheme carries no sender-side recipient list, so the
   * author re-derives the transaction viewing key and decrypts every output
   * slot with it: change slots net the spent inputs down, recipient slots
   * reveal the counterparties. Dummy slots fail the decrypt and are skipped.
   */
  recordConfidentialSend(
    tx: IndexedShieldedTransaction,
    index: number,
    key: ViewingKeyLike,
    knownRecipients: CounterpartyCounters,
  ): void {
    const firstNullifier = tx.nullifiers[0];
    const salt = tx.salt;
    if (tx.txViewingPublicKey === undefined || firstNullifier === undefined || salt === undefined) {
      return;
    }
    const txKey = key.transactionViewingKey(firstNullifier);
    if (!equal(txKey.publicKey().toBytes(), tx.txViewingPublicKey.toBytes())) return;
    if (this.#processedOutbound.has(index)) return;
    this.#processedOutbound.add(index);

    const change: Utxo[] = [];
    const recipientKeys: P256PublicKey[] = [];
    tx.outputSlots.forEach((slot, position) => {
      try {
        const frame = readOutputData(slot.payload);
        if (frame.encoding !== "encrypted" || frame.scheme !== EncryptedScheme.confidential) return;
        const plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, position);
        if (position < SENDER_SLOT_COUNT) {
          change.push(confidentialUtxo(plaintext, this.#owner, this.#assets));
        } else {
          // Each recipient slot stays sealed to its recipient, so the key
          // prefixed to the ciphertext is the one thing the sender reads out.
          recipientKeys.push(P256PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33));
        }
      } catch {
        // A dummy slot fails the transaction-key decrypt; skip it.
      }
    });

    const kind = recipientKeys.length === 0 ? "publicWithdrawal" : "privateTransfer";
    this.#recordOutboundTransfer(
      tx,
      this.#spentAmounts(tx.nullifiers),
      change,
      kind,
      recipientKeys.length === 1 ? recipientKeys[0] : undefined,
    );
    for (const recipient of recipientKeys) knownRecipients.discover(recipient);
  }

  /**
   * Decode one candidate slot, dispatching on its encoding and scheme byte.
   * Recipient and confidential slots are 1:1 and verified against the slot's
   * committed leaf; the anonymous and split sender bundles, passed as slot 0,
   * store their change against the whole transaction.
   */
  decodeSlot(key: ViewingKeyLike, site: Site): SlotOutcome {
    const outcome: SlotOutcome = { recipients: [] };
    const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
    if (this.#processedSlots.has(siteKey)) return outcome;
    const tx = this.#transactions[site.transaction];
    const slot = tx?.outputSlots[site.slot];
    if (tx === undefined || slot === undefined) {
      this.undecryptableCandidates++;
      return outcome;
    }
    let frame: ReturnType<typeof readOutputData>;
    try {
      frame = readOutputData(slot.payload);
    } catch {
      this.undecryptableCandidates++;
      return outcome;
    }
    const { outputContext } = slot;
    const { body } = frame;

    if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.proofless) {
      let deposit: ProoflessOutput;
      let utxo: Utxo;
      try {
        deposit = decodeProofless(body);
        utxo = prooflessUtxo(deposit, this.#owner);
      } catch {
        this.undecryptableCandidates++;
        return outcome;
      }
      if (
        this.#storeRecipientUtxos([utxo], outputContext, deposit.dataHash, deposit.zoneDataHash)
      ) {
        this.#processedSlots.add(siteKey);
        this.#recordDeposit(tx, outputContext, utxo);
      }
      return outcome;
    }

    if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.plaintextTransfer) {
      let utxos: readonly Utxo[];
      try {
        utxos = plaintextTransferUtxos(decodePlaintextTransfer(body), this.#assets, SOL_MINT);
      } catch (error) {
        this.#noteUndecryptable(error);
        return outcome;
      }
      for (const utxo of utxos) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      return outcome;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousRecipient) {
      let sender: P256PublicKey;
      let utxo: Utxo;
      try {
        const plaintext = decodeAnonymousRecipient(this.#decryptFor(key, tx, body, site.slot));
        sender = plaintext.senderPublicKey;
        utxo = anonymousRecipientUtxo(plaintext, this.#assets);
      } catch (error) {
        this.#noteUndecryptable(error);
        return outcome;
      }
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        outcome.sender = sender;
        this.#recordReceived(tx, site.slot, sender, utxo);
      }
      return outcome;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.confidential) {
      let utxo: Utxo;
      try {
        const { txViewingPublicKey, salt } = this.#envelope(tx);
        utxo = confidentialUtxo(
          decryptConfidential(key, txViewingPublicKey, body, salt, site.slot),
          this.#owner,
          this.#assets,
        );
      } catch (error) {
        this.#noteUndecryptable(error);
        return outcome;
      }
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        // A slot the wallet itself authored is its own change or self-send
        // output; its outbound history is recorded once per transaction by
        // `recordConfidentialSend`, so it must not also be logged here as an
        // inbound receipt.
        if (!this.#authored(tx, key)) this.#recordReceived(tx, site.slot, undefined, utxo);
      }
      return outcome;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousSender) {
      let recipients: readonly P256PublicKey[];
      let change: readonly Utxo[];
      try {
        const plaintext = decodeAnonymousSender(this.#decryptFor(key, tx, body, site.slot));
        recipients = plaintext.recipientViewingPublicKeys;
        change = anonymousSenderUtxos(plaintext, this.#assets, SOL_MINT);
      } catch (error) {
        this.#noteUndecryptable(error);
        return outcome;
      }
      for (const utxo of change) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      outcome.recipients = recipients;
      if (!this.#processedOutbound.has(site.transaction)) {
        this.#processedOutbound.add(site.transaction);
        const kind = recipients.length === 0 ? "publicWithdrawal" : "privateTransfer";
        this.#recordOutboundTransfer(
          tx,
          this.#spentAmounts(tx.nullifiers),
          change,
          kind,
          recipients.length === 1 ? recipients[0] : undefined,
        );
      }
      return outcome;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.split) {
      let utxos: readonly Utxo[];
      try {
        const { txViewingPublicKey, salt } = this.#envelope(tx);
        utxos = splitBundleUtxos(
          decodeSplitBundle(key.decryptUtxo(body, txViewingPublicKey, salt, site.slot)),
          this.#assets,
        );
      } catch (error) {
        this.#noteUndecryptable(error);
        return outcome;
      }
      for (const utxo of utxos) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      if (!this.#processedOutbound.has(site.transaction)) {
        this.#processedOutbound.add(site.transaction);
        this.#recordSplit(tx, this.#spentAmounts(tx.nullifiers));
      }
      return outcome;
    }

    if (frame.encoding === "verifiable" && frame.scheme === EncryptedScheme.merge) {
      let utxo: Utxo;
      try {
        utxo = mergeUtxo(decryptMerge(key, body), this.#owner, this.#assets);
      } catch {
        this.undecryptableCandidates++;
        return outcome;
      }
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        this.#recordMerge(tx, outputContext, utxo);
      }
      return outcome;
    }

    this.undecryptableCandidates++;
    return outcome;
  }

  /** The published transaction key and salt every encrypted scheme opens under. */
  #envelope(
    tx: IndexedShieldedTransaction,
  ): Readonly<{ txViewingPublicKey: P256PublicKey; salt: Bytes16 }> {
    if (tx.txViewingPublicKey === undefined || tx.salt === undefined) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "envelope" });
    }
    return { txViewingPublicKey: tx.txViewingPublicKey, salt: tx.salt };
  }

  #decryptFor(
    key: ViewingKeyLike,
    tx: IndexedShieldedTransaction,
    body: Uint8Array,
    slotIndex: number,
  ): Uint8Array {
    const { txViewingPublicKey, salt } = this.#envelope(tx);
    return decryptAnonymous(key, txViewingPublicKey, body, salt, slotIndex);
  }

  /**
   * Walk every tag family of one viewing key over the fetched slots, in the
   * order Rust walks them: the bootstrap and owner tags first, because what
   * they open names the counterparties whose shared tags are scanned after.
   */
  advance(
    entry: ViewingKeyEntry,
    key: ViewingKeyLike,
    input: Readonly<{ window: bigint; index: TagIndex; ownerTag: Bytes32 }>,
  ): ViewingKeyEntry {
    const { window, index } = input;
    const knownSenders = new CounterpartyCounters(entry.knownSenders);
    const knownRecipients = new CounterpartyCounters(entry.knownRecipients);
    const recipientSites = (tag: string): readonly Site[] => index.recipientSites.get(tag) ?? [];

    for (const site of recipientSites(hex(key.recipientBootstrapViewTag()))) {
      const { sender } = this.decodeSlot(key, site);
      if (sender !== undefined) knownSenders.discover(sender);
    }
    const ownerTag = hex(input.ownerTag);
    for (const site of recipientSites(ownerTag)) this.decodeSlot(key, site);
    for (const transaction of index.senderSites.get(ownerTag) ?? []) {
      this.decodeSlot(key, { transaction, slot: 0 });
    }

    const txCount = nextCount(
      entry.txCount,
      scanStream(
        entry.txCount,
        window,
        (n) => key.senderViewTag(n),
        (tag) => {
          const sites = index.senderSites.get(tag);
          if (sites === undefined) return false;
          for (const transaction of sites) {
            for (const recipient of this.decodeSlot(key, { transaction, slot: 0 }).recipients) {
              knownRecipients.discover(recipient);
            }
          }
          return true;
        },
      ),
    );

    const requestCount = nextCount(
      entry.requestCount,
      scanStream(
        entry.requestCount,
        window,
        (n) => key.recipientRequestViewTag(n),
        (tag) => {
          const sites = index.recipientSites.get(tag);
          if (sites === undefined) return false;
          for (const site of sites) {
            const { sender } = this.decodeSlot(key, site);
            if (sender !== undefined) knownSenders.discover(sender);
          }
          return true;
        },
      ),
    );

    knownSenders.advance((counterparty, count) =>
      scanStream(
        count,
        window,
        (n) => key.recipientSharedViewTag(counterparty, n),
        (tag) => {
          const sites = index.recipientSites.get(tag);
          if (sites === undefined) return false;
          for (const site of sites) this.decodeSlot(key, site);
          return true;
        },
      ),
    );

    this.#transactions.forEach((tx, position) => {
      this.recordConfidentialSend(tx, position, key, knownRecipients);
    });

    knownRecipients.advance((counterparty, count) =>
      scanStream(
        count,
        window,
        (n) => key.sendSharedViewTag(counterparty, n),
        (tag) => index.recipientSites.has(tag),
      ),
    );

    return Object.freeze({
      ...entry,
      txCount,
      requestCount,
      knownSenders: knownSenders.entries(),
      knownRecipients: knownRecipients.entries(),
    });
  }
}

/**
 * `Wallet::sync`: read the authority's sync material once, then scan. A free
 * function because `Wallet` is declared in `state.js`, which this scan imports,
 * and qualified because `@zolana/wallet` already carries Rust's `sync_wallet`
 * under the unqualified name.
 */
export async function syncWalletWithAuthority(
  input: Readonly<{
    wallet: Wallet;
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    config?: WalletSyncConfig;
  }>,
): Promise<SyncReport> {
  return syncWalletWithMaterial({ ...input, material: await input.authority.syncMaterial() });
}

/**
 * `Wallet::sync_with_material`, for a caller already holding the material.
 * Rust stages the scan on a clone and commits it only on success; here every
 * mutation is deferred to the single `_replace` at the end, so a throw leaves
 * the wallet as it was.
 */
export function syncWalletWithMaterial(
  input: Readonly<{
    wallet: Wallet;
    material: WalletSyncMaterial;
    transactions: readonly IndexedShieldedTransaction[];
    config?: WalletSyncConfig;
  }>,
): SyncReport {
  const window = input.config?.tagWindow ?? DEFAULT_TAG_WINDOW;
  if (window <= 0n) {
    throw new TransactionError("TRANSACTION_INVALID_TAG_WINDOW");
  }
  const { material } = input;
  validateMaterial(input.wallet, material);
  const current = input.wallet._state();
  const index = buildTagIndex(input.transactions);
  const pass = new SyncPass({
    material,
    assets: input.wallet.registry,
    transactions: input.transactions,
    utxos: current.utxos,
    rows: current.transactions,
  });
  const ownerTag = material.identity.signingPublicKey.confidentialViewTag();

  const viewingKeyHistory = ensureViewingKeyEntries(
    current.viewingKeyHistory,
    material.viewingKeys,
  ).map((entry) => {
    const id = hex(entry.viewingPublicKey.toBytes());
    const key = material.viewingKeys.find(
      (candidate) => hex(candidate.publicKey().toBytes()) === id,
    );
    return key === undefined ? entry : pass.advance(entry, key, { window, index, ownerTag });
  });

  const nullifiers = new Set(current.nullifiers);
  for (const tx of input.transactions) {
    for (const nullifier of tx.nullifiers) nullifiers.add(hex(nullifier));
  }
  const utxos = pass
    .utxos()
    .map((entry) =>
      entry.spent || !nullifiers.has(hex(entry.nullifier))
        ? entry
        : Object.freeze({ ...entry, spent: true }),
    );
  const transactions = [...pass.rows()].sort(
    (left, right) =>
      compareBigints(left.id.slot, right.id.slot) ||
      left.id.signature.localeCompare(right.id.signature) ||
      compareBigints(left.id.index, right.id.index),
  );

  input.wallet._replace({
    utxos,
    transactions,
    nullifiers,
    viewingKeyHistory,
    lastSynced: input.config?.syncedAt ?? 0n,
  });
  return Object.freeze({
    storedUtxos: pass.storedUtxos,
    unparsedTransactions: index.unparsedTransactions,
    undecryptableCandidates: pass.undecryptableCandidates,
    unknownAssetIds: [...pass.unknownAssetIds].sort((left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  });
}

export async function syncWalletWorkerEquivalent(
  input: Parameters<typeof syncWalletWithAuthority>[0],
): Promise<SyncReport> {
  return syncWalletWithAuthority(input);
}

/**
 * `decrypt_transactions`: the balances a fresh wallet holds after scanning
 * these transactions, with nothing kept. The identity comes off the sync
 * material rather than a separate authority call, which is the same value from
 * the one capability the scan already needs.
 */
export async function decryptTransactions(
  input: Readonly<{
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    registry: AssetRegistry;
    config?: WalletSyncConfig;
  }>,
): Promise<readonly AssetBalance[]> {
  const material = await input.authority.syncMaterial();
  const wallet = new Wallet({ identity: material.identity, registry: input.registry });
  syncWalletWithMaterial({ ...input, wallet, material });
  return wallet.balances(false);
}
