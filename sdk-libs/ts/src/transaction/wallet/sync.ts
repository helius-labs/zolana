import type { Address, Bytes16, Bytes32, Bytes33 } from "../../interface/types.js";
import type { NullifierKey } from "../../keypair/nullifier-key.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import { P256PublicKey, type ShieldedPublicKey } from "../../keypair/public-key.js";
import type { ShieldedKeypair, ViewingKeyLike } from "../../keypair/shielded.js";

import { initializePoseidon } from "../../hasher/index.js";
import { TransactionError } from "../error.js";
import { copy, decodeAddress, equal } from "../internal.js";
import { SENDER_SLOT_COUNT } from "../instructions/transact.js";
import type { IndexedShieldedTransaction, OutputContext } from "../instructions/transact.js";
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
  prooflessUtxo,
  plaintextTransferUtxos,
  readOutputData,
  splitBundleUtxos,
  type ProoflessOutput,
} from "../serialization/codecs.js";
import { decodeRingDepositOutput, decryptRingDepositUtxo } from "../serialization/ring-deposit.js";
import { Utxo } from "../utxo.js";
import type { SyncWalletAuthority, WalletSyncMaterial } from "./authority.js";
import { SOL_MINT, type AssetRegistry } from "../asset.js";
import {
  SENDER_HISTORY_ROW_BASE,
  newViewingKeyEntry,
  type AssetBalance,
  type Filter,
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

const U64_MAX = 0xffff_ffff_ffff_ffffn;

interface DecryptTransactionsConfig {
  /** Recorded as `Wallet.lastSynced` once the sync commits, as `Wallet::sync` records `synced_at`. */
  readonly syncedAt?: bigint;
}

export interface PrivateBalances {
  balance(mint: Address, filter?: Filter): AssetBalance;
  balances(skipUtxos?: boolean): readonly AssetBalance[];
}

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
  if (!equal(material.nullifierKey.publicKey(), material.identity.nullifierPublicKey)) {
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
    if (!tx.proofless && tx.txViewingPublicKey === undefined && tx.salt === undefined) {
      for (const [index, slot] of tx.outputSlots.entries()) {
        pushInto(recipientSites, hex(slot.viewTag), { transaction, slot: index });
        classified = true;
      }
      if (!classified) unparsedTransactions++;
      continue;
    }
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

function compareBigints(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Addresses order by their 32 bytes, which base58 text does not preserve. */
function compareAssets(left: Address, right: Address): number {
  const leftBytes = hex(decodeAddress(left));
  const rightBytes = hex(decodeAddress(right));
  return leftBytes < rightBytes ? -1 : leftBytes > rightBytes ? 1 : 0;
}

/** Retain every viewing key the authority can still use after rotation. */
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

/** Whether the kept outputs account for every asset the transaction spent. */
function covered(spent: ReadonlyMap<Address, bigint>, kept: readonly Utxo[]): boolean {
  if (spent.size === 0) return false;
  const byAsset = new Map<Address, bigint>();
  for (const utxo of kept) byAsset.set(utxo.asset, (byAsset.get(utxo.asset) ?? 0n) + utxo.amount);
  return [...spent].every(([asset, amount]) => (byAsset.get(asset) ?? 0n) >= amount);
}

function historyId(tx: IndexedShieldedTransaction, index: bigint): PrivateTransactionId {
  return { signature: tx.txSignature, slot: tx.slot, index };
}

function rowKey(row: PrivateTransaction): string {
  return [
    row.id.signature,
    row.id.slot,
    row.id.index,
    row.kind,
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
  /**
   * Every viewing key this wallet has held, current and rotated-out, as hex
   * ids. A transfer addressed to a retired key is still addressed to this
   * wallet, so self-recognition must not narrow to the current key.
   */
  readonly #selfViewingPublicKeys: ReadonlySet<string>;
  readonly #assets: AssetRegistry;
  readonly #transactions: readonly IndexedShieldedTransaction[];
  readonly #utxos: WalletUtxo[];
  readonly #rows: PrivateTransaction[];
  readonly #rowIndexes: Map<string, number>;
  readonly #outputHashes: Set<string>;
  readonly #processedSlots = new Set<string>();
  readonly #processedOutbound = new Set<number>();
  readonly #unknownAssetsBySite = new Map<
    string,
    Readonly<{ ids: Set<bigint>; fields: Map<string, Bytes32> }>
  >();
  storedUtxos = 0;
  undecryptableCandidates = 0;

  constructor(
    input: Readonly<{
      material: WalletSyncMaterial;
      assets: AssetRegistry;
      transactions: readonly IndexedShieldedTransaction[];
      utxos: readonly WalletUtxo[];
      rows: readonly PrivateTransaction[];
      selfViewingPublicKeys: readonly P256PublicKey[];
    }>,
  ) {
    this.#owner = input.material.identity.signingPublicKey;
    this.#nullifierPublicKey = input.material.identity.nullifierPublicKey;
    this.#nullifierKey = input.material.nullifierKey;
    this.#selfViewingPublicKeys = new Set(
      input.selfViewingPublicKeys.map((key) => hex(key.toBytes())),
    );
    this.#assets = input.assets;
    this.#transactions = input.transactions;
    this.#utxos = [...input.utxos];
    this.#rows = [];
    this.#rowIndexes = new Map();
    for (const row of input.rows) this.#record(row);
    this.#outputHashes = new Set(this.#utxos.map((entry) => hex(entry.outputContext.hash)));
  }

  utxos(): readonly WalletUtxo[] {
    return this.#utxos;
  }

  rows(): readonly PrivateTransaction[] {
    return this.#rows;
  }

  unknownAssetIds(): readonly bigint[] {
    const ids = new Set<bigint>();
    for (const candidate of this.#unknownAssetsBySite.values()) {
      for (const id of candidate.ids) ids.add(id);
    }
    return [...ids].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  }

  unknownAssetFields(): readonly Bytes32[] {
    const fields = new Map<string, Bytes32>();
    for (const candidate of this.#unknownAssetsBySite.values()) {
      for (const [key, field] of candidate.fields) fields.set(key, field);
    }
    return [...fields.values()]
      .map((field) => new Uint8Array(field) as Bytes32)
      .sort((left, right) => {
        const leftKey = hex(left);
        const rightKey = hex(right);
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
      });
  }

  #store(
    utxo: Utxo,
    outputContext: OutputContext,
    dataHash: Bytes32 | undefined,
    ringDataHash: Bytes32 | undefined,
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
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
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
    ringDataHash: Bytes32 | undefined,
  ): boolean {
    let stored = false;
    for (const utxo of utxos) {
      if (!equal(utxo.hash(this.#nullifierPublicKey, dataHash, ringDataHash), outputContext.hash)) {
        this.undecryptableCandidates++;
        continue;
      }
      this.#store(utxo, outputContext, dataHash, ringDataHash);
      stored = true;
    }
    return stored;
  }

  #record(row: PrivateTransaction): void {
    const key = rowKey(row);
    const snapshot = Object.freeze({ ...row, id: Object.freeze({ ...row.id }) });
    const existing = this.#rowIndexes.get(key);
    if (existing === undefined) {
      this.#rowIndexes.set(key, this.#rows.length);
      this.#rows.push(snapshot);
    } else {
      this.#rows[existing] = snapshot;
    }
  }

  /**
   * Record a candidate that failed to become notes. When the failure was an
   * unknown asset id, remember the id so the client sync layer can backfill the
   * registry and retry; that is the single seam where a stale registry surfaces
   * during decode.
   */
  #noteUndecryptable(error: unknown, siteKey: string): void {
    if (error instanceof TransactionError) {
      let candidate = this.#unknownAssetsBySite.get(siteKey);
      const assetCandidate = (): Readonly<{
        ids: Set<bigint>;
        fields: Map<string, Bytes32>;
      }> => {
        if (candidate !== undefined) return candidate;
        candidate = { ids: new Set(), fields: new Map() };
        this.#unknownAssetsBySite.set(siteKey, candidate);
        return candidate;
      };
      if (error.code === "TRANSACTION_UNKNOWN_ASSET") {
        const assetId = error.details?.["assetId"];
        if (typeof assetId === "string" && /^\d+$/u.test(assetId)) {
          assetCandidate().ids.add(BigInt(assetId));
        }
      } else if (error.code === "TRANSACTION_UNKNOWN_ASSET_FIELD") {
        const value = error.details?.["assetField"];
        if (
          Array.isArray(value) &&
          value.length === 32 &&
          value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
        ) {
          const field = new Uint8Array(value as number[]) as Bytes32;
          assetCandidate().fields.set(hex(field), field);
        }
      }
    }
    this.undecryptableCandidates++;
  }

  #resolveAssetCandidate(siteKey: string): void {
    this.#unknownAssetsBySite.delete(siteKey);
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
      sender !== undefined && this.#isSelf(sender) ? "selfTransfer" : "inbound";
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
   * A transfer whose every real recipient is this wallet moved nothing out, so
   * it is a self transfer on any rail. An empty recipient set stays outbound:
   * that is a public withdrawal, and the value did leave.
   */
  #transferDirection(recipients: readonly P256PublicKey[]): PrivateTransactionDirection {
    return recipients.length > 0 && recipients.every((recipient) => this.#isSelf(recipient))
      ? "selfTransfer"
      : "outbound";
  }

  #isSelf(viewingPublicKey: P256PublicKey): boolean {
    return this.#selfViewingPublicKeys.has(hex(viewingPublicKey.toBytes()));
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
    direction: PrivateTransactionDirection,
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
          direction,
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
    const txKey = key.transactionViewingKey(firstNullifier);
    try {
      return equal(txKey.publicKey().toBytes(), tx.txViewingPublicKey.toBytes());
    } finally {
      txKey.destroy();
    }
  }

  /** The embedded viewing key and committed UTXO identify change. */
  recordConfidentialSend(tx: IndexedShieldedTransaction, index: number, key: ViewingKeyLike): void {
    const firstNullifier = tx.nullifiers[0];
    const salt = tx.salt;
    if (tx.txViewingPublicKey === undefined || firstNullifier === undefined || salt === undefined) {
      return;
    }
    const txKey = key.transactionViewingKey(firstNullifier);
    if (!equal(txKey.publicKey().toBytes(), tx.txViewingPublicKey.toBytes())) {
      txKey.destroy();
      return;
    }
    if (this.#processedOutbound.has(index)) {
      txKey.destroy();
      return;
    }
    this.#processedOutbound.add(index);
    try {
      this.#decodeOutboundSlots(tx, txKey, salt);
    } finally {
      txKey.destroy();
    }
  }

  #decodeOutboundSlots(
    tx: IndexedShieldedTransaction,
    txKey: ReturnType<ViewingKeyLike["transactionViewingKey"]>,
    salt: Bytes16,
  ): void {
    const change: Utxo[] = [];
    const recipientKeys: P256PublicKey[] = [];
    tx.outputSlots.forEach((slot, position) => {
      try {
        const frame = readOutputData(slot.payload);
        if (
          frame.encoding !== "encrypted" ||
          (frame.scheme !== EncryptedScheme.confidential &&
            frame.scheme !== EncryptedScheme.ringConfidential)
        ) {
          return;
        }
        const plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, position);
        const recipientKey = P256PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33);
        if (position < SENDER_SLOT_COUNT) {
          const candidate = confidentialUtxo(plaintext, this.#owner, this.#assets);
          if (
            this.#isSelf(recipientKey) &&
            equal(candidate.hash(this.#nullifierPublicKey), slot.outputContext.hash)
          ) {
            change.push(candidate);
            return;
          }
        }
        recipientKeys.push(recipientKey);
      } catch {
        // A dummy slot fails the transaction-key decrypt; skip it.
      }
    });

    const spent = this.#spentAmounts(tx.nullifiers);
    // Paying yourself keeps every output, so nothing distinguishes it from
    // change except that the change covers the whole spend.
    if (recipientKeys.length === 0 && covered(spent, change)) {
      this.#recordSplit(tx, spent);
      return;
    }
    const kind = recipientKeys.length === 0 ? "publicWithdrawal" : "privateTransfer";
    this.#recordOutboundTransfer(
      tx,
      spent,
      change,
      kind,
      recipientKeys.length === 1 ? recipientKeys[0] : undefined,
      this.#transferDirection(recipientKeys),
    );
  }

  /**
   * Decode one candidate slot, dispatching on its encoding and scheme byte.
   * Recipient and confidential slots are 1:1 and verified against the slot's
   * committed leaf; the anonymous and split sender bundles, passed as slot 0,
   * store their change against the whole transaction.
   */
  decodeSlot(key: ViewingKeyLike, site: Site): void {
    const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
    if (this.#processedSlots.has(siteKey)) return;
    const tx = this.#transactions[site.transaction];
    const slot = tx?.outputSlots[site.slot];
    if (tx === undefined || slot === undefined) {
      this.undecryptableCandidates++;
      return;
    }
    if (!tx.proofless && tx.txViewingPublicKey === undefined && tx.salt === undefined) {
      this.#reconstructMerge(tx, site, siteKey);
      return;
    }
    let frame: ReturnType<typeof readOutputData>;
    try {
      frame = readOutputData(slot.payload);
    } catch {
      this.undecryptableCandidates++;
      return;
    }
    const { outputContext } = slot;
    const { body } = frame;

    if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.proofless) {
      let deposit: ProoflessOutput;
      let utxo: Utxo;
      try {
        deposit = decodeProofless(body);
        utxo = prooflessUtxo(deposit, this.#owner);
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      if (
        this.#storeRecipientUtxos([utxo], outputContext, deposit.dataHash, deposit.ringDataHash)
      ) {
        this.#processedSlots.add(siteKey);
        this.#recordDeposit(tx, outputContext, utxo);
      }
      return;
    }

    if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.plaintextTransfer) {
      let utxos: readonly Utxo[];
      try {
        utxos = plaintextTransferUtxos(decodePlaintextTransfer(body), this.#assets, SOL_MINT);
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      for (const utxo of utxos) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      return;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousRecipient) {
      let sender: P256PublicKey;
      let utxo: Utxo;
      try {
        const plaintext = decodeAnonymousRecipient(this.#decryptFor(key, tx, body, site.slot));
        sender = plaintext.senderPublicKey;
        utxo = anonymousRecipientUtxo(plaintext, this.#assets);
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        // Per-slot, unlike the confidential rail, which suppresses an authored
        // slot's receipt: an anonymous recipient slot names its sender, so a
        // self-send's receipt carries the sender the sender-bundle row cannot
        // show per recipient.
        this.#recordReceived(tx, site.slot, sender, utxo);
      }
      return;
    }

    if (
      frame.encoding === "encrypted" &&
      (frame.scheme === EncryptedScheme.confidential ||
        frame.scheme === EncryptedScheme.ringConfidential)
    ) {
      let utxo: Utxo;
      try {
        const { txViewingPublicKey, salt } = this.#envelope(tx);
        utxo = confidentialUtxo(
          decryptConfidential(key, txViewingPublicKey, body, salt, site.slot),
          this.#owner,
          this.#assets,
        );
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        // A slot the wallet itself authored is its own change or self-send
        // output; its outbound history is recorded once per transaction by
        // `recordConfidentialSend`, so it must not also be logged here as an
        // inbound receipt.
        if (!this.#authored(tx, key)) this.#recordReceived(tx, site.slot, undefined, utxo);
      }
      return;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringDeposit) {
      let utxo: Utxo;
      let dataHash: Bytes32 | undefined;
      let ringDataHash: Bytes32 | undefined;
      try {
        const output = decodeRingDepositOutput(body);
        utxo = decryptRingDepositUtxo(output, key, this.#owner);
        dataHash = output.dataHash;
        // A zero ring data hash is absent in the commitment.
        ringDataHash = output.ringDataHash.some((byte) => byte !== 0)
          ? output.ringDataHash
          : undefined;
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      if (this.#storeRecipientUtxos([utxo], outputContext, dataHash, ringDataHash)) {
        this.#processedSlots.add(siteKey);
        this.#recordDeposit(tx, outputContext, utxo);
      }
      return;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousSender) {
      let recipients: readonly P256PublicKey[];
      let change: readonly Utxo[];
      try {
        const plaintext = decodeAnonymousSender(this.#decryptFor(key, tx, body, site.slot));
        recipients = plaintext.recipientViewingPublicKeys;
        change = anonymousSenderUtxos(plaintext, this.#assets, SOL_MINT);
      } catch (error) {
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      for (const utxo of change) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      if (!this.#processedOutbound.has(site.transaction)) {
        this.#processedOutbound.add(site.transaction);
        const kind = recipients.length === 0 ? "publicWithdrawal" : "privateTransfer";
        this.#recordOutboundTransfer(
          tx,
          this.#spentAmounts(tx.nullifiers),
          change,
          kind,
          recipients.length === 1 ? recipients[0] : undefined,
          this.#transferDirection(recipients),
        );
      }
      return;
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
        this.#noteUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      for (const utxo of utxos) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      if (!this.#processedOutbound.has(site.transaction)) {
        this.#processedOutbound.add(site.transaction);
        this.#recordSplit(tx, this.#spentAmounts(tx.nullifiers));
      }
      return;
    }

    this.undecryptableCandidates++;
  }

  /** Reconstruct the ciphertext-free merge output from this wallet's spent inputs. */
  #reconstructMerge(tx: IndexedShieldedTransaction, site: Site, siteKey: string): void {
    const slot = tx.outputSlots[site.slot];
    const firstNullifier = tx.nullifiers[0];
    if (
      slot === undefined ||
      firstNullifier === undefined ||
      !this.#utxos.some((entry) => equal(entry.nullifier, firstNullifier))
    ) {
      this.undecryptableCandidates++;
      return;
    }

    try {
      const matched: WalletUtxo[] = [];
      for (const [index, nullifier] of tx.nullifiers.entries()) {
        if (equal(nullifier, mergeDummyNullifier(this.#nullifierKey, firstNullifier, index))) {
          continue;
        }
        const entry = this.#utxos.find((candidate) => equal(candidate.nullifier, nullifier));
        if (entry === undefined) {
          this.undecryptableCandidates++;
          return;
        }
        matched.push(entry);
      }
      const first = matched[0];
      if (first === undefined || matched.some((entry) => entry.utxo.asset !== first.utxo.asset)) {
        this.undecryptableCandidates++;
        return;
      }
      let amount = 0n;
      for (const entry of matched) {
        amount += entry.utxo.amount;
        if (amount > U64_MAX) throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
      }
      const ringProgramId = first.utxo.ringProgramId;
      if (matched.some((entry) => entry.utxo.ringProgramId !== ringProgramId)) {
        this.undecryptableCandidates++;
        return;
      }
      const ringDataHash =
        ringProgramId === undefined
          ? undefined
          : slot.payload.length === 32
            ? (copy(slot.payload) as Bytes32)
            : null;
      if (ringDataHash === null) {
        this.undecryptableCandidates++;
        return;
      }
      const utxo = new Utxo({
        owner: this.#owner,
        asset: first.utxo.asset,
        amount,
        blinding: mergeOutputBlinding(this.#nullifierKey, firstNullifier),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      });
      if (this.#storeRecipientUtxos([utxo], slot.outputContext, undefined, ringDataHash)) {
        this.#processedSlots.add(siteKey);
        this.#recordMerge(tx, slot.outputContext, utxo);
      }
      return;
    } catch (error) {
      this.#noteUndecryptable(error, siteKey);
    }
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
   * Open only the two stable discovery families: this viewing key's bootstrap
   * tag and the shielded identity's signing tag.
   */
  processStableTags(
    key: ViewingKeyLike,
    input: Readonly<{ identityTag: Bytes32; index: TagIndex }>,
  ): void {
    const { index } = input;
    const recipientSites = (tag: string): readonly Site[] => index.recipientSites.get(tag) ?? [];

    for (const site of recipientSites(hex(key.recipientBootstrapViewTag()))) {
      this.decodeSlot(key, site);
    }
    const identityTag = hex(input.identityTag);
    for (const site of recipientSites(identityTag)) this.decodeSlot(key, site);
    for (const transaction of index.senderSites.get(identityTag) ?? []) {
      this.decodeSlot(key, { transaction, slot: 0 });
    }

    this.#transactions.forEach((tx, position) => {
      this.recordConfidentialSend(tx, position, key);
    });
  }
}

export async function decryptTransactions(
  input: Readonly<{
    wallet: Wallet;
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    config?: DecryptTransactionsConfig;
  }>,
): Promise<SyncReport> {
  await initializePoseidon();
  const material = await input.authority.syncMaterial();
  validateMaterial(input.wallet, material);
  const current = input.wallet._state();
  const index = buildTagIndex(input.transactions);
  // Before the pass, which needs the full key set: seeded with the identity's
  // key and extended with this material's, so it holds every key this wallet
  // has ever been given -- including keys this scan's material omits.
  const viewingKeyHistory = ensureViewingKeyEntries(
    current.viewingKeyHistory,
    material.viewingKeys,
  );
  const pass = new SyncPass({
    material,
    assets: input.wallet.registry,
    transactions: input.transactions,
    utxos: current.utxos,
    rows: current.transactions,
    selfViewingPublicKeys: viewingKeyHistory.map((entry) => entry.viewingPublicKey),
  });
  const identityTag = material.identity.signingPublicKey.confidentialViewTag();

  for (const entry of viewingKeyHistory) {
    const id = hex(entry.viewingPublicKey.toBytes());
    const key = material.viewingKeys.find(
      (candidate) => hex(candidate.publicKey().toBytes()) === id,
    );
    if (key !== undefined) pass.processStableTags(key, { identityTag, index });
  }

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
    unknownAssetIds: pass.unknownAssetIds(),
    unknownAssetFields: pass.unknownAssetFields(),
  });
}

export async function decryptTransactionsWorkerEquivalent(
  input: Parameters<typeof decryptTransactions>[0],
): Promise<SyncReport> {
  return decryptTransactions(input);
}

/** Decrypt a complete indexed history into a read-only balance view. */
export async function decryptToBalances(
  input: Readonly<{
    keypair: ShieldedKeypair;
    registry: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
): Promise<PrivateBalances> {
  await initializePoseidon();
  const identity = input.keypair.shieldedAddress();
  const wallet = new Wallet({ identity, registry: input.registry });
  const viewingKey = input.keypair.viewingKey();
  const nullifierKey = input.keypair.nullifierKey();
  try {
    await decryptTransactions({
      wallet,
      authority: {
        syncMaterial: () => Promise.resolve({ identity, viewingKeys: [viewingKey], nullifierKey }),
      },
      transactions: input.transactions,
    });
  } finally {
    viewingKey.destroy();
    nullifierKey.destroy();
  }
  return Object.freeze({
    balance: (mint: Address, filter?: Filter) => wallet.balance(mint, filter),
    balances: (skipUtxos = false) => wallet.balances(skipUtxos),
  });
}
