import { ringDepositRecipientCiphertext } from "../../interface/ring-deposit-capsule.js";
import { mergePaddedInputCount } from "../../interface/constants.js";
import type { Address, Bytes16, Bytes32, Bytes33, RequestContext } from "../../interface/types.js";
import { type ShieldedPublicKey } from "../../keypair/public-key.js";
import { X25519PublicKey, isSmallOrder, pairHintKey } from "../../keypair/x25519.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../keypair/shielded.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { initializePoseidon } from "../../hasher/index.js";
import { DEFAULT_TREE_ID } from "../../interface/tree-slot.js";
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
  decodeRingAnonymous,
  decodeSplitBundle,
  decodeConfidential,
  decryptConfidentialAsSender,
  prooflessUtxo,
  plaintextTransferUtxos,
  readOutputData,
  splitBundleUtxos,
  splitEmbeddedKey,
  type ProoflessOutput,
} from "../serialization/codecs.js";
import {
  decodeRingDepositOutput,
  ringDepositUtxo,
  type DepositPayloadDecoder,
} from "../serialization/ring-deposit.js";
import { decryptMergeOutput, readMergeOutputBody } from "../serialization/merge.js";
import { Utxo, type TreeId } from "../utxo.js";
import {
  anonymousSlotDefect,
  type AnonymousTagRoutes,
  type PendingAnonymousNote,
} from "./anonymous.js";
import { deriveAnswers, wipeByteAnswers } from "./key-batch.js";
import { KeyMemo } from "./key-memo.js";
import {
  LocalShieldedKeys,
  checkKeysIdentity,
  checkViewingPublicKeys,
  type DecryptRequest,
  type ShieldedKeys,
} from "./keys.js";
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

/** The tree id the indexed leaf folds in, the default tree when the indexer left it out. */
function outputTreeId(context: OutputContext): TreeId {
  return context.treeId ?? DEFAULT_TREE_ID;
}

/** `undefined` for a pair hint no X25519 agreement accepts, the note itself stays verified. */
/** The nullifier every seed-disclosing bundle of `tx` derives its blindings from. */
function firstNullifierOf(tx: IndexedShieldedTransaction): Bytes32 {
  const firstNullifier = tx.nullifiers[0];
  if (firstNullifier === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
  return firstNullifier;
}

interface DecryptTransactionsConfig {
  readonly depositPayloadDecoder?: DepositPayloadDecoder;
  /** Recorded as `Wallet.lastSynced` once the sync commits, as `Wallet::sync` records `synced_at`. */
  readonly syncedAt?: bigint;
}

export interface PrivateBalances {
  balance(mint: Address, filter?: Filter): AssetBalance;
  balances(skipUtxos?: boolean): readonly AssetBalance[];
}

/**
 * Rounds a decode pass can need: one for the ciphertexts, one for the
 * nullifiers over their plaintexts, the merge derivations and the nullifiers of
 * the merge outputs (every merge site asks in the same rounds, so this is an
 * upper bound), and the final pass with every answer in hand. A resolved round
 * answers every request or throws, so a pass past this bound is a memo that is
 * not caching, not a deeper wallet.
 */
function maxKeyRounds(mergeSites: number): number {
  return 3 + 2 * mergeSites;
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
  readonly mergeSites: readonly Site[];
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
  const mergeSites: Site[] = [];
  let unparsedTransactions = 0;
  for (const [transaction, tx] of transactions.entries()) {
    let classified = false;
    if (!tx.proofless && tx.txViewingPublicKey === undefined && tx.salt === undefined) {
      for (const slotIndex of tx.outputSlots.keys()) {
        mergeSites.push({ transaction, slot: slotIndex });
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
  return { senderSites, recipientSites, mergeSites, unparsedTransactions };
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

/** Retain every viewing key the wallet has held. */
function ensureViewingKeyEntries(
  history: readonly ViewingKeyEntry[],
  viewingPublicKeys: readonly X25519PublicKey[],
): readonly ViewingKeyEntry[] {
  const known = new Set(history.map((entry) => hex(entry.viewingPublicKey.toBytes())));
  const entries = [...history];
  for (const key of viewingPublicKeys) {
    const id = hex(key.toBytes());
    if (known.has(id)) continue;
    known.add(id);
    entries.push(newViewingKeyEntry(key, 0n));
  }
  return entries;
}

/** Whether the kept outputs account for every asset the transaction spent. */
function covered(spent: ReadonlyMap<Address, bigint>, kept: readonly Utxo[]): boolean {
  if (spent.size === 0) return false;
  const byAsset = amountsByAsset(kept);
  return [...spent].every(([asset, amount]) => (byAsset.get(asset) ?? 0n) >= amount);
}

function sameAmounts(spent: ReadonlyMap<Address, bigint>, kept: readonly Utxo[]): boolean {
  if (spent.size === 0) return false;
  const byAsset = amountsByAsset(kept);
  return (
    byAsset.size === spent.size &&
    [...spent].every(([asset, amount]) => byAsset.get(asset) === amount)
  );
}

function amountsByAsset(utxos: readonly Utxo[]): ReadonlyMap<Address, bigint> {
  const byAsset = new Map<Address, bigint>();
  for (const utxo of utxos) byAsset.set(utxo.asset, (byAsset.get(utxo.asset) ?? 0n) + utxo.amount);
  return byAsset;
}

function historyId(tx: IndexedShieldedTransaction, index: bigint): PrivateTransactionId {
  return { signature: tx.txSignature, slot: tx.slot, index };
}

/**
 * A row's identity is its transaction and index: a received or merged output
 * by leaf index, a sender-side aggregate by its asset row. Recording the same
 * identity again replaces the row, so a transaction seen with a fuller view of
 * the wallet (its change now known, its spend now netted) does not leave the
 * earlier row beside the corrected one.
 */
function rowKey(row: PrivateTransaction): string {
  return `${row.id.signature}|${row.id.slot}|${row.id.index}`;
}

/**
 * The UTXOs and history rows one sync produces, accumulated across every
 * viewing key the wallet's keys hold. This is the counterpart of Rust
 * `SyncCtx`: it owns the staged wallet contents so a rejection leaves the
 * wallet untouched, and it carries the report counters each decode step
 * advances.
 */
class SyncPass {
  readonly #depositPayloadDecoder: DepositPayloadDecoder;
  readonly #owner: ShieldedPublicKey;
  readonly #nullifierPublicKey: Bytes32;
  /** The keys the wallet holds, current first; the pass opens under each. */
  readonly #viewingPublicKeys: readonly X25519PublicKey[];
  readonly #keys: KeyMemo;
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
  readonly #anonymousOpened = new Map<string, number>();
  readonly #pendingAssetsBySite = new Map<string, PendingAnonymousNote>();
  readonly #unknownAssetsBySite = new Map<
    string,
    Readonly<{ ids: Set<bigint>; fields: Map<string, Bytes32> }>
  >();
  storedUtxos = 0;
  undecryptableCandidates = 0;

  constructor(
    input: Readonly<{
      depositPayloadDecoder?: DepositPayloadDecoder | undefined;
      identity: ShieldedAddress;
      viewingPublicKeys: readonly X25519PublicKey[];
      keys: KeyMemo;
      assets: AssetRegistry;
      transactions: readonly IndexedShieldedTransaction[];
      utxos: readonly WalletUtxo[];
      rows: readonly PrivateTransaction[];
      selfViewingPublicKeys: readonly X25519PublicKey[];
    }>,
  ) {
    this.#depositPayloadDecoder = input.depositPayloadDecoder ?? ringDepositRecipientCiphertext;
    this.#owner = input.identity.signingPublicKey;
    this.#nullifierPublicKey = input.identity.nullifierPublicKey;
    this.#viewingPublicKeys = input.viewingPublicKeys;
    this.#keys = input.keys;
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

  pendingAssets(): readonly PendingAnonymousNote[] {
    return [...this.#pendingAssetsBySite.values()];
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

  /**
   * `pending` means the nullifier is not derived yet; the memo has recorded
   * the request and the next round stores the UTXO. Nothing is counted for a
   * pending slot, so the final round's report is the one a single pass over
   * in-process keys would produce.
   */
  #store(
    utxo: Utxo,
    outputContext: OutputContext,
    dataHash: Bytes32 | undefined,
    ringDataHash: Bytes32 | undefined,
  ): "stored" | "skipped" | "pending" {
    if (!equal(utxo.owner.toBytes(), this.#owner.toBytes())) return "skipped";
    const outputId = hex(outputContext.hash);
    if (this.#outputHashes.has(outputId)) return "skipped";
    const nullifier = this.#keys.derive({
      kind: "nullifier",
      utxoHash: outputContext.hash,
      blinding: utxo.blinding,
    });
    if (nullifier === undefined) return "pending";
    this.#utxos.push(
      Object.freeze({
        utxo,
        outputContext: Object.freeze({
          hash: copy(outputContext.hash),
          tree: outputContext.tree,
          leafIndex: outputContext.leafIndex,
        }),
        nullifier,
        ...(dataHash === undefined ? {} : { dataHash }),
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
        spent: false,
      }),
    );
    this.#outputHashes.add(outputId);
    this.storedUtxos++;
    return "stored";
  }

  /**
   * Store a UTXO whose slot is not known in advance. Find the slot whose
   * committed leaf its hash reproduces. The sender-side bundles carry their
   * change this way: one bundle describes several outputs spread across the
   * transaction.
   */
  #storeInTx(utxo: Utxo, tx: IndexedShieldedTransaction): void {
    const slot = tx.outputSlots.find((candidate) =>
      equal(
        candidate.outputContext.hash,
        utxo.hash(this.#nullifierPublicKey, outputTreeId(candidate.outputContext)),
      ),
    );
    if (slot === undefined) {
      this.undecryptableCandidates++;
      return;
    }
    this.#store(utxo, slot.outputContext, undefined, undefined);
  }

  /** Verify each 1:1 recipient UTXO against the committed leaf and store it. */
  #storeRecipientUtxos(
    utxos: readonly Utxo[],
    outputContext: OutputContext,
    dataHash: Bytes32 | undefined,
    ringDataHash: Bytes32 | undefined,
  ): boolean {
    let stored = false;
    for (const utxo of utxos) {
      if (
        !equal(
          utxo.hash(this.#nullifierPublicKey, outputTreeId(outputContext), dataHash, ringDataHash),
          outputContext.hash,
        )
      ) {
        this.undecryptableCandidates++;
        continue;
      }
      if (this.#store(utxo, outputContext, dataHash, ringDataHash) !== "pending") stored = true;
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
   * Record a candidate that failed to become UTXOs. When the failure was an
   * unknown asset id, remember the id so the client sync layer can backfill the
   * registry and retry; that is the single seam where a stale registry surfaces
   * during decode.
   */
  #recordUndecryptable(error: unknown, siteKey: string): void {
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

  #spentEntries(nullifiers: readonly Bytes32[]): readonly WalletUtxo[] {
    const spent = new Set(nullifiers.map(hex));
    return this.#utxos.filter((entry) => spent.has(hex(entry.nullifier)));
  }

  #recordReceived(
    tx: IndexedShieldedTransaction,
    slotIndex: number,
    sender: X25519PublicKey | undefined,
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
  #transferDirection(recipients: readonly X25519PublicKey[]): PrivateTransactionDirection {
    return recipients.length > 0 && recipients.every((recipient) => this.#isSelf(recipient))
      ? "selfTransfer"
      : "outbound";
  }

  #isSelf(viewingPublicKey: X25519PublicKey): boolean {
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
    counterparty: X25519PublicKey | undefined,
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
   * Whether `viewingPublicKey` is the key that authored `tx`: the transaction
   * viewing key derived from the first nullifier reproduces the published one
   * only for the spending wallet.
   */
  #authored(tx: IndexedShieldedTransaction, viewingPublicKey: X25519PublicKey): boolean {
    const published = tx.txViewingPublicKey;
    const firstNullifier = tx.nullifiers[0];
    if (published === undefined || firstNullifier === undefined) return false;
    const txKey = this.#keys.transactionKey({ viewingPublicKey, firstNullifier });
    return txKey !== undefined && equal(txKey.publicKey().toBytes(), published.toBytes());
  }

  /** The embedded viewing key and committed UTXO identify change. */
  recordConfidentialSend(
    tx: IndexedShieldedTransaction,
    index: number,
    viewingPublicKey: X25519PublicKey,
  ): void {
    const firstNullifier = tx.nullifiers[0];
    const salt = tx.salt;
    if (tx.txViewingPublicKey === undefined || firstNullifier === undefined || salt === undefined) {
      return;
    }
    const txKey = this.#keys.transactionKey({ viewingPublicKey, firstNullifier });
    if (txKey === undefined) return;
    if (!equal(txKey.publicKey().toBytes(), tx.txViewingPublicKey.toBytes())) return;
    if (this.#processedOutbound.has(index)) return;
    this.#processedOutbound.add(index);
    this.#decodeOutboundSlots(tx, txKey, salt);
  }

  #decodeOutboundSlots(tx: IndexedShieldedTransaction, txKey: ViewingKey, salt: Bytes16): void {
    const change: Utxo[] = [];
    const recipients: Array<Readonly<{ key: X25519PublicKey; utxo: Utxo }>> = [];
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
        const recipientKey = X25519PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33);
        if (position < SENDER_SLOT_COUNT) {
          const candidate = confidentialUtxo(plaintext, this.#owner, this.#assets);
          if (
            this.#isSelf(recipientKey) &&
            (position === 0 ||
              (candidate.asset === SOL_MINT &&
                change.length === 1 &&
                change[0]?.asset !== SOL_MINT)) &&
            equal(
              candidate.hash(this.#nullifierPublicKey, outputTreeId(slot.outputContext)),
              slot.outputContext.hash,
            )
          ) {
            change.push(candidate);
            return;
          }
        }
        recipients.push({
          key: recipientKey,
          utxo: confidentialUtxo(plaintext, this.#owner, this.#assets),
        });
      } catch {
        // A dummy slot fails the transaction-key decrypt; skip it.
      }
    });

    const spent = this.#spentAmounts(tx.nullifiers);
    // Paying yourself keeps every output, so nothing distinguishes it from
    // change except that the change covers the whole spend.
    if (recipients.length === 0 && covered(spent, change)) {
      this.#recordSplit(tx, spent);
      return;
    }
    const entry = this.#isRingEntry(tx.nullifiers, change, recipients);
    const kind = entry
      ? "ringEntry"
      : recipients.length === 0
        ? "publicWithdrawal"
        : "privateTransfer";
    const recipientKeys = recipients.map((recipient) => recipient.key);
    this.#recordOutboundTransfer(
      tx,
      spent,
      change,
      kind,
      !entry && recipientKeys.length === 1 ? recipientKeys[0] : undefined,
      entry ? "selfTransfer" : this.#transferDirection(recipientKeys),
    );
  }

  #isRingEntry(
    nullifiers: readonly Bytes32[],
    change: readonly Utxo[],
    recipients: readonly Readonly<{ key: X25519PublicKey; utxo: Utxo }>[],
  ): boolean {
    const inputs = this.#spentEntries(nullifiers);
    const rings = new Set(recipients.map(({ utxo }) => utxo.ringProgramId));
    const assets = new Set(recipients.map(({ utxo }) => utxo.asset));
    return (
      inputs.length > 0 &&
      inputs.every((entry) => entry.utxo.ringProgramId === undefined) &&
      change.every((utxo) => utxo.ringProgramId === undefined) &&
      recipients.length > 0 &&
      rings.size === 1 &&
      assets.size === 1 &&
      recipients.every(({ key, utxo }) => this.#isSelf(key) && utxo.ringProgramId !== undefined) &&
      sameAmounts(this.#spentAmounts(nullifiers), [
        ...change,
        ...recipients.map(({ utxo }) => utxo),
      ])
    );
  }

  /**
   * Decode one candidate slot, dispatching on its encoding and scheme byte.
   * Recipient and confidential slots are 1:1 and verified against the slot's
   * committed leaf; the anonymous and split sender bundles, passed as slot 0,
   * store their change against the whole transaction.
   */
  decodeSlot(viewingPublicKey: X25519PublicKey, site: Site): void {
    const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
    if (this.#processedSlots.has(siteKey)) return;
    const tx = this.#transactions[site.transaction];
    const slot = tx?.outputSlots[site.slot];
    if (tx === undefined || slot === undefined) {
      this.undecryptableCandidates++;
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
        this.#recordUndecryptable(error, siteKey);
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
        utxos = plaintextTransferUtxos(
          decodePlaintextTransfer(body),
          this.#assets,
          SOL_MINT,
          firstNullifierOf(tx),
        );
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      for (const utxo of utxos) this.#storeInTx(utxo, tx);
      this.#processedSlots.add(siteKey);
      return;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousRecipient) {
      let sender: X25519PublicKey;
      let utxo: Utxo;
      const decrypted = this.#decryptSlot(viewingPublicKey, tx, body, site.slot, siteKey);
      if (decrypted === undefined) return;
      try {
        const plaintext = decodeAnonymousRecipient(decrypted);
        sender = plaintext.senderPublicKey;
        utxo = anonymousRecipientUtxo(plaintext, this.#assets);
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
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
      let ciphertext: Uint8Array;
      try {
        ciphertext = splitEmbeddedKey(body).rest;
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
        return;
      }
      const decrypted = this.#decryptSlot(viewingPublicKey, tx, ciphertext, site.slot, siteKey);
      if (decrypted === undefined) return;
      try {
        utxo = confidentialUtxo(decodeConfidential(decrypted), this.#owner, this.#assets);
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
        return;
      }
      this.#resolveAssetCandidate(siteKey);
      if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
        this.#processedSlots.add(siteKey);
        // A slot the wallet itself authored is its own change or self-send
        // output; its outbound history is recorded once per transaction by
        // `recordConfidentialSend`, so it must not also be logged here as an
        // inbound receipt.
        if (!this.#authored(tx, viewingPublicKey)) {
          this.#recordReceived(tx, site.slot, undefined, utxo);
        }
      }
      return;
    }

    if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringDeposit) {
      let utxo: Utxo;
      let dataHash: Bytes32 | undefined;
      let ringDataHash: Bytes32 | undefined;
      let output: ReturnType<typeof decodeRingDepositOutput>;
      let txViewingPublicKey: X25519PublicKey;
      let ciphertext: Uint8Array;
      try {
        output = decodeRingDepositOutput(body);
        txViewingPublicKey = X25519PublicKey.fromBytes(output.encrypted.txViewingPublicKey);
        ciphertext = output.encrypted.ciphertext;
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
        return;
      }
      ciphertext = this.#depositPayloadDecoder(ciphertext);
      const decrypted = this.#open({
        ciphertext,
        viewingPublicKey,
        txViewingPublicKey,
        salt: output.encrypted.salt,
        slotIndex: 0,
        label: "ringDeposit",
      });
      if (decrypted === undefined) return;
      try {
        utxo = ringDepositUtxo(output, decrypted, this.#owner);
        dataHash = output.dataHash;
        // A zero ring data hash is absent in the commitment.
        ringDataHash = output.ringDataHash.some((byte) => byte !== 0)
          ? output.ringDataHash
          : undefined;
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
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
      let recipients: readonly X25519PublicKey[];
      let change: readonly Utxo[];
      const decrypted = this.#decryptSlot(viewingPublicKey, tx, body, site.slot, siteKey);
      if (decrypted === undefined) return;
      try {
        const plaintext = decodeAnonymousSender(decrypted);
        recipients = plaintext.recipientViewingPublicKeys;
        change = anonymousSenderUtxos(plaintext, this.#assets, SOL_MINT, firstNullifierOf(tx));
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
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
      const decrypted = this.#decryptSlot(viewingPublicKey, tx, body, site.slot, siteKey);
      if (decrypted === undefined) return;
      try {
        utxos = splitBundleUtxos(decodeSplitBundle(decrypted), this.#assets, firstNullifierOf(tx));
      } catch (error) {
        this.#recordUndecryptable(error, siteKey);
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

  /**
   * Each merge output decrypts from its own transaction, so one pass reaches
   * every site in any order; a site whose derivations are pending is reached
   * again in the next round.
   */
  resolveMergeSites(sites: readonly Site[]): void {
    for (const site of sites) {
      const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
      if (this.#processedSlots.has(siteKey)) continue;
      const tx = this.#transactions[site.transaction];
      if (tx === undefined || tx.outputSlots[site.slot] === undefined) {
        this.undecryptableCandidates++;
        continue;
      }
      this.#reconstructMerge(tx, site, siteKey);
    }
  }

  /** Check after every key round and newly discovered input has been resolved. */
  assertOwnedMergesDecoded(sites: readonly Site[], identityTag: Bytes32): void {
    const ownedNullifiers = new Set(this.#utxos.map((entry) => hex(entry.nullifier)));
    for (const site of sites) {
      if (this.#processedSlots.has(`${String(site.transaction)}:${String(site.slot)}`)) continue;
      const tx = this.#transactions[site.transaction];
      const slot = tx?.outputSlots[site.slot];
      if (tx === undefined || slot === undefined) continue;
      if (this.#outputHashes.has(hex(slot.outputContext.hash))) continue;
      if (
        equal(slot.viewTag, identityTag) ||
        tx.nullifiers.some((nullifier) => ownedNullifiers.has(hex(nullifier)))
      ) {
        throw new TransactionError("TRANSACTION_MERGE_OUTPUT_UNDECRYPTABLE");
      }
    }
  }

  /**
   * A merge output publishes its amount and mint under a key derived from the
   * nullifier secret and the first nullifier, and the proof binds that
   * ciphertext, so the owner rebuilds the output whichever inputs the merger
   * folded in. The cipher is unauthenticated: another wallet's merge decrypts
   * to noise, which the plaintext range check or the commitment rejects.
   */
  #reconstructMerge(tx: IndexedShieldedTransaction, site: Site, siteKey: string): void {
    const slot = tx.outputSlots[site.slot];
    const firstNullifier = tx.nullifiers[0];
    // A merge publishes its sent nullifiers; compact padding is left out.
    if (
      slot === undefined ||
      firstNullifier === undefined ||
      mergePaddedInputCount(tx.nullifiers.length) === undefined
    ) {
      this.undecryptableCandidates++;
      return;
    }
    const body = readMergeOutputBody(slot.payload);
    // A ring merge leads with its output ring data hash, and the transaction
    // names its ring program; a body and transaction that disagree are not a
    // merge this wallet can rebuild.
    if (
      body === undefined ||
      (body.ringDataHash === undefined) !== (tx.ringProgramId === undefined)
    ) {
      this.undecryptableCandidates++;
      return;
    }
    // Requested together so one round answers both.
    let key: Bytes32 | undefined;
    let outputBlinding: Bytes32 | undefined;
    try {
      key = this.#keys.derive({ kind: "mergeOutputKey", firstNullifier });
      outputBlinding = this.#keys.derive({ kind: "mergeOutputBlinding", firstNullifier });
      if (key === undefined || outputBlinding === undefined) return;
      const plaintext = decryptMergeOutput(body.encrypted, key);
      const utxo = new Utxo({
        owner: this.#owner,
        asset: plaintext.mint,
        amount: plaintext.amount,
        blinding: outputBlinding,
        ...(tx.ringProgramId === undefined ? {} : { ringProgramId: tx.ringProgramId }),
      });
      if (this.#storeRecipientUtxos([utxo], slot.outputContext, undefined, body.ringDataHash)) {
        this.#processedSlots.add(siteKey);
        this.#recordMerge(tx, slot.outputContext, utxo);
      }
    } catch (error) {
      this.#recordUndecryptable(error, siteKey);
    } finally {
      key?.fill(0);
      outputBlinding?.fill(0);
    }
  }

  /** The published transaction key and salt every encrypted scheme opens under. */
  #envelope(
    tx: IndexedShieldedTransaction,
  ): Readonly<{ txViewingPublicKey: X25519PublicKey; salt: Bytes16 }> {
    if (tx.txViewingPublicKey === undefined || tx.salt === undefined) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "envelope" });
    }
    return { txViewingPublicKey: tx.txViewingPublicKey, salt: tx.salt };
  }

  /**
   * The transfer cipher over one slot with this wallet's viewing key, or
   * `undefined` while the memo has no answer yet. A transaction without an
   * envelope is undecryptable, not pending.
   */
  #decryptSlot(
    viewingPublicKey: X25519PublicKey,
    tx: IndexedShieldedTransaction,
    ciphertext: Uint8Array,
    slotIndex: number,
    siteKey: string,
    label: DecryptRequest["label"] = "transfer",
  ): Uint8Array | undefined {
    let envelope: Readonly<{ txViewingPublicKey: X25519PublicKey; salt: Bytes16 }>;
    try {
      envelope = this.#envelope(tx);
    } catch (error) {
      this.#recordUndecryptable(error, siteKey);
      return undefined;
    }
    return this.#open({
      ciphertext,
      viewingPublicKey,
      txViewingPublicKey: envelope.txViewingPublicKey,
      salt: envelope.salt,
      slotIndex,
      label,
    });
  }

  /** `undefined` while the memo has no answer, or for a sender-picked small-order transaction key. */
  #open(request: DecryptRequest): Uint8Array | undefined {
    if (isSmallOrder(request.txViewingPublicKey)) {
      this.undecryptableCandidates++;
      return undefined;
    }
    return this.#keys.decrypt(request);
  }

  /** Unauthenticated cipher, only the commitment recompute proves the routed key sealed the output. */
  processAnonymousRoutes(index: TagIndex, routes: AnonymousTagRoutes): void {
    for (const [tag, route] of routes.entries()) {
      for (const site of index.recipientSites.get(tag) ?? []) {
        const ringAnonymous = this.#isRingAnonymous(site);
        if (!ringAnonymous && route.stream.kind !== "deposit") continue;
        for (const viewingPublicKey of route.viewingPublicKeys) {
          if (ringAnonymous) this.#decodeRingAnonymousSlot(viewingPublicKey, site, routes);
          else this.decodeSlot(viewingPublicKey, site);
        }
      }
    }
  }

  #isRingAnonymous(site: Site): boolean {
    const slot = this.#transactions[site.transaction]?.outputSlots[site.slot];
    if (slot === undefined) return false;
    try {
      const frame = readOutputData(slot.payload);
      return frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.ringAnonymous;
    } catch {
      return false;
    }
  }

  /** The commitment recompute decides before any registry lookup, the per-tag cap only flags the tag and never skips a hit. */
  #decodeRingAnonymousSlot(
    viewingPublicKey: X25519PublicKey,
    site: Site,
    routes: AnonymousTagRoutes,
  ): void {
    const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
    if (this.#processedSlots.has(siteKey)) return;
    const tx = this.#transactions[site.transaction];
    const slot = tx?.outputSlots[site.slot];
    const route = tx === undefined || slot === undefined ? undefined : routes.routeOf(slot.viewTag);
    if (tx === undefined || slot === undefined || route === undefined) {
      this.undecryptableCandidates++;
      return;
    }
    let frame: ReturnType<typeof readOutputData>;
    try {
      frame = readOutputData(slot.payload);
    } catch {
      this.undecryptableCandidates++;
      return;
    }
    if (tx.ringProgramId === undefined) {
      this.undecryptableCandidates++;
      return;
    }
    const defect = anonymousSlotDefect(tx, frame.body);
    if (defect !== undefined) {
      this.undecryptableCandidates++;
      routes.malformed({
        txSignature: tx.txSignature,
        slotIndex: site.slot,
        viewTag: copy(slot.viewTag) as Bytes32,
        defect,
      });
      return;
    }
    const tag = hex(slot.viewTag);
    const opened = this.#anonymousOpened.get(tag) ?? 0;
    this.#anonymousOpened.set(tag, opened + 1);
    if (!routes.allows(opened)) routes.capped(slot.viewTag);
    const decrypted = this.#decryptSlot(
      viewingPublicKey,
      tx,
      frame.body,
      site.slot,
      siteKey,
      "ringAnonymous",
    );
    if (decrypted === undefined) return;
    let plaintext: ReturnType<typeof decodeRingAnonymous>;
    try {
      plaintext = decodeRingAnonymous(decrypted);
    } catch {
      this.undecryptableCandidates++;
      return;
    }
    const { outputContext } = slot;
    const utxo = new Utxo({
      owner: this.#owner,
      asset: plaintext.assetAddress,
      amount: plaintext.amount,
      blinding: plaintext.blinding,
      ringProgramId: tx.ringProgramId,
    });
    const treeId = outputTreeId(outputContext);
    if (!equal(utxo.hash(this.#nullifierPublicKey, treeId), outputContext.hash)) {
      this.undecryptableCandidates++;
      return;
    }
    if (!knowsMint(this.#assets, utxo.asset)) {
      this.#pendingAssetsBySite.set(
        siteKey,
        Object.freeze({
          utxo,
          nullifierPublicKey: copy(this.#nullifierPublicKey),
          outputContext: Object.freeze({
            hash: copy(outputContext.hash),
            tree: outputContext.tree,
            treeId,
            leafIndex: outputContext.leafIndex,
          }),
          txSignature: tx.txSignature,
          slot: tx.slot,
          slotIndex: site.slot,
          pairU: copy(plaintext.pairU),
        }),
      );
      return;
    }
    this.#pendingAssetsBySite.delete(siteKey);
    if (this.#store(utxo, outputContext, undefined, undefined) === "pending") return;
    this.#processedSlots.add(siteKey);
    const pairPublicKey = pairHintKey(plaintext.pairU);
    if (pairPublicKey === undefined) routes.badPairHint(copy(outputContext.hash) as Bytes32);
    routes.found({
      viewTag: copy(slot.viewTag) as Bytes32,
      utxoHash: copy(outputContext.hash) as Bytes32,
      ...(pairPublicKey === undefined ? {} : { pairPublicKey }),
      stream: route.stream,
    });
    if (route.stream.kind !== "change") this.#recordReceived(tx, site.slot, pairPublicKey, utxo);
  }

  /**
   * Open only the two stable discovery families: this viewing key's bootstrap
   * tag and the shielded identity's signing tag.
   */
  processStableTags(input: Readonly<{ identityTag: Bytes32; index: TagIndex }>): void {
    const { index } = input;
    const recipientSites = (tag: string): readonly Site[] => index.recipientSites.get(tag) ?? [];
    const identityTag = hex(input.identityTag);

    for (const viewingPublicKey of this.#viewingPublicKeys) {
      for (const site of recipientSites(hex(viewingPublicKey.x()))) {
        this.decodeSlot(viewingPublicKey, site);
      }
      for (const site of recipientSites(identityTag)) this.decodeSlot(viewingPublicKey, site);
      for (const transaction of index.senderSites.get(identityTag) ?? []) {
        this.decodeSlot(viewingPublicKey, { transaction, slot: 0 });
      }
      this.#transactions.forEach((tx, position) => {
        this.recordConfidentialSend(tx, position, viewingPublicKey);
      });
    }
  }
}

export async function decryptTransactions(
  input: Readonly<{
    wallet: Wallet;
    keys: ShieldedKeys;
    transactions: readonly IndexedShieldedTransaction[];
    config?: DecryptTransactionsConfig;
    /** Scheme-9 slots under these tags open with the routed key, no other scheme-9 slot opens. */
    anonymous?: AnonymousTagRoutes | undefined;
    /** Forwarded to every batch the key holder answers. */
    context?: RequestContext | undefined;
  }>,
): Promise<SyncReport> {
  await initializePoseidon();
  checkKeysIdentity(input.keys, input.wallet.identity);
  const identity = input.keys.address();
  const viewingPublicKeys = checkViewingPublicKeys(input.keys, identity);
  const current = input.wallet._state();
  const index = buildTagIndex(input.transactions);
  // Before the pass, which needs the full key set: seeded with the identity's
  // key and extended with every key held, so it holds every key this wallet
  // has ever been given -- including keys a later sync no longer holds.
  const viewingKeyHistory = ensureViewingKeyEntries(current.viewingKeyHistory, viewingPublicKeys);
  const identityTag = identity.signingPublicKey.confidentialViewTag();
  const mergeSites = index.mergeSites;
  const memo = new KeyMemo(input.keys);
  try {
    for (let round = 0; round < maxKeyRounds(mergeSites.length); round++) {
      const pass = new SyncPass({
        depositPayloadDecoder: input.config?.depositPayloadDecoder,
        identity,
        viewingPublicKeys,
        keys: memo,
        assets: input.wallet.registry,
        transactions: input.transactions,
        utxos: current.utxos,
        rows: current.transactions,
        selfViewingPublicKeys: viewingKeyHistory.map((entry) => entry.viewingPublicKey),
      });
      pass.processStableTags({ identityTag, index });
      if (input.anonymous !== undefined) pass.processAnonymousRoutes(index, input.anonymous);
      pass.resolveMergeSites(mergeSites);
      if (memo.pending()) {
        await memo.resolve(input.context);
        continue;
      }
      pass.assertOwnedMergesDecoded(mergeSites, identityTag);
      return commitPass(input, pass, index, viewingKeyHistory);
    }
    throw new TransactionError("TRANSACTION_KEYS_UNRESOLVED");
  } finally {
    memo.destroy();
  }
}

function commitPass(
  input: Readonly<{
    wallet: Wallet;
    transactions: readonly IndexedShieldedTransaction[];
    config?: DecryptTransactionsConfig;
  }>,
  pass: SyncPass,
  index: TagIndex,
  viewingKeyHistory: readonly ViewingKeyEntry[],
): SyncReport {
  const current = input.wallet._state();
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
    pendingNotes: [...current.pendingNotes, ...pass.pendingAssets()],
    lastSynced: input.config?.syncedAt ?? 0n,
  });
  return Object.freeze({
    storedUtxos: pass.storedUtxos,
    unparsedTransactions: index.unparsedTransactions,
    undecryptableCandidates: pass.undecryptableCandidates,
    unknownAssetIds: pass.unknownAssetIds(),
    unknownAssetFields: pass.unknownAssetFields(),
    pendingAssets: pass.pendingAssets(),
  });
}

/** A pending note admitted by `resolvePendingNotes`. */
export interface ResolvedPendingNote {
  readonly utxo: WalletUtxo;
  /** Its nullifier was among the wallet's spent ones before it was admitted. */
  readonly spent: boolean;
}

/** Admits every pending note whose mint the registry now knows, a failed step leaves the wallet unchanged. */
export async function resolvePendingNotes(
  input: Readonly<{ wallet: Wallet; keys: ShieldedKeys; context?: RequestContext | undefined }>,
): Promise<readonly ResolvedPendingNote[]> {
  checkKeysIdentity(input.keys, input.wallet.identity);
  const revision = input.wallet._revision;
  const current = input.wallet._state();
  const registry = input.wallet.registry;
  const admitted = current.pendingNotes.filter((note) => knowsMint(registry, note.utxo.asset));
  if (admitted.length === 0) return [];
  const answers = await input.keys.derive(
    admitted.map((note) => ({
      kind: "nullifier",
      utxoHash: note.outputContext.hash,
      blinding: note.utxo.blinding,
    })),
    input.context,
  );
  let nullifiers: readonly Bytes32[];
  try {
    nullifiers = deriveAnswers(
      answers,
      admitted.length,
      () => new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH"),
    );
    if (input.wallet._revision !== revision) {
      throw new TransactionError("TRANSACTION_WALLET_STATE_STALE");
    }
  } catch (cause) {
    wipeByteAnswers(answers);
    throw cause;
  }
  const resolved = admitted.map((note, index): ResolvedPendingNote => {
    const nullifier = nullifiers[index]!;
    const spent = current.nullifiers.has(hex(nullifier));
    return Object.freeze({
      utxo: Object.freeze({
        utxo: note.utxo,
        outputContext: Object.freeze({
          hash: note.outputContext.hash,
          tree: note.outputContext.tree,
          leafIndex: note.outputContext.leafIndex,
        }),
        nullifier,
        spent,
      }),
      spent,
    });
  });
  input.wallet._replace({
    ...current,
    utxos: [...current.utxos, ...resolved.map((note) => note.utxo)],
  });
  return resolved;
}

function knowsMint(registry: AssetRegistry, mint: Address): boolean {
  try {
    registry.assetId(mint);
    return true;
  } catch (error) {
    if (error instanceof TransactionError && error.code === "TRANSACTION_UNKNOWN_MINT") {
      return false;
    }
    throw error;
  }
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
  const keys = LocalShieldedKeys.fromKeypair(input.keypair);
  try {
    await decryptTransactions({ wallet, keys, transactions: input.transactions });
  } finally {
    keys.destroy();
  }
  return Object.freeze({
    balance: (mint: Address, filter?: Filter) => wallet.balance(mint, filter),
    balances: (skipUtxos = false) => wallet.balances(skipUtxos),
  });
}
