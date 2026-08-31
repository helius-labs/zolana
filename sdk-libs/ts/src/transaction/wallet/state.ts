import type { Address, Bytes32, Signature } from "../../interface/types.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress } from "../../keypair/shielded.js";

import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "../asset.js";

export interface AssetBalance {
  readonly assetId: bigint;
  readonly mint: Address;
  readonly amount: bigint;
  readonly utxos: readonly Utxo[];
}

/** Holdings bound to one ring, never selectable by the default spend path. */
export interface RingBalance {
  readonly ringProgramId: Address;
  readonly assets: readonly AssetBalance[];
}

/** Narrows which unspent notes a balance counts. */
export type Filter = Readonly<{ kind: "minAmount"; minAmount: bigint }>;

function matches(filter: Filter, utxo: Utxo): boolean {
  return utxo.amount >= filter.minAmount;
}

/**
 * Stable identity of one history row. `index` discriminates rows within a
 * transaction: received outputs use the UTXO leaf index where the indexer
 * supplies one, and sender-side aggregate rows use a high local range.
 */
export interface PrivateTransactionId {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly index: bigint;
}

/**
 * Sender-side aggregate rows are indexed from here, above every leaf index a
 * tree can hand out, so they cannot collide with a received row.
 */
export const SENDER_HISTORY_ROW_BASE = 1n << 63n;

export type PrivateTransactionKind =
  | "deposit"
  | "privateTransfer"
  | "ringEntry"
  | "publicWithdrawal"
  | "split"
  | "merge";

export type PrivateTransactionDirection = "inbound" | "outbound" | "selfTransfer";

/**
 * Streams the wallet keeps read positions in.
 *
 * They are separate because reaching the tip of one says nothing about the
 * others, and sharing a cursor would skip rows in whichever stream is behind.
 * `transactions` and `proofless` are keyed by view tag; `nullifiers` by
 * nullifier.
 */
export type CursorStream = "transactions" | "proofless" | "nullifiers";

/** @internal */
export type SyncCursorAdvances = Readonly<Record<CursorStream, ReadonlyMap<string, Uint8Array>>>;

/** @internal Selection skips its notes until expiry, per wallet instance, not a cross-process lock. */
export interface NoteReservation {
  readonly id: string;
  readonly noteHashes: readonly Bytes32[];
  readonly expiresAtMs: bigint;
}

/** @internal */
export interface SyncDelta {
  readonly utxos: readonly WalletUtxo[];
  readonly transactions: readonly PrivateTransaction[];
  readonly nullifiers: ReadonlySet<string>;
  readonly viewingKeyHistory: readonly ViewingKeyEntry[];
  readonly lastSynced: bigint;
  readonly cursors: SyncCursorAdvances;
  readonly registryAdditions: readonly Readonly<{ assetId: bigint; mint: Address }>[];
}

/**
 * A history row is reconstructed from an indexed transaction, so it exists only
 * once that transaction has landed. Nothing stages a locally submitted transfer
 * into the history ahead of a sync, in either language, so `confirmed` is the
 * only state a row can be in.
 */
export type PrivateTransactionStatus = "confirmed";

export interface PrivateTransaction {
  readonly id: PrivateTransactionId;
  readonly kind: PrivateTransactionKind;
  readonly direction: PrivateTransactionDirection;
  readonly status: PrivateTransactionStatus;
  readonly asset: Address;
  readonly amount: bigint;
  readonly counterpartyViewingPublicKey?: P256PublicKey;
}

export interface SyncReport {
  readonly storedUtxos: number;
  readonly unparsedTransactions: number;
  readonly undecryptableCandidates: number;
  /**
   * Compact asset ids that failed to decode because the wallet's registry did
   * not know them, ascending. The client sync layer uses this to lazily
   * backfill the registry from chain and retry; it stays empty when every id is
   * known.
   */
  readonly unknownAssetIds: readonly bigint[];
  /**
   * Merge asset fields that could not be resolved through the wallet's
   * registry. The client sync layer backfills the registry only when this or
   * `unknownAssetIds` is non-empty.
   */
  readonly unknownAssetFields: readonly Bytes32[];
}

/**
 * A viewing public key retained for historical deposit discovery and
 * decryption after key rotation.
 */
export interface ViewingKeyEntry {
  readonly viewingPublicKey: P256PublicKey;
  readonly createdAt: bigint;
}

export function newViewingKeyEntry(
  viewingPublicKey: P256PublicKey,
  createdAt: bigint,
): ViewingKeyEntry {
  return Object.freeze({
    viewingPublicKey,
    createdAt,
  });
}

function snapshotViewingKeyEntry(value: ViewingKeyEntry): ViewingKeyEntry {
  return Object.freeze({
    viewingPublicKey: value.viewingPublicKey,
    createdAt: value.createdAt,
  });
}

export interface WalletUtxo {
  readonly utxo: Utxo;
  readonly outputContext: Readonly<{
    hash: Bytes32;
    tree: Address;
    leafIndex: bigint;
  }>;
  readonly nullifier: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  readonly spent: boolean;
}

function copyUtxo(value: Utxo): Utxo {
  return new Utxo({
    owner: value.owner,
    asset: value.asset,
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(value.ringProgramId === undefined ? {} : { ringProgramId: value.ringProgramId }),
  });
}

function snapshotUtxo(value: WalletUtxo): WalletUtxo {
  return Object.freeze({
    ...value,
    utxo: copyUtxo(value.utxo),
    outputContext: Object.freeze({
      ...value.outputContext,
      hash: copy(value.outputContext.hash),
    }),
    nullifier: copy(value.nullifier),
    ...(value.dataHash === undefined ? {} : { dataHash: copy(value.dataHash) }),
    ...(value.ringDataHash === undefined ? {} : { ringDataHash: copy(value.ringDataHash) }),
  });
}

export class Wallet {
  readonly identity: ShieldedAddress;
  readonly #registry: AssetRegistry;
  #viewingKeyHistory: ViewingKeyEntry[];
  #utxos: WalletUtxo[] = [];
  #transactions: PrivateTransaction[] = [];
  #nullifiers = new Set<string>();
  #lastSynced = 0n;
  /**
   * Per-view-tag sync watermarks: for each tag, the indexer cursor up to which
   * every matching transaction has already been seen. Mirrors Rust's
   * `Wallet::sync_cursors`.
   *
   * Per tag rather than one shared position, because the tag set GROWS. Tags
   * come from a local counter plus a window, and a second device spending
   * beyond that window makes the counter lag by more than the window absorbs.
   * A tag learned late must be scanned from the beginning even though other
   * tags have advanced far past those slots, so a single cursor would skip
   * those transactions permanently.
   *
   * Serialized with the wallet since snapshot version 3, an older snapshot
   * restores with empty cursors and rescans history once.
   */
  #syncCursors = new Map<string, Uint8Array>();
  /**
   * The same watermarks for the encrypted-utxo stream that proofless deposits
   * are read from. Mirrors Rust's `Wallet::proofless_cursors`.
   *
   * Separate from `#syncCursors` because they are positions in different
   * streams: reaching the tip of the transaction stream says nothing about
   * where the encrypted-utxo stream has been read to, and sharing one cursor
   * would skip rows in whichever stream is behind.
   */
  #prooflessCursors = new Map<string, Uint8Array>();
  /**
   * The same for the nullifier stream, keyed by nullifier rather than tag.
   * Entries are dropped once the nullifier is spent.
   */
  #nullifierCursors = new Map<string, Uint8Array>();
  #revision = 0;
  #syncQueue: Promise<unknown> = Promise.resolve();
  #reservations: NoteReservation[] = [];

  constructor(input: Readonly<{ identity: ShieldedAddress; registry?: AssetRegistry }>) {
    this.identity = input.identity;
    this.#registry = input.registry?.clone() ?? new AssetRegistry();
    this.#viewingKeyHistory = [newViewingKeyEntry(input.identity.viewingPublicKey, 0n)];
  }

  get registry(): AssetRegistry {
    return this.#registry.clone();
  }

  get viewingKeyHistory(): readonly ViewingKeyEntry[] {
    return this.#viewingKeyHistory.map(snapshotViewingKeyEntry);
  }

  /** Timestamp the last completed sync was told to record, zero before the first. */
  get lastSynced(): bigint {
    return this.#lastSynced;
  }

  /**
   * Cursor this tag's stream has been read to, or `undefined` for a tag never
   * scanned -- which must start from the beginning, not from another tag's
   * position.
   *
   * @internal
   */
  _syncCursor(stream: CursorStream, tag: string): Uint8Array | undefined {
    return this.#cursorsFor(stream).get(tag);
  }

  /** @internal */
  _setSyncCursor(stream: CursorStream, tag: string, cursor: Uint8Array): void {
    this.#cursorsFor(stream).set(tag, Uint8Array.from(cursor));
  }

  /**
   * Forget the watermarks for nullifiers now known spent.
   *
   * A spent nullifier is never queried again, so its watermark is dead weight.
   * Without this the map grows with history even though the query set shrinks.
   *
   * @internal
   */
  _forgetNullifierCursors(spent: ReadonlySet<string>): void {
    for (const nullifier of spent) this.#nullifierCursors.delete(nullifier);
  }

  #cursorsFor(stream: CursorStream): Map<string, Uint8Array> {
    if (stream === "transactions") return this.#syncCursors;
    return stream === "proofless" ? this.#prooflessCursors : this.#nullifierCursors;
  }

  /** @internal */
  _cursorEntries(stream: CursorStream): readonly (readonly [string, Uint8Array])[] {
    return [...this.#cursorsFor(stream)].map(
      ([key, cursor]) => [key, Uint8Array.from(cursor)] as const,
    );
  }

  registerAsset(assetId: bigint, mint: Address): void {
    this.#registry.insert(assetId, mint);
    this.#revision += 1;
  }

  /** Inserts when absent, `false` when the exact pair is present, a conflicting binding raises. */
  ensureAsset(assetId: bigint, mint: Address): boolean {
    const inserted = this.#registry.register(assetId, mint);
    if (inserted) this.#revision += 1;
    return inserted;
  }

  utxos(): readonly WalletUtxo[] {
    return this.#utxos.map(snapshotUtxo);
  }

  privateTransactions(): readonly PrivateTransaction[] {
    return this.#transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
  }

  /**
   * The spendable default-ring balance of one registered mint. A mint the
   * wallet holds no note for still has a balance of zero; only a mint the
   * registry does not know is a rejection.
   */
  balance(mint: Address, filter?: Filter): AssetBalance {
    const assetId = this.#registry.assetId(mint);
    const utxos = this.#utxos
      .filter(
        (entry) =>
          !entry.spent &&
          entry.utxo.asset === mint &&
          entry.utxo.ringProgramId === undefined &&
          (filter === undefined || matches(filter, entry.utxo)),
      )
      .map((entry) => copyUtxo(entry.utxo));
    const amount = checkedBalance(utxos.reduce((sum, utxo) => sum + utxo.amount, 0n));
    return Object.freeze({ assetId, mint, amount, utxos: Object.freeze(utxos) });
  }

  /**
   * One spendable default-ring balance per mint the wallet holds an unspent
   * note of, by asset id. Ring-bound notes appear in `ringBalances`.
   */
  balances(skipUtxos = false): readonly AssetBalance[] {
    return this.#assetBalances((entry) => entry.utxo.ringProgramId === undefined, skipUtxos);
  }

  ringBalances(skipUtxos = false): readonly RingBalance[] {
    const rings = [
      ...new Set(
        this.#utxos.flatMap((entry) =>
          !entry.spent && entry.utxo.ringProgramId !== undefined ? [entry.utxo.ringProgramId] : [],
        ),
      ),
    ].sort();
    return rings.map((ringProgramId) =>
      Object.freeze({
        ringProgramId,
        assets: this.#assetBalances(
          (entry) => entry.utxo.ringProgramId === ringProgramId,
          skipUtxos,
        ),
      }),
    );
  }

  #assetBalances(
    eligible: (entry: WalletUtxo) => boolean,
    skipUtxos: boolean,
  ): readonly AssetBalance[] {
    const notes = this.#utxos.filter((entry) => !entry.spent && eligible(entry));
    const mints = new Set(notes.map((entry) => entry.utxo.asset));
    return [...mints]
      .map((mint) => {
        const utxos = notes
          .filter((entry) => entry.utxo.asset === mint)
          .map((entry) => copyUtxo(entry.utxo));
        const amount = checkedBalance(utxos.reduce((sum, utxo) => sum + utxo.amount, 0n));
        return Object.freeze({
          assetId: this.#registry.assetId(mint),
          mint,
          amount,
          utxos: Object.freeze(skipUtxos ? [] : utxos),
        });
      })
      .sort((left, right) =>
        left.assetId < right.assetId ? -1 : left.assetId > right.assetId ? 1 : 0,
      );
  }

  /** @internal */
  _state(): Readonly<{
    utxos: readonly WalletUtxo[];
    transactions: readonly PrivateTransaction[];
    nullifiers: ReadonlySet<string>;
    viewingKeyHistory: readonly ViewingKeyEntry[];
  }> {
    return {
      utxos: this.#utxos.map(snapshotUtxo),
      transactions: this.privateTransactions(),
      nullifiers: new Set(this.#nullifiers),
      viewingKeyHistory: this.viewingKeyHistory,
    };
  }

  /**
   * Omitting `viewingKeyHistory` leaves retained viewing-key history untouched, and
   * omitting `lastSynced` leaves the sync timestamp untouched.
   * @internal
   */
  _replace(
    input: Readonly<{
      utxos: readonly WalletUtxo[];
      transactions: readonly PrivateTransaction[];
      nullifiers: ReadonlySet<string>;
      viewingKeyHistory?: readonly ViewingKeyEntry[];
      lastSynced?: bigint;
    }>,
  ): void {
    const hashes = new Set<string>();
    for (const entry of input.utxos) {
      const hash = hex(entry.outputContext.hash);
      if (hashes.has(hash)) {
        throw new TransactionError("TRANSACTION_DUPLICATE_OUTPUT", { hash });
      }
      hashes.add(hash);
    }
    this.#utxos = input.utxos.map(snapshotUtxo);
    this.#transactions = input.transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
    this.#nullifiers = new Set(input.nullifiers);
    // A spent nullifier is never queried again, so its watermark is dead weight.
    // Both key spaces are lowercase hex of the same bytes, so the sets line up.
    this._forgetNullifierCursors(this.#nullifiers);
    const unspent = new Set(
      this.#utxos.filter((entry) => !entry.spent).map((entry) => hex(entry.outputContext.hash)),
    );
    this.#reservations = this.#reservations.filter((reservation) =>
      reservation.noteHashes.every((noteHash) => unspent.has(hex(noteHash))),
    );
    if (input.viewingKeyHistory !== undefined) {
      this.#viewingKeyHistory = input.viewingKeyHistory.map(snapshotViewingKeyEntry);
    }
    if (input.lastSynced !== undefined) {
      this.#lastSynced = input.lastSynced;
    }
    this.#revision += 1;
  }

  /** @internal Validates and commits in one synchronous step, never bumps the revision. */
  _reserveNotes(
    input: Readonly<{ noteHashes: readonly Bytes32[]; nowMs: bigint; ttlMs: bigint }>,
  ): NoteReservation {
    this.#sweepReservations(input.nowMs);
    const reserved = this._reservedNoteKeys(input.nowMs);
    const known = new Map(this.#utxos.map((entry) => [hex(entry.outputContext.hash), entry]));
    for (const noteHash of input.noteHashes) {
      const key = hex(noteHash);
      const entry = known.get(key);
      if (entry === undefined || entry.spent) {
        throw new TransactionError("TRANSACTION_RESERVED_NOTE_UNAVAILABLE", { hash: key });
      }
      if (reserved.has(key)) {
        throw new TransactionError("TRANSACTION_NOTE_RESERVED", { hash: key });
      }
    }
    const reservation: NoteReservation = Object.freeze({
      id: randomReservationId(),
      noteHashes: Object.freeze(input.noteHashes.map((noteHash) => copy(noteHash) as Bytes32)),
      expiresAtMs: input.nowMs + input.ttlMs,
    });
    this.#reservations.push(reservation);
    return reservation;
  }

  /** @internal Idempotent. */
  _releaseReservation(id: string): void {
    this.#reservations = this.#reservations.filter((reservation) => reservation.id !== id);
  }

  /** @internal */
  _activeReservations(nowMs: bigint): readonly NoteReservation[] {
    return this.#reservations.filter((reservation) => reservation.expiresAtMs > nowMs);
  }

  /** @internal Hex hashes of every note an unexpired reservation holds. */
  _reservedNoteKeys(nowMs: bigint): ReadonlySet<string> {
    const keys = new Set<string>();
    for (const reservation of this._activeReservations(nowMs)) {
      for (const noteHash of reservation.noteHashes) keys.add(hex(noteHash));
    }
    return keys;
  }

  #sweepReservations(nowMs: bigint): void {
    const unspent = new Set(
      this.#utxos.filter((entry) => !entry.spent).map((entry) => hex(entry.outputContext.hash)),
    );
    this.#reservations = this.#reservations.filter(
      (reservation) =>
        reservation.expiresAtMs > nowMs &&
        reservation.noteHashes.every((noteHash) => unspent.has(hex(noteHash))),
    );
  }

  /** @internal Serialization only, includes expired entries. */
  _reservationEntries(): readonly NoteReservation[] {
    return this.#reservations;
  }

  /** @internal Drops entries that name a spent or unknown note. */
  _restoreReservations(reservations: readonly NoteReservation[]): void {
    const unspent = new Set(
      this.#utxos.filter((entry) => !entry.spent).map((entry) => hex(entry.outputContext.hash)),
    );
    this.#reservations = reservations.filter((reservation) =>
      reservation.noteHashes.every((noteHash) => unspent.has(hex(noteHash))),
    );
  }

  /** @internal */
  get _revision(): number {
    return this.#revision;
  }

  /** @internal Serializes read-modify-write spans. */
  _withSyncLock<T>(run: () => Promise<T>): Promise<T> {
    const next = this.#syncQueue.then(
      () => run(),
      () => run(),
    );
    this.#syncQueue = next.catch(() => undefined);
    return next;
  }

  /** @internal Mutating the copy leaves the origin untouched. */
  _clone(): Wallet {
    const clone = new Wallet({ identity: this.identity, registry: this.#registry });
    clone._replace({ ...this._state(), lastSynced: this.#lastSynced });
    for (const stream of ["transactions", "proofless", "nullifiers"] as const) {
      for (const [key, cursor] of this.#cursorsFor(stream)) {
        clone._setSyncCursor(stream, key, cursor);
      }
    }
    clone.#reservations = [...this.#reservations];
    return clone;
  }

  /**
   * Rows, cursors, and registry additions land in one synchronous step, a
   * revision moved by another writer since the snapshot refuses the commit.
   * @internal
   */
  _commitSync(delta: SyncDelta, expectedRevision: number): void {
    if (this.#revision !== expectedRevision) {
      throw new TransactionError("TRANSACTION_WALLET_STATE_STALE");
    }
    const hashes = new Set<string>();
    for (const entry of delta.utxos) {
      const hash = hex(entry.outputContext.hash);
      if (hashes.has(hash)) {
        throw new TransactionError("TRANSACTION_DUPLICATE_OUTPUT", { hash });
      }
      hashes.add(hash);
    }
    // A conflicting addition must not leave earlier ones applied, the clone
    // absorbs the throw before the real registry changes.
    const staged = this.#registry.clone();
    for (const addition of delta.registryAdditions) {
      staged.register(addition.assetId, addition.mint);
    }
    for (const addition of delta.registryAdditions) {
      this.#registry.register(addition.assetId, addition.mint);
    }
    // Cursors land before `_replace`, a cursor for a nullifier spent in the
    // same delta is pruned within the same commit.
    for (const stream of ["transactions", "proofless", "nullifiers"] as const) {
      for (const [key, cursor] of delta.cursors[stream]) {
        this._setSyncCursor(stream, key, cursor);
      }
    }
    this._replace({
      utxos: delta.utxos,
      transactions: delta.transactions,
      nullifiers: delta.nullifiers,
      viewingKeyHistory: delta.viewingKeyHistory,
      lastSynced: delta.lastSynced,
    });
  }
}

function randomReservationId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return hex(bytes);
}

export function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function checkedBalance(amount: bigint): bigint {
  if (amount > 0xffff_ffff_ffff_ffffn) {
    throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
  }
  return amount;
}
