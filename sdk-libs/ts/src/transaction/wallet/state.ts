import type { Address, Bytes32, Signature } from "../../interface/index.js";
import type { P256PublicKey, ShieldedAddress } from "../../keypair/index.js";

import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";

export interface AssetBalance {
  readonly assetId: bigint;
  readonly mint: Address;
  readonly amount: bigint;
  readonly utxos: readonly Utxo[];
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
  | "publicWithdrawal"
  | "split"
  | "merge";

export type PrivateTransactionDirection = "inbound" | "outbound" | "selfTransfer";

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

export interface CounterpartyCounter {
  readonly counterparty: P256PublicKey;
  readonly count: bigint;
}

/**
 * How far each tag family of one viewing key has been discovered. A sync
 * queries through `count + window` for each family, so a counterparty that has
 * advanced its own counter stays reachable.
 */
export interface ViewingKeyEntry {
  readonly viewingPublicKey: P256PublicKey;
  readonly createdAt: bigint;
  readonly txCount: bigint;
  readonly requestCount: bigint;
  readonly knownSenders: readonly CounterpartyCounter[];
  readonly knownRecipients: readonly CounterpartyCounter[];
}

export function newViewingKeyEntry(
  viewingPublicKey: P256PublicKey,
  createdAt: bigint,
): ViewingKeyEntry {
  return Object.freeze({
    viewingPublicKey,
    createdAt,
    txCount: 0n,
    requestCount: 0n,
    knownSenders: Object.freeze([]),
    knownRecipients: Object.freeze([]),
  });
}

function snapshotViewingKeyEntry(value: ViewingKeyEntry): ViewingKeyEntry {
  return Object.freeze({
    ...value,
    knownSenders: Object.freeze(value.knownSenders.map((entry) => Object.freeze({ ...entry }))),
    knownRecipients: Object.freeze(
      value.knownRecipients.map((entry) => Object.freeze({ ...entry })),
    ),
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
  readonly zoneDataHash?: Bytes32;
  readonly spent: boolean;
}

function copyUtxo(value: Utxo): Utxo {
  return new Utxo({
    owner: value.owner,
    asset: value.asset,
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
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
    ...(value.zoneDataHash === undefined ? {} : { zoneDataHash: copy(value.zoneDataHash) }),
  });
}

export class Wallet {
  readonly identity: ShieldedAddress;
  readonly #registry: AssetRegistry;
  #viewingKeyHistory: ViewingKeyEntry[];
  #utxos: WalletUtxo[] = [];
  #transactions: PrivateTransaction[] = [];
  #nullifiers = new Set<string>();
  readonly #reservations = new Map<string, symbol>();
  #lastSynced = 0n;

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

  registerAsset(assetId: bigint, mint: Address): void {
    this.#registry.insert(assetId, mint);
  }

  utxos(): readonly WalletUtxo[] {
    return this.#utxos.map((entry) =>
      snapshotUtxo(
        this.#reservations.has(hex(entry.outputContext.hash)) ? { ...entry, spent: true } : entry,
      ),
    );
  }

  privateTransactions(): readonly PrivateTransaction[] {
    return this.#transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
  }

  /**
   * Conservatively reserve inputs once Solana accepts a submitted transaction.
   * Sync later confirms the same state from indexed nullifiers; until then these
   * notes must not be selected again for a competing proof.
   */
  _markSubmitted(outputHashes: readonly Bytes32[]): void {
    const submitted = new Set(outputHashes.map(hex));
    for (const hash of submitted) this.#reservations.delete(hash);
    this.#utxos = this.#utxos.map((entry) =>
      entry.spent || !submitted.has(hex(entry.outputContext.hash))
        ? entry
        : Object.freeze({ ...entry, spent: true }),
    );
  }

  /**
   * Atomically reserves a set of inputs before any authority or prover await.
   * Reservations are process-local and become ordinary spent flags only when
   * the submission path reaches its final send boundary.
   */
  _reserveSubmission(outputHashes: readonly Bytes32[]): symbol {
    const token = Symbol("wallet submission");
    const hashes = outputHashes.map(hex);
    const seen = new Set<string>();
    for (const [index, hash] of hashes.entries()) {
      const available = this.#utxos.some(
        (entry) => !entry.spent && hex(entry.outputContext.hash) === hash,
      );
      if (!available || seen.has(hash) || this.#reservations.has(hash)) {
        throw new TransactionError("TRANSACTION_INPUT_RESERVED", { index });
      }
      seen.add(hash);
    }
    for (const hash of hashes) this.#reservations.set(hash, token);
    return token;
  }

  _canSpendReserved(outputHash: Bytes32, token?: symbol): boolean {
    const reservation = this.#reservations.get(hex(outputHash));
    return reservation === undefined || reservation === token;
  }

  _releaseSubmission(token: symbol): void {
    for (const [hash, reservation] of this.#reservations) {
      if (reservation === token) this.#reservations.delete(hash);
    }
  }

  _commitSubmission(token: symbol): void {
    const submitted: Bytes32[] = [];
    for (const entry of this.#utxos) {
      if (this.#reservations.get(hex(entry.outputContext.hash)) === token) {
        submitted.push(entry.outputContext.hash);
      }
    }
    this._markSubmitted(submitted);
  }

  /**
   * The balance of one registered mint. A mint the wallet holds no note for
   * still has a balance of zero; only a mint the registry does not know is a
   * rejection.
   */
  balance(mint: Address, filter?: Filter): AssetBalance {
    const assetId = this.#registry.assetId(mint);
    const utxos = this.#utxos
      .filter(
        (entry) =>
          !entry.spent &&
          !this.#reservations.has(hex(entry.outputContext.hash)) &&
          entry.utxo.asset === mint &&
          (filter === undefined || matches(filter, entry.utxo)),
      )
      .map((entry) => copyUtxo(entry.utxo));
    const amount = checkedBalance(utxos.reduce((sum, utxo) => sum + utxo.amount, 0n));
    return Object.freeze({ assetId, mint, amount, utxos: Object.freeze(utxos) });
  }

  /** One balance per mint the wallet holds an unspent note of, by asset id. */
  balances(skipUtxos = false): readonly AssetBalance[] {
    const mints = new Set(
      this.#utxos
        .filter((entry) => !entry.spent && !this.#reservations.has(hex(entry.outputContext.hash)))
        .map((entry) => entry.utxo.asset),
    );
    return [...mints]
      .map((mint) => {
        const balance = this.balance(mint);
        return skipUtxos ? Object.freeze({ ...balance, utxos: Object.freeze([]) }) : balance;
      })
      .sort((left, right) =>
        left.assetId < right.assetId ? -1 : left.assetId > right.assetId ? 1 : 0,
      );
  }

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
   * Omitting `viewingKeyHistory` leaves the scan position untouched, and
   * omitting `lastSynced` leaves the sync timestamp untouched.
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
    const spendable = new Set(
      this.#utxos.filter((entry) => !entry.spent).map((entry) => hex(entry.outputContext.hash)),
    );
    for (const hash of this.#reservations.keys()) {
      if (!spendable.has(hash)) this.#reservations.delete(hash);
    }
    this.#transactions = input.transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
    this.#nullifiers = new Set(input.nullifiers);
    if (input.viewingKeyHistory !== undefined) {
      this.#viewingKeyHistory = input.viewingKeyHistory.map(snapshotViewingKeyEntry);
    }
    if (input.lastSynced !== undefined) {
      this.#lastSynced = input.lastSynced;
    }
  }
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
