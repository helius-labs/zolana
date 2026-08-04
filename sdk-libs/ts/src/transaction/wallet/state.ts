import type { Address, Bytes32, Signature } from "../../interface/types.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress } from "../../keypair/shielded.js";

import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";
import type { DecryptionKeys } from "./authority.js";
import {
  SENDER_HISTORY_ROW_BASE,
  hex,
  newViewingKeyEntry,
  type ViewingKeyEntry,
} from "./primitives.js";
import { decryptIntoState } from "./sync.js";

export { SENDER_HISTORY_ROW_BASE, hex, newViewingKeyEntry, type ViewingKeyEntry };

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

/**
 * A viewing public key retained for historical deposit discovery and
 * decryption after key rotation.
 */
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
    return this.#utxos.map(snapshotUtxo);
  }

  privateTransactions(): readonly PrivateTransaction[] {
    return this.#transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
  }

  /**
   * The balance of one registered mint. A mint the wallet holds no note for
   * still has a balance of zero; only a mint the registry does not know is a
   * rejection.
   */
  balance(mint: Address, filter?: Filter): AssetBalance {
    return balanceOf(this.#utxos, this.#registry, mint, filter);
  }

  /** One balance per mint the wallet holds an unspent note of, by asset id. */
  balances(skipUtxos = false): readonly AssetBalance[] {
    return balancesOf(this.#utxos, this.#registry, skipUtxos);
  }

  /**
   * Decrypt `transactions` and fold what they hold for this wallet into it.
   * Returns counters about the pass; the notes and history land in the wallet.
   *
   * Reading needs no spend authority, so `decryptionKeys` can be a viewing key
   * as well as a full `ShieldedKeypair`.
   */
  decrypt(
    input: Readonly<{
      decryptionKeys: DecryptionKeys;
      transactions: readonly IndexedShieldedTransaction[];
      config?: Readonly<{ syncedAt?: bigint }>;
    }>,
  ): SyncReport {
    const { next, report } = decryptIntoState({
      identity: this.identity,
      registry: this.registry,
      current: this._state(),
      ...input,
    });
    this._replace(next);
    return report;
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
    if (input.viewingKeyHistory !== undefined) {
      this.#viewingKeyHistory = input.viewingKeyHistory.map(snapshotViewingKeyEntry);
    }
    if (input.lastSynced !== undefined) {
      this.#lastSynced = input.lastSynced;
    }
  }
}

function checkedBalance(amount: bigint): bigint {
  if (amount > 0xffff_ffff_ffff_ffffn) {
    throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
  }
  return amount;
}

/**
 * The balance of one registered mint over a set of notes. A mint the notes hold
 * nothing for still has a balance of zero; only a mint the registry does not
 * know is a rejection.
 */
export function balanceOf(
  utxos: readonly WalletUtxo[],
  registry: AssetRegistry,
  mint: Address,
  filter?: Filter,
): AssetBalance {
  const assetId = registry.assetId(mint);
  const unspent = utxos
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.asset === mint &&
        (filter === undefined || matches(filter, entry.utxo)),
    )
    .map((entry) => copyUtxo(entry.utxo));
  const amount = checkedBalance(unspent.reduce((sum, utxo) => sum + utxo.amount, 0n));
  return Object.freeze({ assetId, mint, amount, utxos: Object.freeze(unspent) });
}

/** One balance per mint the notes hold an unspent entry of, by asset id. */
export function balancesOf(
  utxos: readonly WalletUtxo[],
  registry: AssetRegistry,
  skipUtxos = false,
): readonly AssetBalance[] {
  const mints = new Set(utxos.filter((entry) => !entry.spent).map((entry) => entry.utxo.asset));
  return [...mints]
    .map((mint) => {
      const balance = balanceOf(utxos, registry, mint);
      return skipUtxos ? Object.freeze({ ...balance, utxos: Object.freeze([]) }) : balance;
    })
    .sort((left, right) =>
      left.assetId < right.assetId ? -1 : left.assetId > right.assetId ? 1 : 0,
    );
}

/**
 * Decrypted notes as a value. Holds no authority and cannot be updated: a later
 * decrypt produces a new `PrivateBalances` rather than folding into this one.
 */
export interface PrivateBalances {
  balance(mint: Address, filter?: Filter): AssetBalance;
  balances(skipUtxos?: boolean): readonly AssetBalance[];
  utxos(): readonly WalletUtxo[];
  privateTransactions(): readonly PrivateTransaction[];
  /** Counters for the decrypt pass that produced these balances. */
  readonly report: SyncReport;
}

/** @internal */
export function privateBalancesFrom(
  utxos: readonly WalletUtxo[],
  transactions: readonly PrivateTransaction[],
  registry: AssetRegistry,
  report: SyncReport,
): PrivateBalances {
  const notes = utxos.map(snapshotUtxo);
  const rows = transactions.map((transaction) =>
    Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
  );
  const assets = registry.clone();
  return Object.freeze({
    balance: (mint: Address, filter?: Filter) => balanceOf(notes, assets, mint, filter),
    balances: (skipUtxos = false) => balancesOf(notes, assets, skipUtxos),
    utxos: () => notes.map(snapshotUtxo),
    privateTransactions: () => rows,
    report,
  });
}
