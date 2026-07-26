import type { Address, Bytes32, Signature } from "@zolana/interface";
import type { P256PublicKey, ShieldedAddress } from "@zolana/keypair";

import { TransactionError } from "../error.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import { copy } from "../internal.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";
import type { WalletSyncAuthority } from "./authority.js";
// sync.js imports this module in turn. The cycle is safe because neither side
// touches the other while evaluating: the call happens inside a method body.
import { syncWalletWithMaterial, type WalletSyncConfig } from "./sync.js";

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
  "deposit" | "privateTransfer" | "publicWithdrawal" | "split" | "merge";

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
}

export interface CounterpartyCounter {
  readonly counterparty: P256PublicKey;
  readonly count: bigint;
}

/**
 * How far each tag family of one viewing key has been scanned. A sync resumes
 * from these counters and queries `count + window` tags per family, so a
 * counterparty that has advanced its own counter stays reachable.
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
  #lastSynced = 0n;

  constructor(input: Readonly<{ identity: ShieldedAddress; registry: AssetRegistry }>) {
    this.identity = input.identity;
    this.#registry = input.registry.clone();
    this.#viewingKeyHistory = [newViewingKeyEntry(input.identity.viewingPublicKey, 0n)];
  }

  /**
   * Decrypt `transactions` into a wallet of their own, mirroring Rust's
   * `decrypt_transactions`. The authority supplies both the identity the wallet
   * is built around and the viewing keys the notes are opened with, so a caller
   * holding only keys and a page of transactions reads a balance without
   * assembling wallet state first.
   *
   * This walks exactly the transactions it is given. Finding them is the
   * caller's problem, and `syncWallet` in `@zolana/wallet` is the incremental
   * path that queries the indexer and keeps one wallet up to date instead.
   */
  static async decrypt(
    input: Readonly<{
      authority: WalletSyncAuthority;
      transactions: readonly IndexedShieldedTransaction[];
      assets: AssetRegistry;
      config?: WalletSyncConfig;
    }>,
  ): Promise<Wallet> {
    // Rust's free `decrypt_transactions` open-codes this construct-sync path
    // and drops the wallet after reading balances. The method keeps the wallet
    // so a caller that wants the notes — not only the balances — can take it.
    const material = await input.authority.syncMaterial();
    const wallet = new Wallet({ identity: material.identity, registry: input.assets });
    syncWalletWithMaterial({
      wallet,
      material,
      transactions: input.transactions,
      ...(input.config === undefined ? {} : { config: input.config }),
    });
    return wallet;
  }

  /**
   * The live asset registry. Mutations land on the wallet, matching Rust's
   * public `registry` field; use `registerAsset` when the typed wallet path is
   * preferred.
   */
  get registry(): AssetRegistry {
    return this.#registry;
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
    const assetId = this.#registry.assetId(mint);
    const utxos = this.#utxos
      .filter(
        (entry) =>
          !entry.spent &&
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
      this.#utxos.filter((entry) => !entry.spent).map((entry) => entry.utxo.asset),
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
