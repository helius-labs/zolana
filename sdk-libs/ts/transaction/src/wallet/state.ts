import type { Address, Bytes32, Signature } from "@zolana/interface";
import type { P256PublicKey, ShieldedAddress } from "@zolana/keypair";

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

export interface PrivateTransaction {
  readonly id: Readonly<{ signature: Signature; index: bigint }>;
  readonly kind: "deposit" | "transfer" | "withdrawal" | "split" | "merge";
  readonly direction: "incoming" | "outgoing" | "self";
  readonly status: "pending" | "confirmed";
  readonly slot: bigint;
}

export interface SyncReport {
  readonly received: number;
  readonly spent: number;
  readonly transactions: number;
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
