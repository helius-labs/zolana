import type { Address, Bytes32, Signature } from "@zolana/interface";
import type { ShieldedAddress } from "@zolana/keypair";

import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import type { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";

export interface AssetBalance {
  readonly mint: Address;
  readonly amount: bigint;
  readonly spendableAmount: bigint;
}

export interface PrivateTransaction {
  readonly id: Readonly<{ signature: Signature; index: number }>;
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

function snapshotUtxo(value: WalletUtxo): WalletUtxo {
  return Object.freeze({
    ...value,
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
  readonly registry: AssetRegistry;
  #utxos: WalletUtxo[] = [];
  #transactions: PrivateTransaction[] = [];
  #nullifiers = new Set<string>();

  constructor(input: Readonly<{ identity: ShieldedAddress; registry: AssetRegistry }>) {
    this.identity = input.identity;
    this.registry = input.registry;
  }

  utxos(): readonly WalletUtxo[] {
    return this.#utxos.map(snapshotUtxo);
  }

  privateTransactions(): readonly PrivateTransaction[] {
    return this.#transactions.map((transaction) =>
      Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }),
    );
  }

  balance(mint: Address): AssetBalance | undefined {
    const matching = this.#utxos.filter((entry) => !entry.spent && entry.utxo.asset === mint);
    if (matching.length === 0) return undefined;
    const amount = matching.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
    return Object.freeze({ mint, amount, spendableAmount: amount });
  }

  balances(options?: Readonly<{ skipUtxos?: boolean }>): readonly AssetBalance[] {
    void options;
    const mints = new Set(
      this.#utxos.filter((entry) => !entry.spent).map((entry) => entry.utxo.asset),
    );
    return [...mints]
      .sort((left, right) => {
        const leftId = this.registry.assetId(left);
        const rightId = this.registry.assetId(right);
        return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
      })
      .flatMap((mint) => {
        const balance = this.balance(mint);
        return balance ? [balance] : [];
      });
  }

  _state(): Readonly<{
    utxos: readonly WalletUtxo[];
    transactions: readonly PrivateTransaction[];
    nullifiers: ReadonlySet<string>;
  }> {
    return {
      utxos: this.#utxos,
      transactions: this.#transactions,
      nullifiers: this.#nullifiers,
    };
  }

  _replace(
    input: Readonly<{
      utxos: readonly WalletUtxo[];
      transactions: readonly PrivateTransaction[];
      nullifiers: ReadonlySet<string>;
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
  }
}

export function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
