import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";
function matches(filter, utxo) {
    return utxo.amount >= filter.minAmount;
}
/**
 * Sender-side aggregate rows are indexed from here, above every leaf index a
 * tree can hand out, so they cannot collide with a received row.
 */
export const SENDER_HISTORY_ROW_BASE = 1n << 63n;
export function newViewingKeyEntry(viewingPublicKey, createdAt) {
    return Object.freeze({
        viewingPublicKey,
        createdAt,
    });
}
function snapshotViewingKeyEntry(value) {
    return Object.freeze({
        viewingPublicKey: value.viewingPublicKey,
        createdAt: value.createdAt,
    });
}
function copyUtxo(value) {
    return new Utxo({
        owner: value.owner,
        asset: value.asset,
        amount: value.amount,
        blinding: value.blinding,
        data: value.data,
        ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
    });
}
function snapshotUtxo(value) {
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
    identity;
    #registry;
    #viewingKeyHistory;
    #utxos = [];
    #transactions = [];
    #nullifiers = new Set();
    #lastSynced = 0n;
    constructor(input) {
        this.identity = input.identity;
        this.#registry = input.registry?.clone() ?? new AssetRegistry();
        this.#viewingKeyHistory = [newViewingKeyEntry(input.identity.viewingPublicKey, 0n)];
    }
    get registry() {
        return this.#registry.clone();
    }
    get viewingKeyHistory() {
        return this.#viewingKeyHistory.map(snapshotViewingKeyEntry);
    }
    /** Timestamp the last completed sync was told to record, zero before the first. */
    get lastSynced() {
        return this.#lastSynced;
    }
    registerAsset(assetId, mint) {
        this.#registry.insert(assetId, mint);
    }
    utxos() {
        return this.#utxos.map(snapshotUtxo);
    }
    privateTransactions() {
        return this.#transactions.map((transaction) => Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }));
    }
    /**
     * The balance of one registered mint. A mint the wallet holds no note for
     * still has a balance of zero; only a mint the registry does not know is a
     * rejection.
     */
    balance(mint, filter) {
        const assetId = this.#registry.assetId(mint);
        const utxos = this.#utxos
            .filter((entry) => !entry.spent &&
            entry.utxo.asset === mint &&
            (filter === undefined || matches(filter, entry.utxo)))
            .map((entry) => copyUtxo(entry.utxo));
        const amount = checkedBalance(utxos.reduce((sum, utxo) => sum + utxo.amount, 0n));
        return Object.freeze({ assetId, mint, amount, utxos: Object.freeze(utxos) });
    }
    /** One balance per mint the wallet holds an unspent note of, by asset id. */
    balances(skipUtxos = false) {
        const mints = new Set(this.#utxos.filter((entry) => !entry.spent).map((entry) => entry.utxo.asset));
        return [...mints]
            .map((mint) => {
            const balance = this.balance(mint);
            return skipUtxos ? Object.freeze({ ...balance, utxos: Object.freeze([]) }) : balance;
        })
            .sort((left, right) => left.assetId < right.assetId ? -1 : left.assetId > right.assetId ? 1 : 0);
    }
    /** @internal */
    _state() {
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
    _replace(input) {
        const hashes = new Set();
        for (const entry of input.utxos) {
            const hash = hex(entry.outputContext.hash);
            if (hashes.has(hash)) {
                throw new TransactionError("TRANSACTION_DUPLICATE_OUTPUT", { hash });
            }
            hashes.add(hash);
        }
        this.#utxos = input.utxos.map(snapshotUtxo);
        this.#transactions = input.transactions.map((transaction) => Object.freeze({ ...transaction, id: Object.freeze({ ...transaction.id }) }));
        this.#nullifiers = new Set(input.nullifiers);
        if (input.viewingKeyHistory !== undefined) {
            this.#viewingKeyHistory = input.viewingKeyHistory.map(snapshotViewingKeyEntry);
        }
        if (input.lastSynced !== undefined) {
            this.#lastSynced = input.lastSynced;
        }
    }
}
export function hex(bytes) {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function checkedBalance(amount) {
    if (amount > 0xffffffffffffffffn) {
        throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
    }
    return amount;
}
