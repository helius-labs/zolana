import type { Address, Bytes32, Signature } from "../../interface/types.js";
import type { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedAddress } from "../../keypair/shielded.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry } from "./asset.js";
export interface AssetBalance {
    readonly assetId: bigint;
    readonly mint: Address;
    readonly amount: bigint;
    readonly utxos: readonly Utxo[];
}
/** Narrows which unspent notes a balance counts. */
export type Filter = Readonly<{
    kind: "minAmount";
    minAmount: bigint;
}>;
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
export declare const SENDER_HISTORY_ROW_BASE: bigint;
export type PrivateTransactionKind = "deposit" | "privateTransfer" | "publicWithdrawal" | "split" | "merge";
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
export interface ViewingKeyEntry {
    readonly viewingPublicKey: P256PublicKey;
    readonly createdAt: bigint;
}
export declare function newViewingKeyEntry(viewingPublicKey: P256PublicKey, createdAt: bigint): ViewingKeyEntry;
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
export declare class Wallet {
    #private;
    readonly identity: ShieldedAddress;
    constructor(input: Readonly<{
        identity: ShieldedAddress;
        registry?: AssetRegistry;
    }>);
    get registry(): AssetRegistry;
    get viewingKeyHistory(): readonly ViewingKeyEntry[];
    /** Timestamp the last completed sync was told to record, zero before the first. */
    get lastSynced(): bigint;
    registerAsset(assetId: bigint, mint: Address): void;
    utxos(): readonly WalletUtxo[];
    privateTransactions(): readonly PrivateTransaction[];
    /**
     * The balance of one registered mint. A mint the wallet holds no note for
     * still has a balance of zero; only a mint the registry does not know is a
     * rejection.
     */
    balance(mint: Address, filter?: Filter): AssetBalance;
    /** One balance per mint the wallet holds an unspent note of, by asset id. */
    balances(skipUtxos?: boolean): readonly AssetBalance[];
}
export declare function hex(bytes: Uint8Array): string;
