import type { Address, Signature } from "../../interface/types.js";
import { type DataRecord } from "../data.js";
import { Wallet, type PrivateTransactionDirection, type PrivateTransactionKind } from "./state.js";
interface SerializedViewingKeyEntry {
    readonly viewingPublicKey: string;
    readonly createdAt: string;
}
interface SerializedDataRecord {
    readonly kind: DataRecord["kind"];
    readonly bytes: string;
}
interface SerializedWalletUtxo {
    readonly owner: string;
    readonly asset: Address;
    readonly amount: string;
    readonly blinding: string;
    readonly data: readonly SerializedDataRecord[];
    readonly zoneProgramId?: Address;
    readonly outputContext: Readonly<{
        hash: string;
        tree: Address;
        leafIndex: string;
    }>;
    readonly nullifier: string;
    readonly dataHash?: string;
    readonly zoneDataHash?: string;
    readonly spent: boolean;
}
interface SerializedPrivateTransaction {
    readonly id: Readonly<{
        signature: Signature;
        slot: string;
        index: string;
    }>;
    readonly kind: PrivateTransactionKind;
    readonly direction: PrivateTransactionDirection;
    readonly status: "confirmed";
    readonly asset: Address;
    readonly amount: string;
    readonly counterpartyViewingPublicKey?: string;
}
/**
 * Versioned, JSON-safe wallet state. It contains private note plaintext and
 * blindings, but never signing, nullifier, or viewing secrets. Applications
 * must still encrypt it at rest.
 */
export interface SerializedWalletState {
    readonly version: 1;
    readonly identity: Readonly<{
        signingPublicKey: string;
        nullifierPublicKey: string;
        viewingPublicKey: string;
    }>;
    readonly assets: readonly Readonly<{
        assetId: string;
        mint: Address;
    }>[];
    readonly viewingKeyHistory: readonly SerializedViewingKeyEntry[];
    readonly utxos: readonly SerializedWalletUtxo[];
    readonly transactions: readonly SerializedPrivateTransaction[];
    readonly nullifiers: readonly string[];
    readonly lastSynced: string;
}
export declare function serializeWallet(wallet: Wallet): string;
export declare function deserializeWallet(serialized: string): Wallet;
export {};
