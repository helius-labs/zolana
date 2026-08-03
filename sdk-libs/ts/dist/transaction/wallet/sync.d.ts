import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import type { SyncWalletAuthority } from "./authority.js";
import { type SyncReport, Wallet } from "./state.js";
interface DecryptTransactionsConfig {
    /** Recorded as `Wallet.lastSynced` once the sync commits, as `Wallet::sync` records `synced_at`. */
    readonly syncedAt?: bigint;
}
export declare function decryptTransactions(input: Readonly<{
    wallet: Wallet;
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    config?: DecryptTransactionsConfig;
}>): Promise<SyncReport>;
export declare function decryptTransactionsWorkerEquivalent(input: Parameters<typeof decryptTransactions>[0]): Promise<SyncReport>;
export {};
