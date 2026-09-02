import type { ZolanaClient } from "../client/client.js";
import { type IndexerPollConfig } from "../client/retry.js";
import type { RequestContext } from "../interface/types.js";
import { type AssetBalance, type PrivateTransaction, type SyncReport, type Wallet } from "../transaction/wallet/state.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
type SyncClient = Pick<ZolanaClient, "solanaRpc" | "commitment" | "getEncryptedUtxosByTags" | "getShieldedTransactionsByNullifiers" | "getShieldedTransactionsByTags">;
export interface SyncWalletConfig {
    /** Stable tags and nullifiers per indexer request. Defaults to 64. */
    readonly queryChunk?: number;
    /** Rows requested per indexer page. Defaults to Photon's maximum, 1000. */
    readonly pageLimit?: number;
    readonly waitForIndexer?: boolean;
    readonly retry?: IndexerPollConfig;
}
export declare function backfillAssetRegistry(wallet: Wallet, registryRpc: Pick<ZolanaClient, "solanaRpc" | "commitment">, context?: RequestContext): Promise<number>;
export declare function syncWallet(input: Readonly<{
    wallet: Wallet;
    authority: WalletAuthority;
    client: SyncClient;
    config?: SyncWalletConfig;
}>, context?: RequestContext): Promise<SyncReport>;
export declare function getPrivateTokenBalances(wallet: Wallet): readonly AssetBalance[];
export declare function getPrivateTransactions(wallet: Wallet): readonly PrivateTransaction[];
export {};
