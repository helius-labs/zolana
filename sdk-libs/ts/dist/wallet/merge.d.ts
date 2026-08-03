import type { ZolanaClient } from "../client/client.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import type { Wallet } from "../transaction/wallet/state.js";
export interface MergeTransactionParams {
    readonly client: ZolanaClient;
    readonly wallet: Wallet;
    readonly authority: WalletAuthority;
    readonly feePayer: Address;
    readonly asset?: Address;
    readonly inputs?: readonly Bytes32[];
}
export declare function buildMergeTransaction(input: MergeTransactionParams, context?: RequestContext): Promise<Transaction>;
