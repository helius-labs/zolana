import type { ZolanaClient } from "../client/client.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import type { Wallet } from "../transaction/wallet/state.js";
import { type TransferDestination } from "./actions.js";
export interface PrivateTransactionParams {
    readonly client: ZolanaClient;
    readonly wallet: Wallet;
    readonly authority: WalletAuthority;
    readonly feePayer: Address;
}
export interface TransferTransactionParams extends PrivateTransactionParams {
    readonly recipient: TransferDestination;
    readonly asset?: Address;
    readonly amount: bigint;
}
export interface WithdrawalTransactionParams extends PrivateTransactionParams {
    readonly recipient: Address;
    readonly asset?: Address;
    readonly amount: bigint;
    readonly splTokenProgram?: Address | null;
}
export interface SplitTransactionParams extends PrivateTransactionParams {
    readonly asset?: Address;
    readonly parts?: number;
    readonly input?: Bytes32;
}
export declare function buildTransferTransaction(input: TransferTransactionParams, context?: RequestContext): Promise<Transaction>;
export declare function buildWithdrawalTransaction(input: WithdrawalTransactionParams, context?: RequestContext): Promise<Transaction>;
export declare function buildSplitTransaction(input: SplitTransactionParams, context?: RequestContext): Promise<Transaction>;
export type { TransferDestination } from "./actions.js";
