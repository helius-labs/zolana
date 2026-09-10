import { setTransactionMessageLifetimeUsingBlockhash, type Address, type Instruction, type Rpc, type RpcSubscriptions, type SolanaRpcApi, type SolanaRpcSubscriptionsApi, type Transaction } from "@solana/kit";
import type { RequestContext } from "../interface/types.js";
export type SolanaRpc = Rpc<SolanaRpcApi>;
export type SolanaRpcSubscriptions = RpcSubscriptions<SolanaRpcSubscriptionsApi>;
export interface LatestBlockhash {
    readonly blockhash: Parameters<typeof setTransactionMessageLifetimeUsingBlockhash>[0]["blockhash"];
    readonly lastValidBlockHeight: bigint;
}
export declare function createKitClients(input: Readonly<{
    solanaRpcUrl: string | URL;
    solanaRpcSubscriptionsUrl?: string | URL;
}>): Readonly<{
    solanaRpc: SolanaRpc;
    solanaRpcSubscriptions: SolanaRpcSubscriptions;
}>;
export declare function buildUnsignedTransaction(input: Readonly<{
    feePayer: Address;
    instructions: readonly Instruction[];
    lifetime: LatestBlockhash;
}>): Transaction;
export declare function runKitRpc<T>(method: string, context: RequestContext | undefined, operation: (abortSignal: AbortSignal) => Promise<T>): Promise<T>;
export declare function defaultSolanaRpcSubscriptionsUrl(value: string): string;
