import type { ZolanaClient } from "../client/client.js";
import { type Address, type RequestContext, type Transaction } from "../interface/types.js";
import { ShieldedAddress } from "../keypair/shielded.js";
export interface DepositTransactionParams {
    readonly client: ZolanaClient;
    readonly feePayer: Address;
    readonly depositor?: Address;
    readonly tree?: Address;
    readonly recipient: Address | ShieldedAddress;
    readonly asset?: Address;
    readonly amount: bigint;
    readonly splTokenAccount?: Address;
    readonly splTokenProgram?: Address | null;
    readonly memo?: Uint8Array;
}
export declare function buildDepositTransaction(input: DepositTransactionParams, context?: RequestContext): Promise<Transaction>;
