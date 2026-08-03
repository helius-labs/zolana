import type { ZolanaClient } from "../client/client.js";
import { type Address, type Bytes32, type RequestContext, type TransactWithdrawal } from "../interface/types.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
interface UnsignedSpendInput {
    readonly entry: WalletUtxo;
}
type PrivateAction = Readonly<{
    kind: "transfer";
    recipient: ShieldedAddress;
    asset: Address;
    amount: bigint;
}> | Readonly<{
    kind: "withdrawal";
    asset: Address;
    amount: bigint;
    target: Readonly<{
        kind: "sol";
        recipient: Address;
    }> | Readonly<{
        kind: "spl";
        userTokenAccount: Address;
        splTokenInterface: Address;
        vaultBump: number;
    }>;
}> | Readonly<{
    kind: "split";
    asset: Address;
    numOutputs: number;
    perOutputAmount: bigint;
}>;
export declare class UnsignedPrivateTransaction {
    #private;
    constructor(input: Readonly<{
        payer: Address;
        tree: Address;
        inputs: readonly UnsignedSpendInput[];
        action: PrivateAction;
        withdrawal?: TransactWithdrawal;
        summary: string;
    }>);
    payer(): Address;
    tree(): Address;
    inputCount(): number;
}
export interface TransferParams {
    readonly client?: Pick<ZolanaClient, "getAccount">;
    readonly wallet: Wallet;
    readonly payer: Address;
    readonly recipient: TransferDestination;
    readonly asset: Address;
    readonly amount: bigint;
}
export type TransferDestination = Address | ShieldedAddress;
export interface WithdrawalParams {
    readonly wallet: Wallet;
    readonly payer: Address;
    readonly recipient: Address;
    readonly asset: Address;
    readonly amount: bigint;
    readonly splTokenProgram?: Address | null;
}
export type TransferRecipient = Readonly<{
    kind: "shielded";
    address: ShieldedAddress;
    viewTag: Bytes32;
}> | Readonly<{
    kind: "registered";
    owner: Address;
    address: ShieldedAddress;
    viewTag: Bytes32;
}>;
export interface CreatedTransfer {
    readonly transaction: UnsignedPrivateTransaction;
    readonly recipient: TransferRecipient;
}
export interface CreatedWithdrawal {
    readonly transaction: UnsignedPrivateTransaction;
    readonly withdrawal: TransactWithdrawal;
}
export interface SplitParams {
    readonly wallet: Wallet;
    readonly payer: Address;
    readonly asset: Address;
    readonly parts: number;
    readonly input?: Bytes32;
}
export interface CreatedSplit {
    readonly transaction: UnsignedPrivateTransaction;
    readonly numOutputs: number;
    readonly perOutputAmount: bigint;
}
export declare function createWithdrawal(params: WithdrawalParams): Promise<CreatedWithdrawal>;
export declare function createTransfer(params: TransferParams, context?: RequestContext): Promise<CreatedTransfer>;
export declare function createSplit(params: SplitParams): CreatedSplit;
export {};
