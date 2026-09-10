import type { ZolanaClient } from "../client/client.js";
import type { RpcAccount } from "../client/rpc.js";
import { type Address, type Bytes32, type Bytes33, type RequestContext, type Transaction } from "../interface/types.js";
import { ShieldedAddress, type ShieldedKeypair } from "../keypair/shielded.js";
type AccountReader = Pick<ZolanaClient, "getAccount">;
export interface ResolvedAddress {
    readonly owner: Address;
    readonly address: ShieldedAddress;
    readonly viewTag: Bytes32;
}
export interface UserRecord {
    readonly owner: Address;
    readonly ownerP256?: Bytes33;
    readonly nullifierPublicKey: Bytes32;
    readonly viewingPublicKey: Bytes33;
    readonly mergingEnabled: boolean;
    readonly bump: number;
}
export declare function internalUserRecordAddress(owner: Address): Promise<Address>;
export declare function internalUserRecordPda(owner: Address): Promise<Readonly<{
    address: Address;
    bump: number;
}>>;
export declare function decodeUserRecordAccount(account: RpcAccount): UserRecord;
export declare function fetchUserRecord(input: Readonly<{
    rpc: AccountReader;
    owner: Address;
}>, context?: RequestContext): Promise<UserRecord | undefined>;
export declare function fetchUserRecordChecked(input: Readonly<{
    rpc: AccountReader;
    owner: Address;
}>, context?: RequestContext): Promise<UserRecord>;
export declare function isWalletRegistered(input: Readonly<{
    rpc: AccountReader;
    owner: Address;
}>, context?: RequestContext): Promise<boolean>;
export declare function resolvedAddressFromRecord(owner: Address, record: UserRecord): ResolvedAddress;
export declare function resolveRegisteredAddress(input: Readonly<{
    rpc: AccountReader;
    owner: Address;
}>, context?: RequestContext): Promise<ResolvedAddress | undefined>;
/**
 * Rejects when the on-chain record under `owner` publishes keys other than
 * `keypair`'s. A shielded identity's nullifier key never rotates, so a
 * difference is an identity conflict rather than stale data.
 */
export declare function validateRegisteredKeypair(input: Readonly<{
    rpc: AccountReader;
    owner: Address;
    keypair: ShieldedKeypair;
}>, context?: RequestContext): Promise<void>;
/**
 * Confidential output view tag for a transfer recipient. A registered owner
 * uses the tag of its published signing key. An unregistered owner, who can
 * only be paid by a public withdrawal, uses the zero tag.
 */
export declare function recipientConfidentialViewTag(input: Readonly<{
    rpc: AccountReader;
    recipient: Address;
}>, context?: RequestContext): Promise<Bytes32>;
export declare function buildRegistrationTransaction(input: Readonly<{
    client: Pick<ZolanaClient, "getAccount" | "getLatestBlockhash">;
    owner: Address;
    address: ShieldedAddress;
}>, context?: RequestContext): Promise<Transaction | undefined>;
export declare function buildSetMergingEnabledTransaction(input: Readonly<{
    client: Pick<ZolanaClient, "getLatestBlockhash">;
    owner: Address;
    enabled: boolean;
}>, context?: RequestContext): Promise<Transaction>;
export {};
