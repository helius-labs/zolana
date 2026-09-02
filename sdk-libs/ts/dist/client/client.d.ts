import { type Address, type Commitment, type Instruction, type Signature, type Transaction } from "@solana/kit";
import { type MergeTransactInstructionData } from "../interface/instructions/index.js";
import type { Bytes32, RequestContext, TransactInstructionData, TransactWithdrawal } from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedPublicKey } from "../keypair/public-key.js";
import { PreparedMerge } from "../transaction/instructions/builders.js";
import { SppProofInputs, type InputUtxoContext } from "../transaction/instructions/transact.js";
import { type LatestBlockhash, type SolanaRpc, type SolanaRpcSubscriptions } from "./kit.js";
import { type AsyncPollConfig } from "./prover/client.js";
import { type GetByNullifiersRequest, type GetByTagsRequest, type GetEncryptedUtxosByTagsResponse, type GetMerkleProofsResponse, type GetNonInclusionProofsResponse, type GetShieldedTransactionsByNullifiersResponse, type GetShieldedTransactionsBySignatureResponse, type GetShieldedTransactionsByTagsResponse, type IndexerRpcConfig, type RpcAccount, type SpendProof } from "./rpc.js";
export interface ZolanaClientConfig {
    readonly solanaRpcUrl: string | URL;
    readonly solanaRpcSubscriptionsUrl?: string | URL;
    readonly indexerUrl: string | URL;
    readonly apiKey?: string;
    readonly proverUrl: string | URL;
    readonly tree?: Address;
    readonly commitment?: Commitment;
    readonly computeUnitLimit?: number;
    readonly computeUnitPriceMicroLamports?: bigint;
    readonly indexerConfig?: IndexerRpcConfig;
    readonly proverAsyncPoll?: AsyncPollConfig;
    readonly fetch?: typeof globalThis.fetch;
}
export interface MergeMaterialInput {
    readonly signingPublicKey: ShieldedPublicKey;
    readonly nullifierKey: NullifierKey;
}
export interface ProvedMerge {
    readonly data: MergeTransactInstructionData;
    readonly outputHash: Bytes32;
}
export declare class ZolanaClient {
    #private;
    readonly tree: Address;
    readonly solanaRpc: SolanaRpc;
    readonly solanaRpcSubscriptions: SolanaRpcSubscriptions;
    readonly commitment: Commitment;
    constructor(input: ZolanaClientConfig);
    get indexerConfig(): IndexerRpcConfig;
    getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined>;
    getMultipleAccounts(addresses: readonly Address[], context?: RequestContext): Promise<readonly (RpcAccount | undefined)[]>;
    getBalance(address: Address, context?: RequestContext): Promise<bigint>;
    getLatestBlockhash(context?: RequestContext): Promise<LatestBlockhash>;
    getEncryptedUtxosByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetEncryptedUtxosByTagsResponse>;
    getShieldedTransactionsByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsByTagsResponse>;
    getShieldedTransactionsByNullifiers(request: GetByNullifiersRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsByNullifiersResponse>;
    getShieldedTransactionsBySignature(signature: Signature, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsBySignatureResponse>;
    getMerkleProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetMerkleProofsResponse>;
    getNonInclusionProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
    getInputMerkleProofs(inputUtxoCommitments: readonly InputUtxoContext[], config?: IndexerRpcConfig, context?: RequestContext): Promise<readonly SpendProof[]>;
    proveTransact(proofInputs: SppProofInputs, config?: IndexerRpcConfig, context?: RequestContext): Promise<TransactInstructionData>;
    proveMerge(input: Readonly<{
        prepared: PreparedMerge;
        material: MergeMaterialInput;
        indexer?: Pick<ZolanaClient, "getInputMerkleProofs" | "getNonInclusionProofs">;
    }>, context?: RequestContext): Promise<ProvedMerge>;
}
export declare function buildUnsignedTransaction(input: Readonly<{
    computeUnitLimit: number;
    computeUnitPriceMicroLamports?: bigint;
    feePayer: Address;
    inputTree: Address;
    outputTree: Address;
    setupInstructions?: readonly Instruction[];
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    lifetime: LatestBlockhash;
}>): Transaction;
export declare function buildUnsignedMergeTransaction(input: Readonly<{
    tree: Address;
    feePayer: Address;
    userRecord: Address;
    lifetime: LatestBlockhash;
    data: MergeTransactInstructionData;
}>): Transaction;
