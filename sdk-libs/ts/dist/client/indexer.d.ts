import { ZolanaApi } from "../api/index.js";
import type { Address, Bytes32, RequestContext, Signature } from "../interface/types.js";
import { type IndexerRpcConfig } from "./retry.js";
import { type GetByNullifiersRequest, type GetByTagsRequest, type GetEncryptedUtxosByTagsResponse, type GetMerkleProofsResponse, type GetNonInclusionProofsResponse, type GetShieldedTransactionsByNullifiersResponse, type GetShieldedTransactionsBySignatureResponse, type GetShieldedTransactionsByTagsResponse } from "./rpc.js";
export declare class ZolanaIndexer {
    #private;
    constructor(api: ZolanaApi);
    getEncryptedUtxosByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetEncryptedUtxosByTagsResponse>;
    getShieldedTransactionsByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsByTagsResponse>;
    getShieldedTransactionsByNullifiers(request: GetByNullifiersRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsByNullifiersResponse>;
    getShieldedTransactionsBySignature(signature: Signature, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsBySignatureResponse>;
    getMerkleProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetMerkleProofsResponse>;
    getNonInclusionProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
}
