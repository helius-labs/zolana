import type { RequestContext } from "../interface/types.js";
import type { GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse, GetNonInclusionProofsRequest, GetNonInclusionProofsResponse, GetRingsByNullifiersRequest, GetRingsByTagsRequest, GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureRequest, GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse } from "../indexer/types.js";
export declare class ApiError extends Error {
    readonly code: `API_${string}`;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly cause?: unknown;
    constructor(code: `API_${string}`, message: string, options?: Readonly<{
        details?: Readonly<Record<string, unknown>>;
        cause?: unknown;
    }>);
}
export interface ZolanaApiConfig {
    readonly url: URL | string;
    readonly apiKey?: string;
    readonly fetch?: typeof globalThis.fetch;
}
export declare class ZolanaApi {
    #private;
    constructor(config: ZolanaApiConfig);
    getEncryptedUtxosByTags(request: GetRingsByTagsRequest, context?: RequestContext): Promise<GetEncryptedUtxosByTagsResponse>;
    getShieldedTransactionsByTags(request: GetRingsByTagsRequest, context?: RequestContext): Promise<GetShieldedTransactionsByTagsResponse>;
    getShieldedTransactionsByNullifiers(request: GetRingsByNullifiersRequest, context?: RequestContext): Promise<GetShieldedTransactionsByNullifiersResponse>;
    getShieldedTransactionsBySignature(request: GetShieldedTransactionsBySignatureRequest, context?: RequestContext): Promise<GetShieldedTransactionsBySignatureResponse>;
    getMerkleProofs(request: GetMerkleProofsRequest, context?: RequestContext): Promise<GetMerkleProofsResponse>;
    getNonInclusionProofs(request: GetNonInclusionProofsRequest, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
}
