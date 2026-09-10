import type { GetEncryptedUtxosByTagsResponse, GetMerkleProofsRequest, GetMerkleProofsResponse, GetNonInclusionProofsRequest, GetNonInclusionProofsResponse, GetRingsByNullifiersRequest, GetRingsByTagsRequest, GetShieldedTransactionsByNullifiersResponse, GetShieldedTransactionsBySignatureRequest, GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse } from "../types.js";
export interface MethodDescriptor<Request, Response> {
    readonly name: string;
    encodeRequest(value: Request): Readonly<Record<string, unknown>>;
    decodeResponse(value: unknown): Response;
}
export declare const getEncryptedUtxosByTagsMethod: MethodDescriptor<GetRingsByTagsRequest, GetEncryptedUtxosByTagsResponse>;
export declare const getShieldedTransactionsByTagsMethod: MethodDescriptor<GetRingsByTagsRequest, GetShieldedTransactionsByTagsResponse>;
export declare const getShieldedTransactionsByNullifiersMethod: MethodDescriptor<GetRingsByNullifiersRequest, GetShieldedTransactionsByNullifiersResponse>;
export declare const getShieldedTransactionsBySignatureMethod: MethodDescriptor<GetShieldedTransactionsBySignatureRequest, GetShieldedTransactionsBySignatureResponse>;
export declare const getMerkleProofsMethod: MethodDescriptor<GetMerkleProofsRequest, GetMerkleProofsResponse>;
export declare const getNonInclusionProofsMethod: MethodDescriptor<GetNonInclusionProofsRequest, GetNonInclusionProofsResponse>;
