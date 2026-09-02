import { decodeEncryptedUtxosResponse, decodeMerkleProofsResponse, decodeNonInclusionProofsResponse, decodeShieldedTransactionsByNullifiersResponse, decodeShieldedTransactionsBySignatureResponse, decodeShieldedTransactionsResponse, encodeMerkleProofsRequest, encodeNonInclusionProofsRequest, encodeRingsByNullifiersRequest, encodeRingsByTagsRequest, encodeShieldedTransactionsBySignatureRequest, } from "../codec.js";
import { GET_ENCRYPTED_UTXOS_BY_TAGS, GET_MERKLE_PROOFS, GET_NON_INCLUSION_PROOFS, GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS, GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE, GET_SHIELDED_TRANSACTIONS_BY_TAGS, } from "../names.js";
export const getEncryptedUtxosByTagsMethod = {
    name: GET_ENCRYPTED_UTXOS_BY_TAGS,
    encodeRequest: encodeRingsByTagsRequest,
    decodeResponse: decodeEncryptedUtxosResponse,
};
export const getShieldedTransactionsByTagsMethod = {
    name: GET_SHIELDED_TRANSACTIONS_BY_TAGS,
    encodeRequest: encodeRingsByTagsRequest,
    decodeResponse: decodeShieldedTransactionsResponse,
};
export const getShieldedTransactionsByNullifiersMethod = {
    name: GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS,
    encodeRequest: encodeRingsByNullifiersRequest,
    decodeResponse: decodeShieldedTransactionsByNullifiersResponse,
};
export const getShieldedTransactionsBySignatureMethod = {
    name: GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE,
    encodeRequest: encodeShieldedTransactionsBySignatureRequest,
    decodeResponse: decodeShieldedTransactionsBySignatureResponse,
};
export const getMerkleProofsMethod = {
    name: GET_MERKLE_PROOFS,
    encodeRequest: encodeMerkleProofsRequest,
    decodeResponse: decodeMerkleProofsResponse,
};
export const getNonInclusionProofsMethod = {
    name: GET_NON_INCLUSION_PROOFS,
    encodeRequest: encodeNonInclusionProofsRequest,
    decodeResponse: decodeNonInclusionProofsResponse,
};
