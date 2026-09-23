import {
  decodeEncryptedUtxosResponse,
  decodeMerkleProofsResponse,
  decodeNonInclusionProofsResponse,
  decodeShieldedTransactionsBySignatureResponse,
  decodeShieldedTransactionsResponse,
  encodeMerkleProofsRequest,
  encodeNonInclusionProofsRequest,
  encodeRingsByNullifiersRequest,
  encodeRingsByTagsRequest,
  encodeShieldedTransactionsBySignatureRequest,
  encodeRingMemberProofRequest,
  encodeRingMemberRequest,
  decodeRingSpendRecordResponse,
  decodeRingKeyRegistryEntry,
  decodeRingKeyRegistryRegisterProof,
} from "../codec.js";
import {
  GET_ENCRYPTED_UTXOS_BY_TAGS,
  GET_MERKLE_PROOFS,
  GET_NON_INCLUSION_PROOFS,
  GET_RING_SPEND_RECORD,
  GET_RING_KEY_REGISTRY_ENTRY,
  GET_RING_KEY_REGISTRY_REGISTER_PROOF,
  GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS,
  GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE,
  GET_SHIELDED_TRANSACTIONS_BY_TAGS,
} from "../names.js";
import type {
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetRingsByNullifiersRequest,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureRequest,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
  GetRingSpendRecordResponse,
  RingMemberProofRequest,
  RingMemberRequest,
  RingKeyRegistryEntry,
  RingKeyRegistryRegisterProof,
} from "../types.js";

export interface MethodDescriptor<Request, Response> {
  readonly name: string;
  encodeRequest(value: Request): Readonly<Record<string, unknown>>;
  decodeResponse(value: unknown): Response;
}

export const getRingSpendRecordMethod: MethodDescriptor<
  RingMemberRequest,
  GetRingSpendRecordResponse
> = {
  name: GET_RING_SPEND_RECORD,
  encodeRequest: encodeRingMemberRequest,
  decodeResponse: decodeRingSpendRecordResponse,
};
export const getRingKeyRegistryEntryMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingKeyRegistryEntry
> = {
  name: GET_RING_KEY_REGISTRY_ENTRY,
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingKeyRegistryEntry,
};
export const getRingKeyRegistryRegisterProofMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingKeyRegistryRegisterProof
> = {
  name: GET_RING_KEY_REGISTRY_REGISTER_PROOF,
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingKeyRegistryRegisterProof,
};

export const getEncryptedUtxosByTagsMethod: MethodDescriptor<
  GetRingsByTagsRequest,
  GetEncryptedUtxosByTagsResponse
> = {
  name: GET_ENCRYPTED_UTXOS_BY_TAGS,
  encodeRequest: encodeRingsByTagsRequest,
  decodeResponse: decodeEncryptedUtxosResponse,
};

export const getShieldedTransactionsByTagsMethod: MethodDescriptor<
  GetRingsByTagsRequest,
  GetShieldedTransactionsByTagsResponse
> = {
  name: GET_SHIELDED_TRANSACTIONS_BY_TAGS,
  encodeRequest: encodeRingsByTagsRequest,
  decodeResponse: decodeShieldedTransactionsResponse,
};

export const getShieldedTransactionsByNullifiersMethod: MethodDescriptor<
  GetRingsByNullifiersRequest,
  GetShieldedTransactionsByNullifiersResponse
> = {
  name: GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS,
  encodeRequest: encodeRingsByNullifiersRequest,
  decodeResponse: decodeShieldedTransactionsResponse,
};

export const getShieldedTransactionsBySignatureMethod: MethodDescriptor<
  GetShieldedTransactionsBySignatureRequest,
  GetShieldedTransactionsBySignatureResponse
> = {
  name: GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE,
  encodeRequest: encodeShieldedTransactionsBySignatureRequest,
  decodeResponse: decodeShieldedTransactionsBySignatureResponse,
};

export const getMerkleProofsMethod: MethodDescriptor<
  GetMerkleProofsRequest,
  GetMerkleProofsResponse
> = {
  name: GET_MERKLE_PROOFS,
  encodeRequest: encodeMerkleProofsRequest,
  decodeResponse: decodeMerkleProofsResponse,
};

export const getNonInclusionProofsMethod: MethodDescriptor<
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse
> = {
  name: GET_NON_INCLUSION_PROOFS,
  encodeRequest: encodeNonInclusionProofsRequest,
  decodeResponse: decodeNonInclusionProofsResponse,
};
