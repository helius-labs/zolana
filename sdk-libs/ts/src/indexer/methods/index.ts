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
  encodeRingMemberRecordsRequest,
  decodeRingMemberOpening,
  decodeRingMemberPage,
  decodeRingRegistryState,
  encodeRingMemberRegistryRootRequest,
  decodeRingApplyProofInputs,
  decodeRingMemberOpenings,
  decodeRingRecordQueue,
  encodeRingApplyProofInputsRequest,
  encodeRingMemberOpeningsRequest,
  decodeUserRecordsResponse,
  encodeUserRecordsRequest,
} from "../codec.js";
import {
  GET_ENCRYPTED_UTXOS_BY_TAGS,
  GET_MERKLE_PROOFS,
  GET_NON_INCLUSION_PROOFS,
  GET_RING_MEMBER_RECORD,
  GET_RING_MEMBER_RECORDS,
  GET_RING_MEMBER_REGISTRY_ROOT,
  GET_RING_APPLY_PROOF_INPUTS,
  GET_RING_MEMBER_OPENINGS,
  GET_RING_RECORD_QUEUE,
  GET_SHIELDED_TRANSACTIONS_BY_NULLIFIERS,
  GET_SHIELDED_TRANSACTIONS_BY_SIGNATURE,
  GET_SHIELDED_TRANSACTIONS_BY_TAGS,
  GET_USER_RECORDS,
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
  GetUserRecordsRequest,
  GetUserRecordsResponse,
  RingMemberProofRequest,
  RingMemberOpeningResponse,
  RingMemberPageResponse,
  RingMemberRecordsRequest,
  RingRegistryStateResponse,
  RingApplyProofInputsRequest,
  RingApplyProofInputsResponse,
  RingMemberOpeningsRequest,
  RingMemberOpeningsResponse,
  RingRecordQueueResponse,
} from "../types.js";

export interface MethodDescriptor<Request, Response> {
  readonly name: string;
  encodeRequest(value: Request): Readonly<Record<string, unknown>>;
  decodeResponse(value: unknown): Response;
}

export const getRingMemberRecordMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingMemberOpeningResponse
> = {
  name: GET_RING_MEMBER_RECORD,
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingMemberOpening,
};
export const getRingMemberRecordsMethod: MethodDescriptor<
  RingMemberRecordsRequest,
  RingMemberPageResponse
> = {
  name: GET_RING_MEMBER_RECORDS,
  encodeRequest: encodeRingMemberRecordsRequest,
  decodeResponse: decodeRingMemberPage,
};
export const getRingMemberRegistryRootMethod: MethodDescriptor<
  Readonly<{ ringProgramId: import("../../interface/types.js").Address }>,
  RingRegistryStateResponse
> = {
  name: GET_RING_MEMBER_REGISTRY_ROOT,
  encodeRequest: encodeRingMemberRegistryRootRequest,
  decodeResponse: decodeRingRegistryState,
};

export const getRingMemberOpeningsMethod: MethodDescriptor<
  RingMemberOpeningsRequest,
  RingMemberOpeningsResponse
> = {
  name: GET_RING_MEMBER_OPENINGS,
  encodeRequest: encodeRingMemberOpeningsRequest,
  decodeResponse: decodeRingMemberOpenings,
};
export const getRingRecordQueueMethod: MethodDescriptor<
  Readonly<{ ringProgramId: import("../../interface/types.js").Address }>,
  RingRecordQueueResponse
> = {
  name: GET_RING_RECORD_QUEUE,
  encodeRequest: encodeRingMemberRegistryRootRequest,
  decodeResponse: decodeRingRecordQueue,
};
export const getRingApplyProofInputsMethod: MethodDescriptor<
  RingApplyProofInputsRequest,
  RingApplyProofInputsResponse
> = {
  name: GET_RING_APPLY_PROOF_INPUTS,
  encodeRequest: encodeRingApplyProofInputsRequest,
  decodeResponse: decodeRingApplyProofInputs,
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

export const getUserRecordsMethod: MethodDescriptor<GetUserRecordsRequest, GetUserRecordsResponse> =
  {
    name: GET_USER_RECORDS,
    encodeRequest: encodeUserRecordsRequest,
    decodeResponse: decodeUserRecordsResponse,
  };
