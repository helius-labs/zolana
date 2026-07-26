import {
  decodeEncryptedUtxosResponse,
  decodeMerkleProofsRequest,
  decodeMerkleProofsResponse,
  decodeNonInclusionProofsRequest,
  decodeNonInclusionProofsResponse,
  decodeNullifierQueueRequest,
  decodeNullifierQueueResponse,
  decodeRingsByTagsRequest,
  decodeShieldedTransactionsResponse,
  encodeEncryptedUtxosResponse,
  encodeMerkleProofsRequest,
  encodeMerkleProofsResponse,
  encodeNonInclusionProofsRequest,
  encodeNonInclusionProofsResponse,
  encodeNullifierQueueRequest,
  encodeNullifierQueueResponse,
  encodeRingsByTagsRequest,
  encodeShieldedTransactionsResponse,
} from "../codec.js";
import {
  GET_ENCRYPTED_UTXOS_BY_TAGS,
  GET_MERKLE_PROOFS,
  GET_NON_INCLUSION_PROOFS,
  GET_NULLIFIER_QUEUE_ELEMENTS,
  GET_SHIELDED_TRANSACTIONS_BY_TAGS,
} from "../names.js";
import type {
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetNullifierQueueElementsRequest,
  GetNullifierQueueElementsResponse,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByTagsResponse,
} from "../types.js";

export interface MethodDescriptor<Request, Response> {
  readonly name: string;
  encodeRequest(value: Request): Readonly<Record<string, unknown>>;
  decodeRequest(value: unknown): Request;
  encodeResponse(value: Response): Readonly<Record<string, unknown>>;
  decodeResponse(value: unknown): Response;
}

export const getEncryptedUtxosByTagsMethod: MethodDescriptor<
  GetRingsByTagsRequest,
  GetEncryptedUtxosByTagsResponse
> = {
  name: GET_ENCRYPTED_UTXOS_BY_TAGS,
  encodeRequest: encodeRingsByTagsRequest,
  decodeRequest: decodeRingsByTagsRequest,
  encodeResponse: encodeEncryptedUtxosResponse,
  decodeResponse: decodeEncryptedUtxosResponse,
};

export const getShieldedTransactionsByTagsMethod: MethodDescriptor<
  GetRingsByTagsRequest,
  GetShieldedTransactionsByTagsResponse
> = {
  name: GET_SHIELDED_TRANSACTIONS_BY_TAGS,
  encodeRequest: encodeRingsByTagsRequest,
  decodeRequest: decodeRingsByTagsRequest,
  encodeResponse: encodeShieldedTransactionsResponse,
  decodeResponse: decodeShieldedTransactionsResponse,
};

export const getMerkleProofsMethod: MethodDescriptor<
  GetMerkleProofsRequest,
  GetMerkleProofsResponse
> = {
  name: GET_MERKLE_PROOFS,
  encodeRequest: encodeMerkleProofsRequest,
  decodeRequest: decodeMerkleProofsRequest,
  encodeResponse: encodeMerkleProofsResponse,
  decodeResponse: decodeMerkleProofsResponse,
};

export const getNonInclusionProofsMethod: MethodDescriptor<
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse
> = {
  name: GET_NON_INCLUSION_PROOFS,
  encodeRequest: encodeNonInclusionProofsRequest,
  decodeRequest: decodeNonInclusionProofsRequest,
  encodeResponse: encodeNonInclusionProofsResponse,
  decodeResponse: decodeNonInclusionProofsResponse,
};

export const getNullifierQueueElementsMethod: MethodDescriptor<
  GetNullifierQueueElementsRequest,
  GetNullifierQueueElementsResponse
> = {
  name: GET_NULLIFIER_QUEUE_ELEMENTS,
  encodeRequest: encodeNullifierQueueRequest,
  decodeRequest: decodeNullifierQueueRequest,
  encodeResponse: encodeNullifierQueueResponse,
  decodeResponse: decodeNullifierQueueResponse,
};
