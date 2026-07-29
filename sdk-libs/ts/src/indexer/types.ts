import type { Address, Signature } from "../interface/types.js";

export type Base64String = string & { readonly __base64: unique symbol };
export type Hash = string & { readonly __hash32Base58: unique symbol };
export type Limit = bigint & { readonly __limit1To1000: unique symbol };

export interface IndexerContext {
  readonly blockTime: bigint;
}

export interface GetRingsByTagsRequest {
  readonly tags: readonly Hash[];
  readonly cursor?: Base64String;
  readonly limit?: Limit;
}

export interface RingsOutputContext {
  readonly hash: Hash;
  readonly tree: Address;
  readonly leafIndex: bigint;
}

export interface RingsOutputSlot {
  readonly viewTag: Hash;
  readonly outputContext: RingsOutputContext;
  readonly payload: Base64String;
}

export interface RingsMessage {
  readonly viewTag: Hash;
  readonly payload: Base64String;
}

export interface EncryptedUtxoMatch {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly outputSlot: RingsOutputSlot;
  readonly txViewingPk?: Base64String;
  readonly salt?: Base64String;
}

export interface GetEncryptedUtxosByTagsResponse {
  readonly context: IndexerContext;
  readonly matches: readonly EncryptedUtxoMatch[];
  readonly nextCursor?: Base64String;
}

export interface IndexedShieldedTransaction {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly txViewingPk?: Base64String;
  readonly salt?: Base64String;
  readonly outputSlots: readonly RingsOutputSlot[];
  readonly messages: readonly RingsMessage[];
  readonly nullifiers: readonly Hash[];
  readonly proofless: boolean;
}

export interface GetShieldedTransactionsByTagsResponse {
  readonly context: IndexerContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Base64String;
}

export interface GetShieldedTransactionsBySignatureRequest {
  readonly txSignature: Signature;
}

export interface SignatureIndexedShieldedTransaction {
  readonly eventIndex: number;
  readonly transaction: IndexedShieldedTransaction;
}

export interface GetShieldedTransactionsBySignatureResponse {
  readonly context: IndexerContext;
  readonly transactions: readonly SignatureIndexedShieldedTransaction[];
}

export interface GetMerkleProofsRequest {
  readonly treeAccount: Address;
  readonly leaves: readonly Hash[];
}

export interface MerkleProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[];
  readonly leafIndex: bigint;
  readonly root: Hash;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}

export interface GetMerkleProofsResponse {
  readonly context: IndexerContext;
  readonly proofs: readonly MerkleProof[];
}

export interface GetNonInclusionProofsRequest {
  readonly treeAccount: Address;
  readonly leaves: readonly Hash[];
}

export interface NonInclusionProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[];
  readonly lowElement: Hash;
  readonly lowElementIndex: bigint;
  readonly highElement: Hash;
  readonly highElementIndex: bigint;
  readonly root: Hash;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}

export interface GetNonInclusionProofsResponse {
  readonly context: IndexerContext;
  readonly proofs: readonly NonInclusionProof[];
}
