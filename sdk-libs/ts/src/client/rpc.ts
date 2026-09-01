import { getBase58Encoder, type Address, type Signature } from "@solana/kit";

import type { Bytes16, Bytes32, ChainPosition } from "../interface/types.js";

export type { ChainPosition } from "../interface/types.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";

export {
  DEFAULT_INDEXER_POLL_CONFIG as DEFAULT_INDEXER_POLL,
  validatePollConfig,
} from "./retry.js";
export type { IndexerPollConfig, IndexerRpcConfig } from "./retry.js";

const signatureEncoder = getBase58Encoder();

/** Orders by slot, then signature bytes, matching the indexer's pagination. */
export function compareChainPositions(left: ChainPosition, right: ChainPosition): number {
  if (left.slot !== right.slot) return left.slot < right.slot ? -1 : 1;
  const leftBytes = signatureEncoder.encode(left.signature);
  const rightBytes = signatureEncoder.encode(right.signature);
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index++) {
    const difference = (leftBytes[index] ?? -1) - (rightBytes[index] ?? -1);
    if (difference !== 0) return difference;
  }
  return 0;
}

export interface RpcContext {
  readonly blockTime: bigint;
  /** Highest slot the indexer has persisted. */
  readonly slot: bigint;
}

export interface GetByTagsRequest {
  readonly tags: readonly Bytes32[];
  readonly since?: ChainPosition;
  readonly limit?: number;
}

export interface GetByNullifiersRequest {
  readonly nullifiers: readonly Bytes32[];
  readonly since?: ChainPosition;
  readonly limit?: number;
}

export interface EncryptedUtxoMatch {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly outputSlot: IndexedShieldedTransaction["outputSlots"][number];
  readonly txViewingPk?: P256PublicKey;
  readonly salt?: Bytes16;
}

export interface GetEncryptedUtxosByTagsResponse {
  readonly context: RpcContext;
  readonly matches: readonly EncryptedUtxoMatch[];
  /** Present only when the limit truncated the page. */
  readonly next?: ChainPosition;
  /** The stream tip, present on a terminal page. */
  readonly latest?: ChainPosition;
}

export interface GetShieldedTransactionsByTagsResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  /** Present only when the limit truncated the page. */
  readonly next?: ChainPosition;
  /** The stream tip, present on a terminal page. */
  readonly latest?: ChainPosition;
}

export interface GetShieldedTransactionsByNullifiersResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  /** Present only when the limit truncated the page. */
  readonly next?: ChainPosition;
  /**
   * The stream tip, present on a terminal page. Unspent nullifiers match
   * nothing, so for them it is the only resume point.
   */
  readonly latest?: ChainPosition;
}

export interface GetShieldedTransactionsBySignatureResponse {
  readonly context: RpcContext;
  readonly transactions: readonly Readonly<{
    eventIndex: number;
    transaction: IndexedShieldedTransaction;
  }>[];
}

export interface MerkleContext {
  readonly treeType: number;
  readonly tree: Address;
}

export interface MerkleProof {
  readonly leaf: Bytes32;
  readonly merkleContext: MerkleContext;
  readonly path: readonly Bytes32[];
  readonly leafIndex: bigint;
  readonly root: Bytes32;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}

export interface NonInclusionProof {
  readonly leaf: Bytes32;
  readonly merkleContext: MerkleContext;
  readonly path: readonly Bytes32[];
  readonly lowElement: Bytes32;
  readonly lowElementIndex: bigint;
  readonly highElement: Bytes32;
  readonly highElementIndex: bigint;
  readonly root: Bytes32;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}

export interface GetMerkleProofsResponse {
  readonly context: RpcContext;
  readonly proofs: readonly MerkleProof[];
}

export interface GetNonInclusionProofsResponse {
  readonly context: RpcContext;
  readonly proofs: readonly NonInclusionProof[];
}

export interface SpendProof {
  readonly state: MerkleProof;
  readonly nullifier: NonInclusionProof;
}

export interface RpcAccount {
  readonly owner: Address;
  readonly data: Uint8Array;
  readonly lamports: bigint;
}

/** One account of a program listing, which carries its own address. */
export interface ProgramAccount {
  readonly address: Address;
  readonly account: RpcAccount;
}
