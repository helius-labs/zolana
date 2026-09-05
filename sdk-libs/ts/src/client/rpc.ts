import type { Address, Signature } from "@solana/kit";

import type { Bytes16, Bytes32 } from "../interface/types.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";

export {
  DEFAULT_INDEXER_POLL_CONFIG as DEFAULT_INDEXER_POLL,
  validatePollConfig,
} from "./retry.js";
export type { IndexerPollConfig, IndexerRpcConfig } from "./retry.js";

export interface RpcContext {
  readonly blockTime: bigint;
  /** Highest slot the indexer has persisted. */
  readonly slot: bigint;
}

export interface GetByTagsRequest {
  readonly tags: readonly Bytes32[];
  readonly cursor?: Uint8Array;
  readonly limit?: number;
}

export interface GetByNullifiersRequest {
  readonly nullifiers: readonly Bytes32[];
  readonly cursor?: Uint8Array;
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
  readonly nextCursor?: Uint8Array;
  readonly scannedThrough?: Uint8Array;
}

export interface GetShieldedTransactionsByTagsResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Uint8Array;
  readonly scannedThrough?: Uint8Array;
}

export interface GetShieldedTransactionsByNullifiersResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Uint8Array;
  /**
   * Where the indexer's scan reached. Present only on a page the limit did not
   * truncate. Unspent nullifiers match nothing, so `nextCursor` is absent for
   * them and this is the only resume point.
   */
  readonly scannedThrough?: Uint8Array;
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
  /** Completed Solana slot used to order this state-tree root and assess freshness. */
  readonly rootSeq: bigint;
  /** Actual on-chain cyclic-history position; it is not derivable from `rootSeq`. */
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
  /** On-chain indexed-tree update sequence. */
  readonly rootSeq: bigint;
  /** On-chain root-history position for `root`. */
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
