import { type Address, type Signature } from "@solana/kit";

import type { Bytes16, Bytes32, PageOptions, PaginationToken } from "../interface/types.js";
export type { HistoryFilters, PaginationToken, SlotFilter } from "../interface/types.js";

import type { X25519PublicKey } from "../keypair/x25519.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";

export {
  DEFAULT_INDEXER_POLL_CONFIG as DEFAULT_INDEXER_POLL,
  validatePollConfig,
} from "./retry.js";
export type { IndexerPollConfig, IndexerRpcConfig } from "./retry.js";

export type { PageOptions } from "../interface/types.js";

export interface RpcContext {
  readonly blockTime: bigint;
  /** Highest slot the indexer has persisted. */
  readonly slot: bigint;
}

export interface GetByTagsRequest extends PageOptions {
  readonly tags: readonly Bytes32[];
  readonly ringProgramId?: Address;
}

export interface GetByNullifiersRequest extends PageOptions {
  readonly nullifiers: readonly Bytes32[];
}

export interface EncryptedUtxoMatch {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly outputSlot: IndexedShieldedTransaction["outputSlots"][number];
  readonly txViewingPk?: X25519PublicKey;
  readonly salt?: Bytes16;
}

export interface Page<T> {
  readonly context: RpcContext;
  readonly items: readonly T[];
  /** Pass back as `paginationToken` for the next page, `null` when the history has no more results. */
  readonly paginationToken: PaginationToken | null;
}
export interface TransactionEvents<T> {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly events: readonly T[];
}
export interface TransactionOutputs<T> {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly outputs: readonly T[];
}
export type GetEncryptedUtxosByTagsResponse = Page<TransactionOutputs<EncryptedUtxoMatch>>;
export type GetShieldedTransactionsByTagsResponse = Page<
  TransactionEvents<IndexedShieldedTransaction>
>;
export type GetShieldedTransactionsByNullifiersResponse = GetShieldedTransactionsByTagsResponse;

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
