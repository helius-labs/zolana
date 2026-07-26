import type {
  Address,
  Bytes16,
  Bytes32,
  RequestContext,
  Signature,
  Transaction,
} from "@zolana/interface";
import type { P256PublicKey } from "@zolana/keypair";
import type { InputUtxoContext } from "@zolana/transaction";
import type { IndexedShieldedTransaction } from "@zolana/transaction/instructions";

import type { IndexerRpcConfig } from "./retry.js";

export {
  DEFAULT_INDEXER_POLL_CONFIG as DEFAULT_INDEXER_POLL,
  validatePollConfig,
} from "./retry.js";
export type { IndexerPollConfig, IndexerRpcConfig } from "./retry.js";

export interface RpcContext {
  readonly blockTime: bigint;
}

export interface GetByTagsRequest {
  readonly tags: readonly Bytes32[];
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
}

export interface GetShieldedTransactionsByTagsResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Uint8Array;
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

export interface Rpc {
  getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined>;
  getProgramAccounts?(
    programAddress: Address,
    context?: RequestContext,
  ): Promise<readonly Readonly<{ address: Address; account: RpcAccount }>[]>;
  getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
  getMinimumBalanceForRentExemption?(dataLength: number, context?: RequestContext): Promise<bigint>;
  getLatestBlockhash(
    context?: RequestContext,
  ): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>>;
  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature>;
  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean>;
  transactOutputViewTags(
    signature: Signature,
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse>;
  getInputMerkleProofs(
    inputUtxoCommitments: readonly InputUtxoContext[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<readonly SpendProof[]>;
}
