import type { Address, Bytes32, RequestContext, Signature, Transaction } from "@zolana/interface";
import type { InputUtxoContext } from "@zolana/transaction";

import { ClientError } from "./error.js";

export interface IndexerPollConfig {
  readonly numRetries: number;
  readonly delayMs: bigint;
  readonly maxDelayMs: bigint;
}

export interface IndexerRpcConfig {
  readonly waitForIndexer: boolean;
  readonly poll: IndexerPollConfig;
}

export interface RpcContext {
  readonly blockTime: bigint;
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
  getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
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

export const DEFAULT_INDEXER_POLL: IndexerPollConfig = Object.freeze({
  numRetries: 10,
  delayMs: 400n,
  maxDelayMs: 8_000n,
});

export function validatePollConfig(config: IndexerPollConfig): IndexerPollConfig {
  const candidate: unknown = config;
  if (typeof candidate !== "object" || candidate === null) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "poll" },
    });
  }
  const value = candidate as Record<string, unknown>;
  const numRetries = value["numRetries"];
  const delayMs = value["delayMs"];
  const maxDelayMs = value["maxDelayMs"];
  if (
    typeof numRetries !== "number" ||
    !Number.isSafeInteger(numRetries) ||
    numRetries < 0 ||
    numRetries > 0xffff_ffff
  ) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "numRetries" },
    });
  }
  if (
    typeof delayMs !== "bigint" ||
    typeof maxDelayMs !== "bigint" ||
    delayMs < 0n ||
    maxDelayMs < 0n ||
    delayMs > 0xffff_ffff_ffff_ffffn ||
    maxDelayMs > 0xffff_ffff_ffff_ffffn ||
    delayMs > maxDelayMs
  ) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "delayMs" },
    });
  }
  return Object.freeze({ numRetries, delayMs, maxDelayMs });
}
