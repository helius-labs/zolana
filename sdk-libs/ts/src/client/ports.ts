import type { Address, Commitment, Signature } from "@solana/kit";

import type { RequestContext, TransactInstructionData, Bytes32 } from "../interface/types.js";
import type { InputUtxoContext, SppProofInputs } from "../transaction/instructions/transact.js";

import type { LatestBlockhash, SolanaRpc } from "./kit.js";
import type { ProverHealth } from "./prover/client.js";
import type { CustomRingProofRequest } from "./prover/types.js";
import type {
  GetByNullifiersRequest,
  GetByTagsRequest,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
  IndexerRpcConfig,
  ProgramAccount,
  RpcAccount,
  SpendProof,
} from "./rpc.js";

export interface ChainReader {
  getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined>;
  getProgramAccounts(
    programId: Address,
    context?: RequestContext,
  ): Promise<readonly ProgramAccount[]>;
  getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
}

export interface BlockhashProvider {
  getLatestBlockhash(context?: RequestContext): Promise<LatestBlockhash>;
}

export interface IndexerReader {
  getEncryptedUtxosByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetEncryptedUtxosByTagsResponse>;
  getShieldedTransactionsByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse>;
  getShieldedTransactionsByNullifiers(
    request: GetByNullifiersRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByNullifiersResponse>;
  getShieldedTransactionsBySignature(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsBySignatureResponse>;
}

export interface ProofReader {
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

export interface Prover {
  proveTransact(
    proofInputs: SppProofInputs,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData>;
  proveRingTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData>;
  proveCustomRing(inputs: CustomRingProofRequest, context?: RequestContext): Promise<Uint8Array>;
  proverHealth(context?: RequestContext): Promise<ProverHealth>;
}

export interface TransactionConfirmer {
  confirmPrivateTransaction(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<void>;
  confirmTransaction(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<bigint>;
}

export interface KitRpcAccess {
  readonly solanaRpc: SolanaRpc;
  readonly commitment: Commitment;
}
