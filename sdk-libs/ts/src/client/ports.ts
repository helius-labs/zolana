import type { Address, Commitment, Signature } from "@solana/kit";

import type {
  Instruction,
  MergeTransactInstructionData,
  RequestContext,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
  Bytes32,
} from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedPublicKey } from "../keypair/public-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import type { InputUtxoContext, SppProofInputs } from "../transaction/instructions/transact.js";
import type { TransactionIntent } from "../transaction/wallet/intent.js";
import { intentHash } from "../transaction/wallet/intent.js";
import { equal } from "../transaction/internal.js";

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

/** The pool tree the client builds against. */
export interface TreeContext {
  readonly tree: Address;
}

/** @internal */
export interface AuthorizedPrivateTransactionMaterial {
  readonly proofInputs: SppProofInputs;
  readonly withdrawal?: TransactWithdrawal;
  readonly tree: Address;
  readonly intent: TransactionIntent;
  readonly senderOutputCount: number;
  readonly owner: ShieldedAddress;
  readonly setupInstructions: readonly Instruction[];
}

export abstract class AuthorizedPrivateTransaction {
  readonly #authorization = true;

  protected constructor() {
    void this.#authorization;
  }
}

class AuthorizedPrivateTransactionToken extends AuthorizedPrivateTransaction {
  constructor() {
    super();
  }
}

interface AuthorizedPrivateTransactionState {
  readonly material: AuthorizedPrivateTransactionMaterial;
  readonly approvedIntentHash: Uint8Array;
}

const authorizedPrivateTransactions = new WeakMap<
  AuthorizedPrivateTransaction,
  AuthorizedPrivateTransactionState
>();

/** @internal */
export function mintAuthorizedPrivateTransaction(
  material: Omit<AuthorizedPrivateTransactionMaterial, "setupInstructions"> &
    Readonly<{ setupInstructions?: readonly Instruction[] }>,
  approvedIntentHash: Bytes32,
): AuthorizedPrivateTransaction {
  const token = new AuthorizedPrivateTransactionToken();
  Object.freeze(token);
  authorizedPrivateTransactions.set(token, {
    material: Object.freeze({
      ...material,
      intent: Object.freeze({ ...material.intent }),
      setupInstructions: Object.freeze([...(material.setupInstructions ?? [])]),
    }),
    approvedIntentHash: new Uint8Array(approvedIntentHash),
  });
  return token;
}

/** @internal */
export function authorizedPrivateTransactionMaterial(
  value: unknown,
): AuthorizedPrivateTransactionMaterial | undefined {
  if (!(value instanceof AuthorizedPrivateTransaction)) return undefined;
  const state = authorizedPrivateTransactions.get(value);
  if (state === undefined || !equal(intentHash(state.material.intent), state.approvedIntentHash)) {
    return undefined;
  }
  return state.material;
}

export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierKey: NullifierKey;
}

export interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}

export interface TransactionAssembler {
  assembleAuthorizedPrivateTransaction(
    input: Readonly<{
      authorized: AuthorizedPrivateTransaction;
      feePayer: Address;
    }>,
    context?: RequestContext,
  ): Promise<Transaction>;
}

export interface MergeAssembler {
  proveMerge(
    input: Readonly<{
      prepared: PreparedMerge;
      material: MergeMaterialInput;
      indexer?: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">;
    }>,
    context?: RequestContext,
  ): Promise<ProvedMerge>;
  assembleAuthorizedMergeTransaction(
    input: Readonly<{
      proved: ProvedMerge;
      feePayer: Address;
      userRecord: Address;
    }>,
    context?: RequestContext,
  ): Promise<Transaction>;
}
