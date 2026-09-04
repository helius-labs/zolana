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
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import type { InputUtxoContext, SppProofInputs } from "../transaction/instructions/transact.js";
import type { TransactionIntent } from "../transaction/wallet/intent.js";
import { intentHash } from "../transaction/wallet/intent.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import { equal } from "../transaction/internal.js";

import type { LatestBlockhash, SolanaRpc } from "./kit.js";
import type { ProverHealth } from "./prover/client.js";
import type { CustomRingProofRequest, MergeInputs, Proof, ProverInputs } from "./prover/types.js";
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

/**
 * Proves inputs that are complete. What an in-process `ProofAuthority`
 * forwards to once it has filled the nullifier secrets in; the prover server
 * behind `ZolanaClient`.
 */
export interface ProofService {
  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof>;
  proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof>;
}

/**
 * The one capability that consumes the nullifier secret: completes proof
 * inputs whose owner it holds the secret for, and proves them. Inputs arrive
 * with `nullifierSecret` absent on the wallet's own real inputs; dummy slots
 * carry zero and any other owner's inputs arrive already complete.
 */
export interface ProofAuthority {
  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof>;
  proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof>;
}

/**
 * Everything a wallet needs of its privacy roles: the derivations
 * (`ShieldedKeys`) and proving (`ProofAuthority`). `LocalKeys` answers both
 * in-process; a remote key holder answers both over its own transport.
 */
export type WalletKeys = ShieldedKeys & ProofAuthority;

export interface Prover {
  proveTransact(
    proofInputs: SppProofInputs,
    keys: ProofAuthority,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData>;
  proveRingTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    keys: ProofAuthority,
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

export interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}

export interface TransactionAssembler {
  assembleAuthorizedPrivateTransaction(
    input: Readonly<{
      authorized: AuthorizedPrivateTransaction;
      feePayer: Address;
      keys: ProofAuthority;
    }>,
    context?: RequestContext,
  ): Promise<Transaction>;
}

export interface MergeAssembler {
  proveMerge(
    input: Readonly<{
      prepared: PreparedMerge;
      keys: ProofAuthority;
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
