import type { Address, Commitment, Signature } from "@solana/kit";

import type {
  Instruction,
  MergeTransactInstructionData,
  RequestContext,
  Transaction,
  TransactInstructionData,
  TransactProof,
  TransactWithdrawal,
  Bytes32,
} from "../interface/types.js";
import type { P256PublicKey } from "../keypair/public-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import type { InputUtxoContext, SppProofInputs } from "../transaction/instructions/transact.js";
import type { TransactionIntent } from "../transaction/wallet/intent.js";
import { intentHash } from "../transaction/wallet/intent.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import { equal } from "../transaction/internal.js";

import type { LatestBlockhash, SolanaRpc } from "./kit.js";
import type { ProverHealth } from "./prover/client.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingDepositProofRequest,
  CustomRingPolicyProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingRegisterKeyProofRequest,
  MergeInputs,
  Proof,
  ProverInputs,
  RingTransactRoots,
  TransferInputs,
  TransferInput,
  Field,
} from "./prover/types.js";
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

/** Spending windows follow the chain slot clock. */
export interface SlotReader {
  getSlot(context?: RequestContext): Promise<bigint>;
}

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Bytes32;
}

export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: bigint;
}

/** Correlates a member proof with its indexed root and cursor. */
export interface RingMemberProofContext {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: Bytes32;
  readonly nextIndex: bigint;
  readonly member: Bytes32;
}

/** `record` is `null` until the member registers. */
export interface RingSpendRecordLookup {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly record: Readonly<{
    transaction: IndexedShieldedTransaction;
    outputIndex: number;
  }> | null;
}

export interface RingSpendRecordReader {
  getRingSpendRecord(
    request: RingMemberRequest,
    context?: RequestContext,
  ): Promise<RingSpendRecordLookup>;
}

/** Authenticates insertion of a member's encrypted nullifier key. */
export interface RingKeyRegistryRegisterProof extends RingMemberProofContext {
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowKeyHash: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

/** Carries an encrypted key and the path needed to authenticate its opening. */
export interface RingKeyRegistryEntry extends RingMemberProofContext {
  readonly next: Bytes32;
  readonly index: bigint;
  readonly ephemeralPublicKey: P256PublicKey;
  readonly ciphertext: Bytes32;
  readonly proof: readonly Bytes32[];
}

/** Reads encrypted member keys and their registry paths. */
export interface RingKeyRegistryReader {
  getRingKeyRegistryEntry(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryEntry>;
  getRingKeyRegistryRegisterProof(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryRegisterProof>;
}

export type RingSubmissionStatus =
  | Readonly<{ kind: "unknown" }>
  | Readonly<{ kind: "confirmed"; slot: bigint }>
  | Readonly<{ kind: "failed"; instructionIndex?: number; customCode?: number }>
  | Readonly<{ kind: "expired" }>;

/** Identifies a broadcast awaiting confirmation or expiry. */
export interface RingSubmissionPending {
  readonly signature: Signature;
  readonly lastValidBlockHeight: bigint;
}

/** Separates signing and broadcast from submission status resolution. */
export interface RingSubmissionTransport {
  sign(transaction: Transaction, context?: RequestContext): Promise<Transaction>;
  /** A refusal before broadcast returns `failed`, a throw leaves the signature pending. */
  send(
    transaction: Transaction,
    context?: RequestContext,
  ): Promise<RingSubmissionStatus | undefined>;
  status(pending: RingSubmissionPending, context?: RequestContext): Promise<RingSubmissionStatus>;
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

export type PreparedTransferInput = Omit<
  TransferInput,
  | "statePathElements"
  | "statePathIndex"
  | "nullifierLowValue"
  | "nullifierNextValue"
  | "nullifierLowPathElements"
  | "nullifierLowPathIndex"
>;

export type PreparedTransferInputs = Omit<
  TransferInputs,
  "inputs" | "treeSlots" | "publicInputHash"
> & {
  readonly inputs: readonly PreparedTransferInput[];
};

export type PreparedMergeInputs = Omit<MergeInputs, "inputs" | "treeSlots" | "publicInputHash"> & {
  readonly inputs: readonly PreparedTransferInput[];
};

export interface IndexedTree {
  readonly tree: Address;
  readonly id: number;
}

export interface ResolvedProofTree extends IndexedTree {
  readonly utxoRoot: Bytes32;
  readonly nullifierRoot: Bytes32;
  readonly utxoRootIndex: number;
  readonly nullifierRootIndex: number;
}

export interface ProofResolution {
  readonly trees: readonly ResolvedProofTree[];
  readonly publicInputHash: Bytes32;
}

export type IndexedProofInputs = Readonly<{
  readonly trees: readonly IndexedTree[];
  readonly lookups: readonly Readonly<{ treeSlot: number; commitment: Bytes32 | null }>[];
  readonly publicInputs: readonly Field[];
  readonly minContextSlot?: bigint;
}> &
  (
    | Readonly<{ circuit: "transfer" | "transferRing"; payload: PreparedTransferInputs }>
    | Readonly<{ circuit: "merge"; payload: PreparedMergeInputs }>
  );

export interface IndexedProofResult {
  readonly proof: Proof;
  readonly resolution: ProofResolution;
}

export interface IndexedProofAuthority {
  proveIndexed(inputs: IndexedProofInputs, context?: RequestContext): Promise<IndexedProofResult>;
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

export interface RingProvingConfig {
  readonly indexer?: IndexerRpcConfig;
  readonly outputTree?: TreeContext;
}

export interface Prover {
  proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveRingAuthorityTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    keys: ProofAuthority,
    context?: RequestContext,
    outputTree?: TreeContext,
  ): Promise<ProvenRingTransact>;
  proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
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
    config?: RingProvingConfig,
    context?: RequestContext,
  ): Promise<ProvenRingTransact>;
  proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  /** The ring circuit when `ringProgramId` is non-zero. */
  proveTransferInputs(inputs: TransferInputs, context?: RequestContext): Promise<TransactProof>;
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

/** The pool tree the client builds against, by address and by the raw id its commitments hash under. */
export interface TreeContext {
  readonly tree: Address;
  readonly treeId: number;
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

/** A proved ring transfer with the tree history entries the ring statement binds. */
export interface ProvenRingTransact {
  readonly data: TransactInstructionData;
  readonly roots: RingTransactRoots;
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

export type RingMergeClient = TreeContext &
  BlockhashProvider &
  Pick<ChainReader, "getAccount"> &
  Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">;
