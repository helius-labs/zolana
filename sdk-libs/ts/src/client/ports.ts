import type { X25519PublicKey } from "../keypair/x25519.js";
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
import type {
  ApplyProofInputs,
  MemberRecord,
  QuadPath,
  QueueEntry,
  RecordOpening,
} from "../interface/member-registry.js";
import type { MergeEncryptionScheme } from "../interface/state.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { PreparedMerge } from "../transaction/instructions/builders.js";
import type { InputUtxoContext, SppProofInputs } from "../transaction/instructions/transact.js";
import type { TransactionIntent } from "../transaction/wallet/intent.js";
import { intentHash } from "../transaction/wallet/intent.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import { equal } from "../transaction/internal.js";

import type { LatestBlockhash, SolanaRpc } from "./kit.js";
import type { ProverHealth, ProvingKeyReport } from "./prover/client.js";
import type {
  AnonymousMergeProofRequest,
  RegisterKeyProofRequest,
  RingProofRequest,
} from "./prover/ring.js";
import type {
  AnonymousEddsaAuthorization,
  HiddenOwnerAuthorization,
  MergeInputs,
  PresentRecordOpening,
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

/** A member under the registry state the caller read, Photon refuses another root. */
export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: number;
}

/** A user registry record, the shielded address a Solana pubkey publishes. */
export interface RegistryRecord {
  readonly owner: Address;
  /** Wallet-wide nullifier pubkey. Never rotates. */
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: X25519PublicKey;
  /**
   * Merge opt-in and scheme: `Disabled` refuses `merge_transact`, any other
   * scheme lets any caller merge this owner's UTXOs with exactly that scheme.
   */
  readonly mergeEncryption: MergeEncryptionScheme;
}

/**
 * One entry per requested owner, in request order; `null` for an owner with no
 * record at the slot the registry was read, which is no earlier than
 * `context.slot`.
 */
export interface UserRecordsLookup {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly records: readonly (RegistryRecord | null)[];
}

/** Reads registry records for many owners in one request. */
export interface UserRecordReader {
  getUserRecords(
    owners: readonly Address[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<UserRecordsLookup>;
}

/** A root the registry history holds, `applied` the queue position the floor rule reads. */
export interface RingRegistryRoot {
  readonly root: Bytes32;
  readonly rootIndex: number;
  readonly applied: bigint;
  readonly nextIndex: number;
}

/** The nullifier key a member escrowed through `RegisterKey`, sealed to the auditor. */
export interface RingSealedKey {
  /** The signer whose owner identity is the record's member. */
  readonly owner: Address;
  readonly nullifierPk: Bytes32;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
}

/** An opening the indexer served, unverified until checked against the bound root. */
export type RingMemberOpening = RecordOpening & Readonly<{ sealedKey?: RingSealedKey }>;

export interface RingMemberOpenings {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  /** In request order. */
  readonly openings: readonly RingMemberOpening[];
}

/** The record queue Photon projects, every pending write in queue order. */
export interface RingQueueState {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly head: bigint;
  readonly tail: bigint;
  /** `chain(head - 1)`. */
  readonly chainHead: Bytes32;
  readonly entries: readonly Readonly<{ position: bigint; entry: QueueEntry; slot: bigint }>[];
}

/** An authority list write, the queue entry without an escrow key. */
export interface RecordWrite {
  readonly member: Bytes32;
  readonly mask: bigint;
  readonly value: bigint;
}

export interface RingApplyProofInputs {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  /** Unverified until replayed from the registry the program holds. */
  readonly inputs: ApplyProofInputs;
}

/** The member's record or the low record bracketing its absence. */
export interface RingMemberRecordResult {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  readonly opening: RingMemberOpening;
}

export interface RingMemberPageRequest {
  readonly ringProgramId: Address;
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: number;
  readonly startIndex: number;
  readonly limit: number;
}

/** Leaves from `startIndex` at one root, each with its path. */
export interface RingMemberPage {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: RingRegistryRoot;
  readonly records: readonly Readonly<{
    record: MemberRecord;
    path: QuadPath;
    sealedKey?: RingSealedKey;
  }>[];
  /** `undefined` on the last page. */
  readonly nextLeafIndex: number | undefined;
}

/** The registry as Photon projects it, the account itself is the authority. */
export interface RingRegistryState {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  /** `MEMBER_REGISTRY_ROOT_HISTORY` slots, `undefined` where no root was pushed. */
  readonly history: readonly (
    | Readonly<{ root: Bytes32; applied: bigint; slot: bigint }>
    | undefined
  )[];
  readonly historyCursor: number;
  readonly nextIndex: number;
  readonly floor: bigint;
  readonly priorFloor: bigint;
  readonly floorSlot: bigint;
  /** The path of the empty leaf at `nextIndex`, absent once the registry is full. */
  readonly appendPath?: QuadPath;
}

/** Photon's record projection, the queue and the proof inputs of an application. */
export interface RingRecordReader {
  getRingMemberRecord(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingMemberRecordResult>;
  getRingMemberRecords(
    request: RingMemberPageRequest,
    context?: RequestContext,
  ): Promise<RingMemberPage>;
  getRingMemberRegistryRoot(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingRegistryState>;
  /** At most `MAX_RING_MEMBER_BATCH` members, all under `expectedRoot`. */
  getRingMemberOpenings(
    request: Readonly<{
      ringProgramId: Address;
      members: readonly Bytes32[];
      expectedRoot: Bytes32;
    }>,
    context?: RequestContext,
  ): Promise<RingMemberOpenings>;
  getRingRecordQueue(
    request: Readonly<{ ringProgramId: Address }>,
    context?: RequestContext,
  ): Promise<RingQueueState>;
  /** Every pending write, then `authorityWrites`. */
  getRingApplyProofInputs(
    request: Readonly<{ ringProgramId: Address; authorityWrites: readonly RecordWrite[] }>,
    context?: RequestContext,
  ): Promise<RingApplyProofInputs>;
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

/**
 * What the prover fetches for one input slot: the commitment of a real spend,
 * and for compact padding the derived nullifier its witness is taken for,
 * since the slot publishes 0.
 */
export interface IndexedProofLookup {
  readonly treeSlot: number;
  readonly commitment: Bytes32 | null;
  readonly nullifier: Bytes32 | null;
}

export type IndexedProofInputs = Readonly<{
  readonly trees: readonly IndexedTree[];
  readonly lookups: readonly IndexedProofLookup[];
  readonly publicInputs: readonly Field[];
  readonly minContextSlot?: bigint;
}> &
  (
    | Readonly<{
        circuit: "transfer" | "transferRing" | "transferRingAuthority";
        payload: PreparedTransferInputs;
      }>
    | Readonly<{
        circuit: "transferEddsaRing";
        payload: PreparedTransferInputs;
        authorization: AnonymousEddsaAuthorization;
      }>
    | Readonly<{ circuit: "merge"; payload: PreparedMergeInputs }>
  );

export type ProofDataSource = "client" | "prover";

export interface ProofDataSourceContext {
  readonly proofDataSource: ProofDataSource;
}

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
  proveRing(request: RingProofRequest, context?: RequestContext): Promise<Proof>;
}

/** A ring proof whose nullifier secret only the key holder adds, register key and anonymous merge. */
export type SecretRingProofRequest =
  | Omit<RegisterKeyProofRequest, "nullifierSecret">
  | Omit<AnonymousMergeProofRequest, "nullifierSecret">;

/**
 * The one capability that consumes the nullifier secret: completes proof
 * inputs whose owner it holds the secret for, and proves them. Inputs arrive
 * with `nullifierSecret` absent on the wallet's own real inputs; dummy slots
 * carry zero and any other owner's inputs arrive already complete.
 */
export interface ProofAuthority {
  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof>;
  proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof>;
  /** The holder decides whether its secret may be sealed to the request's auditor key. */
  proveRingWithSecret(request: SecretRingProofRequest, context?: RequestContext): Promise<Proof>;
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

export interface MergeCacheTarget {
  readonly address: Address;
  readonly slot: number;
}

export interface Prover {
  /** One ring proof, the 192-byte `CustomRingProof` the ring program verifies. */
  proveRing(request: RingProofRequest, context?: RequestContext): Promise<Uint8Array>;
  proveRingAuthorityTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    keys: ProofAuthority,
    context?: RequestContext,
    outputTree?: TreeContext,
  ): Promise<ProvenRingTransact>;
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
  /** The hidden owner of an anonymous ring signs `ringSpendMessage` before the proof, the proof carries its BSB22 commitment in `data.circuit`. */
  proveAnonymousRingTransact(
    input: AnonymousRingTransactProofInput,
    context?: RequestContext,
  ): Promise<ProvenRingTransact>;
  /** The ring circuit when `ringProgramId` is non-zero. */
  proveTransferInputs(inputs: TransferInputs, context?: RequestContext): Promise<TransactProof>;
  proverHealth(context?: RequestContext): Promise<ProverHealth>;
  /** The prover's proving keys, checked against the SDK's verifying keys. */
  checkProverProvingKeys(context?: RequestContext): Promise<ProvingKeyReport>;
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

/** The registry opening a ring merge binds to its proof and on-chain root history, Rust `MergeRegistration`. */
export type RingMergeRegistryProof =
  | Readonly<{
      root: Bytes32;
      record: PresentRecordOpening;
      /** `hash_bytes` of the escrowed key ciphertext, its record's escrow key binds it. */
      ctHash: Bytes32;
      anonymous?: false;
    }>
  /** Binds a zero root and opens no record, the ring's merge disclosure proves the owner. */
  | Readonly<{ anonymous: true }>;

/** A proved ring transfer with the tree history entries the ring statement binds. */
export interface AnonymousRingTransactProofInput {
  readonly proofInputs: SppProofInputs;
  readonly ringProgramId: Address;
  readonly owner: HiddenOwnerAuthorization;
  /** The ring's configured co-signer, absent without one. */
  readonly cosigner?: Address;
  /** The owner SPP reads from the SPL withdrawal's token account, absent without one. */
  readonly exitTokenOwner?: Address;
  readonly keys: ProofAuthority;
  readonly config?: RingProvingConfig;
}

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
      cache?: MergeCacheTarget;
      ringRegistry?: RingMergeRegistryProof;
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
  Pick<RingRecordReader, "getRingMemberRecord"> &
  Pick<MergeAssembler, "proveMerge"> &
  Pick<Prover, "proveRing">;

/** A nullifier key encrypted to the ring auditor. */
export interface RingSealedNullifierKey {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
}
