export { RING_DEPOSIT_AUDIT_SLOTS } from "../../interface/ring-deposit-capsule.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes64,
  Bytes128,
  TransactInstructionData,
  TransactProof,
  TreeHeadRoots,
} from "../../interface/types.js";
import type { TreeSlot } from "../../interface/tree-slot.js";
import type { SpendProof } from "../rpc.js";

export type Shape = Readonly<{ inputs: number; outputs: number }>;
export type Field = bigint & { readonly __bn254Field: unique symbol };

export interface CircuitUtxo {
  readonly domain: Field;
  readonly owner: Field;
  readonly asset: Field;
  readonly amount: Field;
  readonly blinding: Field;
  readonly dataHash: Field;
  readonly ringDataHash: Field;
  readonly ringProgramId: Field;
}

/**
 * One of the `INPUT_TREES` public tree slots of a proof, as the prover reads
 * it: the raw tree id and the two roots the slot's inputs open against.
 */
export interface TreeSlotFields {
  readonly id: Field;
  readonly utxoRoot: Field;
  readonly nullifierRoot: Field;
}

export interface TransferInput {
  readonly circuit: CircuitUtxo;
  readonly isDummy: Field;
  readonly statePathElements: readonly Field[];
  readonly statePathIndex: Field;
  readonly nullifierLowValue: Field;
  readonly nullifierNextValue: Field;
  readonly nullifierLowPathElements: readonly Field[];
  readonly nullifierLowPathIndex: Field;
  /** Index into `treeSlots` of the slot this input opens against. */
  readonly treeSlot: Field;
  readonly nullifier: Field;
  readonly ownerPublicKeyHash: Field;
  /**
   * The owner's nullifier secret, present once the `ProofAuthority` holding it
   * has completed the input. Absent until then; a dummy slot carries zero.
   */
  readonly nullifierSecret?: Field;
}

export interface TransferOutput {
  readonly circuit: CircuitUtxo;
  readonly isDummy: Field;
  readonly hash: Field;
  readonly ownerPublicKeyHash: Field;
  readonly nullifierPublicKey: Field;
}

export interface TransferInputs {
  readonly inputs: readonly TransferInput[];
  readonly outputs: readonly TransferOutput[];
  /** Exactly `INPUT_TREES` entries; the input tree in slot 0, zero slots after it. */
  readonly treeSlots: readonly TreeSlotFields[];
  readonly outputTreeId: Field;
  readonly externalDataHash: Field;
  readonly privateTxHash: Field;
  /** The proof's private root seed; the circuit derives every output blinding from it. */
  readonly blindingSeed: Field;
  readonly publicAssets: readonly Field[];
  readonly publicAmounts: readonly Field[];
  readonly ringProgramId: Field;
  readonly signerPublicKeyHashes: readonly Field[];
  /** Bit 0 is the dummy-input policy, then three bits of tree slot per input. */
  readonly inputFlags: Field;
  readonly publishedOutputOwnerPublicKeyHashes: readonly Field[];
  /**
   * The cache selection published right after the output owners. A spend that
   * draws no input from a cache publishes the empty selection rather than
   * omitting it, so every owner-signed rail proves on one verifying key with
   * or without a cache.
   */
  readonly cacheTreeId: Field;
  readonly cacheReadHashChain: Field;
  readonly cacheReadHashes: readonly Field[];
  readonly cacheIsCached: readonly Field[];
  readonly cacheReadIndex: readonly Field[];
  readonly publicInputHash: Field;
}

export interface MergeInputs {
  readonly inputs: readonly TransferInput[];
  readonly output: TransferOutput;
  /** Exactly `INPUT_TREES` entries; the input tree in slot 0, zero slots after it. */
  readonly treeSlots: readonly TreeSlotFields[];
  readonly outputTreeId: Field;
  readonly ownerPublicKeyHash: Field;
  readonly userNullifierPublicKey: Field;
  /** Present once the `ProofAuthority` has completed the inputs. */
  readonly userNullifierSecret?: Field;
  readonly externalDataHash: Field;
  readonly privateTxHash: Field;
  readonly allowDummyInputs: Field;
  readonly publicInputHash: Field;
  readonly outputRingDataHash: Field;
  readonly ringProgramId: Field;
}

export type ProverInputs = Readonly<{
  circuit: "transfer" | "transferRing" | "transferRingAuthority";
  payload: TransferInputs;
}>;

/** Selects member authorization or the ring authority statement. */
export type TransferCircuit =
  | Readonly<{ kind: "confidential" }>
  | Readonly<{ kind: "ring"; ring: Address }>
  | Readonly<{ kind: "ringAuthority"; ring: Address }>;

/** The tree history entries the ring statement binds. */
export type RingTransactRoots = TreeHeadRoots;

/**
 * The root history positions every input of one proof references. The
 * shielded pool requires them equal across inputs, so one pair describes the
 * whole instruction.
 */
export interface InputRootIndexes {
  readonly utxoTree: number;
  readonly nullifierTree: number;
}

export interface AssembledTransfer {
  readonly instructionData: TransactInstructionData;
  readonly proverInputs: ProverInputs;
  readonly publicInputHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly outputHashes: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  readonly rootIndexes: InputRootIndexes;
  /** The input tree's roots and positions, the pair the ring statement binds. */
  readonly roots: RingTransactRoots;
  withProof(proof: TransactProof): TransactInstructionData;
}

/** Legacy policy witness widths, shaped policy requests use their declared capacities. */
export const RING_INPUT_SLOTS = 5;
export const RING_OUTPUT_SLOTS = 4;
/** Rust `MAX_RULES` and `MAX_INLINE_ASSETS`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
export const RING_INLINE_ASSET_SLOTS = 8;
/** Rust `ANSWER_SLOTS`, the server rejects any other answers length. */
export const RING_ANSWER_SLOTS = 10;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 8;
/** Rust `MAX_OUTFLOW_LIMITS`, one bound per mint a table limits. */
export const RING_OUTFLOW_LIMIT_SLOTS = 8;
export const RING_STATE_PATH_LENGTH = 32;
export const RING_NULLIFIER_PATH_LENGTH = 40;

/** Mirrors Rust `CustomRingOpening`, one opened UTXO slot in circuit hash order. */
export interface CustomRingOpening {
  readonly domain: Bytes32;
  /** Raw id of the tree the slot hashes under, right aligned. */
  readonly treeId: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
  readonly ctHash?: Bytes32;
}
export interface CustomRingRecordWitness {
  readonly next: Bytes32;
  readonly lists: bigint;
  readonly escrowKey: Bytes32;
  readonly index: bigint;
  readonly path: readonly Bytes32[];
}
export interface CustomRingSubjectWitness extends CustomRingRecordWitness {
  readonly present: boolean;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowLists: bigint;
  readonly lowEscrow: Bytes32;
}
/** A checked record plus its sealed-key ciphertext hash. */
export interface CustomRingRegistryKey extends CustomRingRecordWitness {
  readonly ctHash: Bytes32;
}
export const RING_SUBJECT_SLOTS = RING_INPUT_SLOTS + 2 * RING_OUTPUT_SLOTS;

/** Mirrors Rust `RuleAnswer`, one entry fact proven against the roots. */
export interface CustomRingRuleAnswer {
  readonly enabled: boolean;
  /** Index into the proof's `treeSlots` of the tree the fact is read in. */
  readonly treeSlot: number;
  readonly mode: number;
  readonly listId: number;
  readonly state: number;
  readonly absentBranch: number;
  readonly member: Bytes32;
  readonly contentHash: Bytes32;
  readonly version: bigint;
  readonly blinding: Bytes32;
  readonly low: Bytes32;
  readonly next: Bytes32;
  readonly nullifierPath: readonly Bytes32[];
  readonly nullifierPathIndex: bigint;
  readonly statePath: readonly Bytes32[];
  readonly statePathIndex: bigint;
}

/** Mirrors Rust `RuleAnswer::default`. */
export function disabledRuleAnswer(): CustomRingRuleAnswer {
  const zero = (): Bytes32 => new Uint8Array(32) as Bytes32;
  return Object.freeze({
    enabled: false,
    treeSlot: 0,
    mode: 1,
    listId: 1,
    state: 1,
    absentBranch: 1,
    member: zero(),
    contentHash: zero(),
    version: 0n,
    blinding: zero(),
    low: zero(),
    next: zero(),
    nullifierPath: Object.freeze(Array.from({ length: RING_NULLIFIER_PATH_LENGTH }, () => zero())),
    nullifierPathIndex: 0n,
    statePath: Object.freeze(Array.from({ length: RING_STATE_PATH_LENGTH }, () => zero())),
    statePathIndex: 0n,
  });
}

/** Mirrors Rust `SourceOwner`, slot `i` is empty or serves list `i + 1`. */
export interface CustomRingSourceOwner {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Mirrors Rust `OutflowLimit`, a zero `cap` or `cosignAbove` leaves that bound off. */
export interface CustomRingOutflowLimit {
  readonly asset: Bytes32;
  readonly cap: bigint;
  readonly cosignAbove: bigint;
}

/** Mirrors Rust `OutflowLimitProofInput`, the pinned limits and the approval the transfer proves. */
export interface CustomRingOutflowLimitProofInput {
  readonly limits: readonly CustomRingOutflowLimit[];
  readonly ringId: Bytes32;
  readonly namespaceOwnerHash: Bytes32;
  readonly approvalRequired: boolean;
}

/** A ring without limits still binds its id and namespace. */
export function outflowLimitsOff(
  identity: Readonly<{ ringId: Bytes32; namespaceOwnerHash: Bytes32 }>,
): CustomRingOutflowLimitProofInput {
  return Object.freeze({
    limits: Object.freeze([]),
    ringId: identity.ringId,
    namespaceOwnerHash: identity.namespaceOwnerHash,
    approvalRequired: false,
  });
}

/** Mirrors Rust `CustomRingPolicyProofRequest`, `auditorPublicKey` is the canonical 32-byte X25519 coordinate. */
export interface CustomRingPolicyProofRequest {
  /** Use the fixed 2x3 proof when each registry's records share an eight-leaf subtree. */
  readonly twoByThree?: boolean;
  /** Supported SPP capacities for the shaped policy proof, with witnesses padded to this shape. */
  readonly shape?: Shape;
  /** Prove shared eight-leaf registry paths, or use full paths when omitted. */
  readonly registrySubtree?: boolean;
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  readonly salt: Bytes16;
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
  readonly addressChain: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly sources: readonly CustomRingSourceOwner[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly inlineCount: number;
  /** The populated prefix, one to `INPUT_TREES` policy trees. */
  readonly treeSlots: readonly TreeSlot[];
  readonly addressTreeId: number;
  readonly limits: CustomRingOutflowLimitProofInput;
  readonly keyEscrow: boolean;
  readonly memberRegistryRoot: Bytes32;
  readonly subjects: readonly (CustomRingSubjectWitness | undefined)[];
  readonly foreignRoot: Bytes32;
  readonly foreignSubjects: readonly (CustomRingSubjectWitness | undefined)[];
}

export interface CustomRingBaseProofRequest {
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  readonly salt: Bytes16;
  readonly nOut: number;
  readonly outputs: readonly CustomRingOpening[];
}

/** Proves one batch of deposit openings encrypted to the ring auditor. */
export interface CustomRingDepositProofRequest {
  readonly publicInputHash: Bytes32;
  readonly contextHash: Bytes32;
  readonly count: number;
  /** `ownerHash = Poseidon(ownerPkHash, nullifierPk)` per slot, zero past `count`. */
  readonly ownerPkHashes: readonly Bytes32[];
  readonly nullifierPks: readonly Bytes32[];
  readonly blindings: readonly Bytes32[];
  /** Per slot, absent with escrow off or past `count`. */
  readonly members: readonly (CustomRingRecordWitness | undefined)[];
  readonly ctHashes: readonly Bytes32[];
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  /** Present exactly when the ring escrows nullifier keys. */
  readonly memberRegistryRoot?: Bytes32;
}

export interface CustomRingRegisterKeyProofRequest {
  readonly publicInputHash: Bytes32;
  readonly registryOldRoot: Bytes32;
  readonly registryNewRoot: Bytes32;
  readonly member: Bytes32;
  readonly oldLists: bigint;
  readonly update: import("../../interface/member-registry.js").RecordUpdateWitness;
  readonly nullifierSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
}
export interface CustomRingUpdateMembersProofRequest {
  readonly publicInputHash: Bytes32;
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly items: readonly (import("../../interface/member-registry.js").MemberUpdate &
    Readonly<{ update: import("../../interface/member-registry.js").RecordUpdateWitness }>)[];
}

export interface Proof {
  readonly a: Bytes64;
  readonly b: Bytes128;
  readonly c: Bytes64;
  readonly commitment?: Bytes64;
  readonly commitmentPok?: Bytes64;
}

export interface CompressedProof {
  readonly a: Bytes32;
  readonly b: Bytes128;
  readonly c: Bytes32;
  readonly commitment?: Bytes32;
  readonly commitmentPok?: Bytes32;
  toTransactProof(): TransactProof;
  /** `a(32) || b(64) || c(32) || commitment(32) || commitmentPok(32)`, Rust `CustomRingProof`. */
  toCustomRingProof(): Uint8Array;
}

export type { SpendProof };
