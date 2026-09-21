export const RING_DEPOSIT_AUDIT_SLOTS = 8;
import type {
  Address,
  Bytes32,
  Bytes64,
  Bytes128,
  TransactInstructionData,
  TransactProof,
  TreeHeadRoots,
} from "../../interface/types.js";
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

/** Rust `POLICY_INPUT_SLOTS` and `POLICY_OUTPUT_SLOTS`, the ring circuit's slot counts. */
export const RING_INPUT_SLOTS = 5;
export const RING_OUTPUT_SLOTS = 4;
/** Rust `MAX_RULES` and `MAX_INLINE_ASSETS`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
export const RING_INLINE_ASSET_SLOTS = 8;
/** Rust `ANSWER_SLOTS`, the server rejects any other answers length. */
export const RING_ANSWER_SLOTS = 10;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 8;
/** Rust `MAX_VELOCITY_ASSETS`, one counter per mint a spend record carries. */
export const RING_VELOCITY_SLOTS = 8;
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
}

/** Mirrors Rust `RuleAnswer`, one entry fact proven against the roots. */
export interface CustomRingRuleAnswer {
  readonly enabled: boolean;
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
  readonly ownerHash: Bytes32;
}

/** Sets outflow and approval bounds for one asset. */
export interface CustomRingVelocityRow {
  readonly asset: Bytes32;
  readonly cap: bigint;
  readonly cosignAbove: bigint;
}

/** Opens the previous counters and salts their successor commitment. */
export interface CustomRingSpendRecordProofInput {
  readonly version: bigint;
  readonly window: bigint;
  readonly commitment: Bytes32;
  readonly salt: Bytes32;
  readonly assets: readonly Bytes32[];
  readonly spent: readonly bigint[];
  readonly nextSalt: Bytes32;
}

/** Binds outflow accounting to a ring and its current window. */
export interface CustomRingVelocityProofInput {
  readonly windowSlots: bigint;
  readonly rows: readonly CustomRingVelocityRow[];
  readonly ringId: Bytes32;
  readonly namespaceOwnerHash: Bytes32;
  readonly windowIndex: bigint;
  readonly approvalRequired: boolean;
  readonly record: CustomRingSpendRecordProofInput;
}

const zeroField = (): Bytes32 => new Uint8Array(32) as Bytes32;

export function velocityProofInputOff(
  identity: Readonly<{ ringId: Bytes32; namespaceOwnerHash: Bytes32 }>,
): CustomRingVelocityProofInput {
  return Object.freeze({
    windowSlots: 0n,
    rows: Object.freeze([]),
    ringId: identity.ringId,
    namespaceOwnerHash: identity.namespaceOwnerHash,
    windowIndex: 0n,
    approvalRequired: false,
    record: Object.freeze({
      version: 0n,
      window: 0n,
      commitment: zeroField(),
      salt: zeroField(),
      assets: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, zeroField)),
      spent: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, () => 0n)),
      nextSalt: zeroField(),
    }),
  });
}

/** Mirrors Rust `CustomRingPolicyProofRequest`, `auditorPublicKey` is the uncompressed SEC1 point. */
export interface CustomRingPolicyProofRequest {
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
  readonly addressChain: Bytes32;
  readonly externalDataHash: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly sources: readonly CustomRingSourceOwner[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly inlineCount: number;
  readonly stateRoot: Bytes32;
  readonly nullifierRoot: Bytes32;
  readonly entriesTreeId: number;
  readonly velocity: CustomRingVelocityProofInput;
  readonly answers: readonly CustomRingRuleAnswer[];
}

export interface CustomRingBaseProofRequest {
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
}

/** Proves one batch of deposit openings encrypted to the ring auditor. */
export interface CustomRingDepositProofRequest {
  readonly publicInputHash: Bytes32;
  readonly contextHash: Bytes32;
  readonly count: number;
  readonly ownerHashes: readonly Bytes32[];
  readonly blindings: readonly Bytes32[];
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
}

/** Proves policy satisfaction with the member's compressed head update. */
export interface CustomRingCompressedPolicyProofRequest {
  readonly policy: CustomRingPolicyProofRequest;
  readonly headOldRoot: Bytes32;
  readonly headNewRoot: Bytes32;
  readonly headNext: Bytes32;
  readonly headIndex: bigint;
  readonly headProof: readonly Bytes32[];
}

/** Mirrors Go `headInsertion`, the append both registration circuits prove. */
export interface CustomRingHeadInsertion {
  readonly headOldRoot: Bytes32;
  readonly headNewRoot: Bytes32;
  readonly member: Bytes32;
  readonly newIndex: bigint;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowNullifier: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

/** Adds the initial spend record to the member head map. */
export interface CustomRingRegisterProofRequest extends CustomRingHeadInsertion {
  readonly publicInputHash: Bytes32;
  readonly genesis: Bytes32;
}

/** Proves disclosure of a member nullifier key to the auditor. */
export interface CustomRingRegisterKeyProofRequest extends CustomRingHeadInsertion {
  readonly publicInputHash: Bytes32;
  readonly nullifierSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
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
  /** `a(32) || b(64) || c(32)`, a proof without a BSB22 commitment. */
  toPlainProof(): Uint8Array;
}

export type { SpendProof };
