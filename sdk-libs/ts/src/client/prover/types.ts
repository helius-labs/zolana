import type {
  Bytes32,
  Bytes64,
  Bytes128,
  TransactInstructionData,
  TransactProof,
} from "../../interface/types.js";
import type { ProofInputUtxo } from "../../transaction/utxo.js";

import type { SpendProof } from "../rpc.js";

export type Shape = Readonly<{ inputs: number; outputs: number }>;
export type Field = bigint & { readonly __bn254Field: unique symbol };

export interface TransferInput {
  readonly utxo: ProofInputUtxo;
  readonly isDummy: Field;
  readonly statePathElements: readonly Field[];
  readonly statePathIndex: Field;
  readonly nullifierLowValue: Field;
  readonly nullifierNextValue: Field;
  readonly nullifierLowPathElements: readonly Field[];
  readonly nullifierLowPathIndex: Field;
  readonly utxoTreeRoot: Field;
  readonly nullifierTreeRoot: Field;
  readonly nullifier: Field;
  readonly ownerPublicKeyHash: Field;
  readonly nullifierSecret: Field;
}

export interface TransferOutput {
  readonly utxo: ProofInputUtxo;
  readonly isDummy: Field;
  readonly hash: Field;
  readonly ownerPublicKeyHash: Field;
  readonly nullifierPublicKey: Field;
}

export interface TransferInputs {
  readonly inputs: readonly TransferInput[];
  readonly outputs: readonly TransferOutput[];
  readonly externalDataHash: Field;
  readonly privateTxHash: Field;
  readonly publicAssets: readonly Field[];
  readonly publicAmounts: readonly Field[];
  readonly ringProgramId: Field;
  readonly signerPublicKeyHashes: readonly Field[];
  readonly allowDummyInputs: Field;
  readonly publishedOutputOwnerPublicKeyHashes: readonly Field[];
  readonly publicInputHash: Field;
}

export interface MergeInputs {
  readonly inputs: readonly TransferInput[];
  readonly output: TransferOutput;
  readonly ownerPublicKeyHash: Field;
  readonly userNullifierPublicKey: Field;
  readonly userNullifierSecret: Field;
  readonly externalDataHash: Field;
  readonly privateTxHash: Field;
  readonly allowDummyInputs: Field;
  readonly publicInputHash: Field;
  readonly outputRingDataHash: Field;
  readonly ringProgramId: Field;
}

export type ProverInputs = Readonly<{
  circuit: "transfer" | "transferRing";
  payload: TransferInputs;
}>;

/** The tree history entries the ring statement binds. */
export interface RingTransactRoots {
  readonly stateRoot: Bytes32;
  readonly stateRootIndex: number;
  readonly nullifierRoot: Bytes32;
  readonly nullifierRootIndex: number;
}

export interface AssembledTransfer {
  readonly instructionData: TransactInstructionData;
  readonly proverInputs: ProverInputs;
  readonly publicInputHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly outputHashes: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /// Per input, `[utxoTreeRootIndex, nullifierTreeRootIndex]`, in input order.
  readonly inputRootIndexes: readonly (readonly [number, number])[];
  /// The first input's roots and indices, the pair the ring statement binds.
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
export const RING_STATE_PATH_LENGTH = 32;
export const RING_NULLIFIER_PATH_LENGTH = 40;

/** Mirrors Rust `CustomRingOpening`, one opened UTXO slot in circuit hash order. */
export interface CustomRingOpening {
  readonly domain: Bytes32;
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

/** Mirrors Rust `CustomRingProofRequest`, `auditorPublicKey` is the uncompressed SEC1 point. */
export interface CustomRingProofRequest {
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
  readonly sources: readonly CustomRingSourceOwner[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineCount: number;
  readonly stateRoot: Bytes32;
  readonly nullifierRoot: Bytes32;
  readonly answers: readonly CustomRingRuleAnswer[];
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
  readonly b: Bytes64;
  readonly c: Bytes32;
  readonly commitment?: Bytes32;
  readonly commitmentPok?: Bytes32;
  toTransactProof(): TransactProof;
  /** `a(32) || b(64) || c(32) || commitment(32) || commitmentPok(32)`, Rust `CustomRingProof`. */
  toCustomRingProof(): Uint8Array;
}

export type { SpendProof };
