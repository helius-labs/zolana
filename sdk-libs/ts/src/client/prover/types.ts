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
  /** The `hash_bytes_32` chunks of the merged mint; the circuit derives the asset from them. */
  readonly mintChunks: readonly [Field, Field];
  /** Per-proof pad nonce of the output ciphertext, a public input. */
  readonly outputCiphertextSalt: Field;
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
}

export type { SpendProof };
