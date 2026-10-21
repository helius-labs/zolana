export { RING_DEPOSIT_AUDIT_SLOTS } from "../../interface/ring-deposit-capsule.js";
import type {
  Address,
  Bsb22Commitment,
  Bytes32,
  Bytes64,
  Bytes128,
  TransactInstructionData,
  TransactProof,
  TreeHeadRoots,
} from "../../interface/types.js";
import type { RecordOpening } from "../../interface/member-registry.js";
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
  /** One per output on a ring rail, zero for an exit or a dummy, empty on the default rail. */
  readonly ringSecrets: readonly Field[];
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
  /** A ring merge proves a registered, auditor-recoverable owner key. Absent on plain merges. */
  readonly memberRegistryRoot?: Field;
  /** Both absent exactly when `anonymous` is set. */
  readonly registeredCiphertextHash?: Field;
  readonly memberRecord?: PresentRecordOpening;
  /** An anonymous ring escrows no key, its merge disclosure proves the output owner instead. */
  readonly anonymous?: true;
}

export type ProverInputs =
  | Readonly<{
      circuit: "transfer" | "transferRing" | "transferRingAuthority";
      payload: TransferInputs;
    }>
  | Readonly<{
      circuit: "transferEddsaRing";
      payload: TransferInputs;
      authorization: AnonymousEddsaAuthorization;
    }>;

/** The hidden owner's signature over `ringSpendMessage`, made before the proof. Rust `HiddenOwnerAuthorization`. */
export interface HiddenOwnerAuthorization {
  readonly publicKey: Bytes32;
  readonly signature: Bytes64;
}

/** The hidden owner fields of an anonymous ring proof, Rust `AnonymousEddsaAuthorization`. */
export interface AnonymousEddsaAuthorization {
  readonly ownerPublicKey: Bytes32;
  readonly ownerSignature: Bytes64;
  /** Preimage of the public ring id, bound inside the signed message. */
  readonly ringProgramAddress: Bytes32;
  readonly messageDigest: Bytes32;
  /** Zero unless the hidden owner spends a default-ring UTXO. */
  readonly defaultOwnerPkHash: Bytes32;
  /** Payer, co-signer and exit destination identities, zero when absent. */
  readonly parties: readonly [Bytes32, Bytes32, Bytes32];
}

/** Selects member authorization, the hidden owner of an anonymous ring or the ring authority statement. */
export type TransferCircuit =
  | Readonly<{ kind: "confidential" }>
  | Readonly<{ kind: "ring"; ring: Address }>
  | Readonly<{
      kind: "ringAnonymous";
      ring: Address;
      owner: HiddenOwnerAuthorization;
      /** The ring's configured co-signer, the circuit proves the owner apart from it. */
      cosigner?: Address;
      /** The owner SPP reads from the SPL withdrawal's token account. */
      exitTokenOwner?: Address;
    }>
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
  /** `commitment` is required on the anonymous rail and refused on every other. */
  withProof(proof: TransactProof, commitment?: Bsb22Commitment): TransactInstructionData;
}

/** Rust `MAX_RULES` and `MAX_INLINE_ASSETS`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
export const RING_INLINE_ASSET_SLOTS = 8;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 8;
/** Rust `MAX_OUTFLOW_LIMITS`, one bound per mint a table limits. */
export const RING_OUTFLOW_LIMIT_SLOTS = 8;
export const RING_STATE_PATH_LENGTH = 32;

/** Rust `ANONYMOUS_MERGE_WIDTHS`, the merge widths whose disclosure still fits one v1 transaction. */
export const ANONYMOUS_MERGE_WIDTHS: readonly number[] = Object.freeze([8, 24]);

/** A member's record in a member registry, the opening a ring merge proves. */
export type PresentRecordOpening = Extract<RecordOpening, { kind: "present" }>;

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
