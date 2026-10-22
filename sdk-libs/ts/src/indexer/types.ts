import type { MergeEncryptionScheme } from "../interface/state.js";
import type { Address, Cursor, Signature } from "../interface/types.js";

export type { Cursor } from "../interface/types.js";

export type Base64String = string & { readonly __base64: unique symbol };
export type Hash = string & { readonly __hash32Base58: unique symbol };
export type Limit = bigint & { readonly __limit1To1000: unique symbol };

export interface IndexerContext {
  readonly blockTime: bigint;
  /** Highest slot the indexer has persisted. */
  readonly slot: bigint;
}

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Hash;
}

export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Hash;
  readonly expectedNextIndex: bigint;
}

/** Reports the projection cursor and root of a member proof. */
export interface RingMemberProofContext {
  readonly context: IndexerContext;
  readonly root: Hash;
  readonly nextIndex: bigint;
  readonly member: Hash;
}

/** `record` is `null` until the member registers. */
export interface GetRingSpendRecordResponse {
  readonly context: IndexerContext;
  readonly record: Readonly<{
    transaction: IndexedShieldedTransaction;
    outputIndex: number;
  }> | null;
}

export interface RingKeyRegistryRegisterProof extends RingMemberProofContext {
  readonly lowMember: Hash;
  readonly lowNext: Hash;
  readonly lowKeyHash: Hash;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Hash[];
  readonly newProof: readonly Hash[];
}

/** Carries the encrypted nullifier key and its registry path. */
export interface RingKeyRegistryEntry extends RingMemberProofContext {
  readonly next: Hash;
  readonly index: bigint;
  readonly ephPk: Base64String;
  readonly ciphertext: Base64String;
  readonly proof: readonly Hash[];
}

export interface GetRingsByTagsRequest {
  readonly tags: readonly Hash[];
  readonly after?: Cursor;
  readonly limit?: Limit;
  readonly minContextSlot?: bigint;
  /**
   * Restrict the match to one ring. Its config account is derived from this
   * program id, so the filter needs no indexed registration.
   */
  readonly ringProgramId?: Address;
}

export interface GetRingsByNullifiersRequest {
  readonly nullifiers: readonly Hash[];
  readonly after?: Cursor;
  readonly limit?: Limit;
  readonly minContextSlot?: bigint;
}

export interface RingsOutputContext {
  readonly treeId: number;
  readonly hash: Hash;
  readonly tree: Address;
  readonly leafIndex: bigint;
}

export interface RingsOutputSlot {
  readonly viewTag: Hash;
  readonly outputContext: RingsOutputContext;
  readonly payload: Base64String;
}

export interface RingsMessage {
  readonly viewTag: Hash;
  readonly payload: Base64String;
}

export interface EncryptedUtxoMatch {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly outputSlot: RingsOutputSlot;
  readonly txViewingPk?: Base64String;
  readonly salt?: Base64String;
}

export interface Page<T> {
  readonly outputTreeId?: number;
  readonly context: IndexerContext;
  readonly items: readonly T[];
  readonly cursor: Cursor | null;
  readonly hasMore: boolean;
}
export interface TransactionEvents<T> {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly events: readonly T[];
}
export interface TransactionOutputs<T> {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly outputs: readonly T[];
}
export type GetEncryptedUtxosByTagsResponse = Page<TransactionOutputs<EncryptedUtxoMatch>>;

export interface IndexedShieldedTransaction {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly eventIndex?: number;
  readonly txViewingPk?: Base64String;
  readonly salt?: Base64String;
  readonly outputSlots: readonly RingsOutputSlot[];
  readonly messages: readonly RingsMessage[];
  readonly nullifiers: readonly Hash[];
  readonly proofless: boolean;
  /**
   * The ring's config account (its `ring_auth` PDA), absent when no ring
   * authorized this transaction. Observed directly on the transaction.
   */
  readonly ringConfig?: Address;
  /**
   * The ring's program, resolved through the indexed registrations. Absent when
   * `ringConfig` is absent, and also when the registration itself was never
   * indexed -- so `ringConfig` is what separates "no ring" from "ring whose
   * program is unknown here".
   */
  readonly ringProgramId?: Address;
}

export type GetShieldedTransactionsByTagsResponse = Page<
  TransactionEvents<IndexedShieldedTransaction>
>;
export type GetShieldedTransactionsByNullifiersResponse = GetShieldedTransactionsByTagsResponse;

export interface GetShieldedTransactionsBySignatureRequest {
  readonly txSignature: Signature;
}

export interface SignatureIndexedShieldedTransaction {
  readonly eventIndex: number;
  readonly transaction: IndexedShieldedTransaction;
}

export interface GetShieldedTransactionsBySignatureResponse {
  readonly outputTreeId?: number;
  readonly context: IndexerContext;
  readonly transactions: readonly SignatureIndexedShieldedTransaction[];
}

export interface GetMerkleProofsRequest {
  readonly treeAccount: Address;
  readonly leaves: readonly Hash[];
}

export interface MerkleProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[];
  readonly leafIndex: bigint;
  readonly root: Hash;
  /** Completed Solana slot used to order this state-tree root and assess freshness. */
  readonly rootSeq: bigint;
  /** Actual on-chain cyclic-history position; it is not derivable from `rootSeq`. */
  readonly rootIndex: number;
}

export interface GetMerkleProofsResponse {
  readonly context: IndexerContext;
  readonly proofs: readonly MerkleProof[];
}

export interface GetNonInclusionProofsRequest {
  readonly treeAccount: Address;
  readonly leaves: readonly Hash[];
}

export interface NonInclusionProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[];
  readonly lowElement: Hash;
  readonly lowElementIndex: bigint;
  readonly highElement: Hash;
  readonly highElementIndex: bigint;
  readonly root: Hash;
  /** On-chain indexed-tree update sequence. */
  readonly rootSeq: bigint;
  /** On-chain root-history position for `root`. */
  readonly rootIndex: number;
}

export interface GetNonInclusionProofsResponse {
  readonly context: IndexerContext;
  readonly proofs: readonly NonInclusionProof[];
}

export interface GetUserRecordsRequest {
  /** At most `MAX_USER_RECORD_OWNERS`. */
  readonly owners: readonly Address[];
}

/** A user registry record, the shielded address a Solana pubkey publishes. */
export interface UserRecord {
  readonly owner: Address;
  /** Wallet-wide nullifier pubkey. Never rotates. */
  readonly nullifierPubkey: Hash;
  /** Tagged canonical X25519 viewing pubkey. */
  readonly viewingPubkey: Base64String;
  /**
   * Merge opt-in and scheme: `Disabled` (0) refuses `merge_transact`, any other
   * scheme lets any caller merge this owner's UTXOs with exactly that scheme.
   */
  readonly mergeEncryption: MergeEncryptionScheme;
}

export interface GetUserRecordsResponse {
  readonly context: IndexerContext;
  /**
   * One entry per requested owner, in request order; `null` for an owner with
   * no record at the slot the records were read, which is no earlier than
   * `context.slot`.
   */
  readonly records: readonly (UserRecord | null)[];
}
