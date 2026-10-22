import type { MergeEncryptionScheme } from "../interface/state.js";
import type { Address, Signature } from "../interface/types.js";

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

export interface RingMemberRecordView {
  readonly member: Hash;
  readonly next: Hash;
  readonly lists: bigint;
  readonly escrowKey: Hash;
  readonly ownerPubkey?: Address | null;
  /** `escrowKey` is `Poseidon(nullifierPk, hash_bytes(ciphertext))`. */
  readonly nullifierPk?: Hash | null;
  readonly ephPk: Base64String | null;
  readonly ciphertext: Base64String | null;
}
export interface RingMemberRecordsRequest {
  readonly ringProgramId: Address;
  readonly expectedRoot: Hash;
  readonly expectedNextIndex: bigint;
  readonly startIndex: bigint;
  readonly limit: number;
}

/** A leaf and the other three children of each level in child order, leaf level first. */
export interface RingRecordPathView {
  readonly index: bigint;
  readonly siblings: readonly (readonly Hash[])[];
}

/** A root the on-chain registry history holds. */
export interface RingRegistryRootView {
  readonly root: Hash;
  readonly rootIndex: number;
  /** The queue position applied at the root, checked against the registry floor. */
  readonly applied: bigint;
  readonly nextIndex: bigint;
}

/** A member's record under one root, or the low record bracketing its absence. */
export interface RingMemberOpeningView {
  readonly present: boolean;
  readonly record: RingMemberRecordView;
  readonly path: RingRecordPathView;
}

export interface RingMemberOpeningResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  readonly opening: RingMemberOpeningView;
}

/** At most `MAX_RING_MEMBER_PAGE_LIMIT` members under one history root. */
export interface RingMemberOpeningsRequest {
  readonly ringProgramId: Address;
  readonly members: readonly Hash[];
  readonly expectedRoot: Hash;
}

export interface RingMemberOpeningsResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  /** In request order. */
  readonly openings: readonly RingMemberOpeningView[];
}

export interface RingMemberPageResponse {
  readonly context: IndexerContext;
  readonly root: RingRegistryRootView;
  readonly records: readonly Readonly<{ record: RingMemberRecordView; path: RingRecordPathView }>[];
  readonly nextLeafIndex: bigint | null;
}

export interface RingRootEntryView {
  readonly root: Hash;
  readonly applied: bigint;
  readonly slot: bigint;
}

/** The registry account as projected. */
export interface RingRegistryStateResponse {
  readonly context: IndexerContext;
  /** Entry `i` sits at history slot `i`, `null` for a slot never written. */
  readonly history: readonly (RingRootEntryView | null)[];
  readonly historyCursor: number;
  readonly nextIndex: bigint;
  readonly floor: bigint;
  readonly priorFloor: bigint;
  readonly floorSlot: bigint;
  /** The empty leaf at `nextIndex` under the newest root, `null` once the registry is full. */
  readonly appendPath: RingRecordPathView | null;
}

export interface RingQueueEntryView {
  readonly position: bigint;
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  /** Zero except on a RegisterKey write. */
  readonly escrowKey: Hash;
  readonly slot: bigint;
}

export interface RingRecordQueueResponse {
  readonly context: IndexerContext;
  readonly head: bigint;
  readonly tail: bigint;
  /** `chain(head - 1)`, zero at head 0. */
  readonly chainHead: Hash;
  /** Positions `head .. tail`. */
  readonly entries: readonly RingQueueEntryView[];
}

export interface RingListWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
}

export interface RingApplyProofInputsRequest {
  readonly ringProgramId: Address;
  /** Applied after every pending write. */
  readonly authorityWrites: readonly RingListWriteView[];
}

/** Paths are under the root the preceding writes reached. */
export interface RingRecordWriteView {
  readonly member: Hash;
  readonly mask: bigint;
  readonly value: bigint;
  readonly escrowKey: Hash;
  readonly exists: boolean;
  readonly oldNext: Hash;
  readonly oldLists: bigint;
  readonly oldEscrow: Hash;
  readonly slot: RingRecordPathView;
  readonly low: RingMemberRecordView;
  readonly lowPath: RingRecordPathView;
}

export interface RingApplyProofInputsResponse {
  readonly context: IndexerContext;
  readonly oldRoot: Hash;
  readonly newRoot: Hash;
  readonly oldNextIndex: bigint;
  readonly newNextIndex: bigint;
  readonly chainStart: Hash;
  readonly chainEnd: Hash;
  /** Queue order. */
  readonly writes: readonly RingRecordWriteView[];
}

export interface GetRingsByTagsRequest {
  readonly tags: readonly Hash[];
  readonly cursor?: Base64String;
  readonly limit?: Limit;
  /**
   * Restrict the match to one ring. Its config account is derived from this
   * program id, so the filter needs no indexed registration.
   */
  readonly ringProgramId?: Address;
}

export interface GetRingsByNullifiersRequest {
  readonly nullifiers: readonly Hash[];
  readonly cursor?: Base64String;
  readonly limit?: Limit;
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

export interface GetEncryptedUtxosByTagsResponse {
  readonly outputTreeId?: number;
  readonly context: IndexerContext;
  readonly matches: readonly EncryptedUtxoMatch[];
  readonly nextCursor?: Base64String;
  /** Where the scan reached on a terminal page, including an empty page. */
  readonly scannedThrough?: Base64String;
}

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

export interface GetShieldedTransactionsByTagsResponse {
  readonly outputTreeId?: number;
  readonly context: IndexerContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Base64String;
  /** Where the scan reached on a terminal page, including an empty page. */
  readonly scannedThrough?: Base64String;
}

export interface GetShieldedTransactionsByNullifiersResponse {
  readonly outputTreeId?: number;
  readonly context: IndexerContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Base64String;
  /**
   * Where the indexer's scan reached. Present only on a page the limit did not
   * truncate. Unspent nullifiers match nothing, so `nextCursor` is absent for
   * them and this is the only resume point.
   */
  readonly scannedThrough?: Base64String;
}

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
