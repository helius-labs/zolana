export type ErrorDetails = Readonly<Record<string, unknown>>;

export type MerkleTreeErrorCode =
  | "MERKLE_TREE_INVALID_HASHER"
  | "MERKLE_TREE_INVALID_HEIGHT"
  | "MERKLE_TREE_INVALID_CANOPY"
  | "MERKLE_TREE_INVALID_HISTORY"
  | "MERKLE_TREE_INVALID_BYTES"
  | "MERKLE_TREE_CAPACITY"
  | "MERKLE_TREE_INDEX"
  | "MERKLE_TREE_INDEX_WIDTH"
  | "MERKLE_TREE_INVALID_LEVEL"
  | "MERKLE_TREE_INVALID_PROOF_LENGTH"
  | "MERKLE_TREE_HASH";

export class MerkleTreeError extends Error {
  readonly code: MerkleTreeErrorCode;
  readonly details?: ErrorDetails;
  override readonly cause?: unknown;

  constructor(
    code: MerkleTreeErrorCode,
    message: string,
    options?: Readonly<{ details?: ErrorDetails; cause?: unknown }>,
  ) {
    super(message);
    this.name = "MerkleTreeError";
    this.code = code;
    if (options?.details !== undefined) {
      this.details = options.details;
    }
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

export type IndexedMerkleTreeErrorCode =
  | "INDEXED_MERKLE_TREE_INVALID_VALUE"
  | "INDEXED_MERKLE_TREE_INVALID_SENTINEL"
  | "INDEXED_MERKLE_TREE_INDEX"
  | "INDEXED_MERKLE_TREE_DUPLICATE"
  | "INDEXED_MERKLE_TREE_CAPACITY"
  | "INDEXED_MERKLE_TREE_LOWER_BOUND"
  | "INDEXED_MERKLE_TREE_HIGHER_BOUND"
  | "INDEXED_MERKLE_TREE_INVALID_PROOF"
  | "INDEXED_MERKLE_TREE_HASH";

export class IndexedMerkleTreeError extends Error {
  readonly code: IndexedMerkleTreeErrorCode;
  readonly details?: ErrorDetails;
  override readonly cause?: unknown;

  constructor(
    code: IndexedMerkleTreeErrorCode,
    message: string,
    options?: Readonly<{ details?: ErrorDetails; cause?: unknown }>,
  ) {
    super(message);
    this.name = "IndexedMerkleTreeError";
    this.code = code;
    if (options?.details !== undefined) {
      this.details = options.details;
    }
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}
