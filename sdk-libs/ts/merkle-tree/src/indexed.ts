import { bigintToBytes, bytes32, compareBytes, copyBytes, type Bytes32 } from "./bytes.js";
import { IndexedMerkleTreeError, MerkleTreeError } from "./errors.js";
import { CoreMerkleTree, type Hasher32 } from "./merkle-tree.js";

const HIGHEST_ADDRESS_PLUS_ONE =
  bigintToBytes(452312848583266388373324160190187140051835877600158453279131187530910662655n);
const ZERO = bytes32(new Uint8Array(32), "zero");

interface IndexedElement {
  readonly index: bigint;
  readonly value: Bytes32;
  nextIndex: bigint;
}

export interface NonInclusionProof {
  readonly root: Bytes32;
  readonly value: Bytes32;
  readonly leafLowerRangeValue: Bytes32;
  readonly leafHigherRangeValue: Bytes32;
  readonly leafIndex: bigint;
  readonly nextIndex: bigint;
  readonly merkleProof: readonly Bytes32[];
}

function indexedHash(hasher: Hasher32, left: Bytes32, right: Bytes32): Bytes32 {
  try {
    return bytes32(hasher.hash(copyBytes(left), copyBytes(right)), "hash");
  } catch (cause) {
    throw new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_HASH", "Hasher failed", { cause });
  }
}

function indexedBytes(value: Uint8Array): Bytes32 {
  try {
    return bytes32(value, "value");
  } catch (cause) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_VALUE",
      "Value must contain 32 bytes",
      { cause },
    );
  }
}

function proofBytes(value: Uint8Array, field: string): Bytes32 {
  try {
    return bytes32(value, field);
  } catch (cause) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_PROOF",
      `${field} must contain 32 bytes`,
      { details: { field }, cause },
    );
  }
}

function proofIndex(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_PROOF",
      `${field} must be a non-negative bigint`,
      { details: { field } },
    );
  }
  return value;
}

export function verifyNonInclusionProof(hasher: Hasher32, proof: NonInclusionProof): boolean {
  const root = proofBytes(proof.root, "root");
  const value = proofBytes(proof.value, "value");
  const lower = proofBytes(proof.leafLowerRangeValue, "leafLowerRangeValue");
  const higher = proofBytes(proof.leafHigherRangeValue, "leafHigherRangeValue");
  let index = proofIndex(proof.leafIndex, "leafIndex");
  proofIndex(proof.nextIndex, "nextIndex");

  if (compareBytes(lower, value) >= 0) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_LOWER_BOUND",
      "Proof value must exceed its lower range",
    );
  }
  if (compareBytes(higher, value) <= 0) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_HIGHER_BOUND",
      "Proof value must be below its higher range",
    );
  }

  let hash = indexedHash(hasher, lower, higher);
  for (const siblingValue of proof.merkleProof) {
    const sibling = proofBytes(siblingValue, "merkleProof");
    hash =
      (index & 1n) === 0n ? indexedHash(hasher, hash, sibling) : indexedHash(hasher, sibling, hash);
    index >>= 1n;
  }
  if (compareBytes(hash, root) !== 0) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_PROOF",
      "Merkle proof does not match its root",
    );
  }
  return true;
}

function mapTreeError(cause: unknown): never {
  if (cause instanceof IndexedMerkleTreeError) {
    throw cause;
  }
  if (cause instanceof MerkleTreeError && cause.code === "MERKLE_TREE_CAPACITY") {
    const options = cause.details === undefined ? { cause } : { details: cause.details, cause };
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_CAPACITY",
      "Indexed tree is full",
      options,
    );
  }
  throw new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_HASH", "Indexed tree update failed", {
    cause,
  });
}

export class IndexedMerkleTree {
  private readonly hasher: Hasher32;
  private readonly tree: CoreMerkleTree;
  private readonly elements: IndexedElement[];

  constructor(height: number, hasher: Hasher32) {
    this.hasher = hasher;
    try {
      this.tree = new CoreMerkleTree(height, hasher);
      const firstLeaf = indexedHash(hasher, ZERO, HIGHEST_ADDRESS_PLUS_ONE);
      this.tree.append(firstLeaf);
    } catch (cause) {
      mapTreeError(cause);
    }
    this.elements = [{ index: 0n, value: copyBytes(ZERO), nextIndex: 0n }];
  }

  insert(value: Bytes32): bigint {
    const ownedValue = indexedBytes(value);
    if (
      compareBytes(ownedValue, ZERO) <= 0 ||
      compareBytes(ownedValue, HIGHEST_ADDRESS_PLUS_ONE) >= 0
    ) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INVALID_VALUE",
        "Value is outside the indexed range",
      );
    }

    const low = this.findLowElement(ownedValue);
    const high = this.highElement(low);
    const newIndex = BigInt(this.elements.length);
    const newLowLeaf = indexedHash(this.hasher, low.value, ownedValue);
    const newLeaf = indexedHash(this.hasher, ownedValue, high.value);

    try {
      this.tree.replaceAndAppend(low.index, newLowLeaf, newLeaf);
    } catch (cause) {
      mapTreeError(cause);
    }

    const nextIndex = low.nextIndex;
    low.nextIndex = newIndex;
    this.elements.push({ index: newIndex, value: ownedValue, nextIndex });
    return newIndex;
  }

  root(): Bytes32 {
    return this.tree.root();
  }

  nonInclusionProof(value: Bytes32): NonInclusionProof {
    const ownedValue = indexedBytes(value);
    if (
      compareBytes(ownedValue, ZERO) <= 0 ||
      compareBytes(ownedValue, HIGHEST_ADDRESS_PLUS_ONE) >= 0
    ) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INVALID_VALUE",
        "Value is outside the indexed range",
      );
    }

    const low = this.findLowElement(ownedValue);
    const high = this.highElement(low);
    return {
      root: this.tree.root(),
      value: copyBytes(ownedValue),
      leafLowerRangeValue: copyBytes(low.value),
      leafHigherRangeValue: copyBytes(high.value),
      leafIndex: low.index,
      nextIndex: low.nextIndex,
      merkleProof: this.tree.proof(low.index),
    };
  }

  private findLowElement(value: Bytes32): IndexedElement {
    let current = this.element(0n);
    for (;;) {
      const order = compareBytes(value, current.value);
      if (order === 0) {
        throw new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_DUPLICATE", "Value already exists", {
          details: { index: current.index.toString() },
        });
      }
      const high = this.highElement(current);
      if (order > 0 && compareBytes(value, high.value) < 0) {
        return current;
      }
      if (current.nextIndex === 0n) {
        return current;
      }
      current = high;
    }
  }

  private highElement(low: IndexedElement): IndexedElement {
    if (low.nextIndex === 0n) {
      return { index: 0n, value: HIGHEST_ADDRESS_PLUS_ONE, nextIndex: 0n };
    }
    return this.element(low.nextIndex);
  }

  private element(index: bigint): IndexedElement {
    const element = this.elements[Number(index)];
    if (element === undefined) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INVALID_VALUE",
        "Indexed tree invariant failed",
      );
    }
    return element;
  }
}
