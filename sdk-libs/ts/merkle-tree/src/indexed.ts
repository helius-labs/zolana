import { bigintToBytes, bytes32, compareBytes, copyBytes, type Bytes32 } from "./bytes.js";
import { IndexedMerkleTreeError, MerkleTreeError } from "./errors.js";
import { CoreMerkleTree, type Hasher32 } from "./merkle-tree.js";

const HIGHEST_ADDRESS_PLUS_ONE =
  bigintToBytes(452312848583266388373324160190187140051835877600158453279131187530910662655n);
const ZERO = bytes32(new Uint8Array(32), "zero");
const MAX_U64 = (1n << 64n) - 1n;

export interface IndexedElement {
  readonly index: bigint;
  readonly value: Bytes32;
  readonly nextIndex: bigint;
}

interface MutableIndexedElement {
  readonly index: bigint;
  readonly value: Bytes32;
  nextIndex: bigint;
}

export interface IndexedMerkleTreeOptions {
  readonly canopyDepth?: number;
  readonly highestValue?: Bytes32;
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

function sentinelBytes(value: Uint8Array): Bytes32 {
  try {
    return bytes32(value, "highestValue");
  } catch (cause) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_SENTINEL",
      "Highest value must contain 32 bytes",
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
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_INVALID_PROOF", `${field} must fit u64`, {
      details: {
        field,
        value: typeof value === "bigint" ? value.toString() : value,
      },
    });
  }
  return value;
}

function treeIndex(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_INDEX", `${field} must fit u64`, {
      details: {
        field,
        value: typeof value === "bigint" ? value.toString() : value,
      },
    });
  }
  return value;
}

export function verifyNonInclusionProof(
  hasher: Hasher32,
  proof: NonInclusionProof,
  expectedRoot: Bytes32,
  height: number,
): boolean {
  const root = proofBytes(proof.root, "root");
  const trustedRoot = proofBytes(expectedRoot, "expectedRoot");
  if (compareBytes(root, trustedRoot) !== 0) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_PROOF",
      "Proof root does not match the trusted root",
      { details: { field: "root" } },
    );
  }
  if (!Number.isSafeInteger(height) || height < 1 || proof.merkleProof.length !== height) {
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INVALID_PROOF",
      "Proof length must equal tree height",
      { details: { actual: proof.merkleProof.length, required: height } },
    );
  }
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
  if (
    cause instanceof MerkleTreeError &&
    (cause.code === "MERKLE_TREE_INDEX" || cause.code === "MERKLE_TREE_INDEX_WIDTH")
  ) {
    const options = cause.details === undefined ? { cause } : { details: cause.details, cause };
    throw new IndexedMerkleTreeError(
      "INDEXED_MERKLE_TREE_INDEX",
      "Indexed tree index is invalid",
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
  private readonly elements: MutableIndexedElement[];
  private readonly highest: Bytes32;

  constructor(height: number, hasher: Hasher32, options: IndexedMerkleTreeOptions = {}) {
    this.hasher = hasher;
    this.highest =
      options.highestValue === undefined
        ? copyBytes(HIGHEST_ADDRESS_PLUS_ONE)
        : sentinelBytes(options.highestValue);
    if (compareBytes(this.highest, ZERO) <= 0) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INVALID_SENTINEL",
        "Highest value must exceed zero",
      );
    }
    try {
      const treeOptions =
        options.canopyDepth === undefined ? {} : { canopyDepth: options.canopyDepth };
      this.tree = new CoreMerkleTree(height, hasher, treeOptions);
      const firstLeaf = indexedHash(hasher, ZERO, this.highest);
      this.tree.append(firstLeaf);
    } catch (cause) {
      mapTreeError(cause);
    }
    this.elements = [{ index: 0n, value: copyBytes(ZERO), nextIndex: 0n }];
  }

  insert(value: Bytes32): bigint {
    const ownedValue = indexedBytes(value);
    this.checkBelowHighestValue(ownedValue);

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

  path(index: bigint, full = true): readonly Bytes32[] {
    return this.tree.path(index, full);
  }

  proof(index: bigint, full = true): readonly Bytes32[] {
    return this.tree.proof(index, full);
  }

  update(
    newLowElement: IndexedElement,
    newElement: IndexedElement,
    newElementNextValue: Bytes32,
  ): void {
    const lowIndex = treeIndex(newLowElement.index, "newLowElement.index");
    treeIndex(newLowElement.nextIndex, "newLowElement.nextIndex");
    treeIndex(newElement.index, "newElement.index");
    treeIndex(newElement.nextIndex, "newElement.nextIndex");
    const lowValue = indexedBytes(newLowElement.value);
    const value = indexedBytes(newElement.value);
    const nextValue = indexedBytes(newElementNextValue);
    const newLowLeaf = indexedHash(this.hasher, lowValue, value);
    const newLeaf = indexedHash(this.hasher, value, nextValue);
    try {
      this.tree.replaceAndAppend(lowIndex, newLowLeaf, newLeaf);
    } catch (cause) {
      mapTreeError(cause);
    }
  }

  verifyNonInclusionProof(proof: NonInclusionProof): boolean {
    return verifyNonInclusionProof(this.hasher, proof, this.tree.root(), this.tree.height);
  }

  highestValue(): Bytes32 {
    return copyBytes(this.highest);
  }

  element(index: bigint): IndexedElement {
    const element = this.internalElement(treeIndex(index, "index"));
    return {
      index: element.index,
      value: copyBytes(element.value),
      nextIndex: element.nextIndex,
    };
  }

  elementCount(): bigint {
    return BigInt(this.elements.length);
  }

  nonInclusionProof(value: Bytes32): NonInclusionProof {
    const ownedValue = indexedBytes(value);
    this.checkBelowHighestValue(ownedValue);

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

  // The exclusion ranges tile `(0, highestValue)`, so a value at or above the
  // sentinel would claim an empty range and no range could contain the sentinel
  // itself. The low end needs no guard here: zero is the tree's first element,
  // so `findLowElement` already reports it as a duplicate, which is what the
  // Rust indexed array does.
  private checkBelowHighestValue(value: Bytes32): void {
    if (compareBytes(value, this.highest) >= 0) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INVALID_VALUE",
        "Value is outside the indexed range",
      );
    }
  }

  private findLowElement(value: Bytes32): MutableIndexedElement {
    let current = this.internalElement(0n);
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

  private highElement(low: MutableIndexedElement): MutableIndexedElement {
    if (low.nextIndex === 0n) {
      return { index: 0n, value: this.highest, nextIndex: 0n };
    }
    return this.internalElement(low.nextIndex);
  }

  private internalElement(index: bigint): MutableIndexedElement {
    if (index > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INDEX",
        "Indexed element index exceeds JavaScript array capacity",
        { details: { index: index.toString() } },
      );
    }
    const element = this.elements[Number(index)];
    if (element === undefined) {
      throw new IndexedMerkleTreeError(
        "INDEXED_MERKLE_TREE_INDEX",
        "Indexed tree invariant failed",
        { details: { index: index.toString() } },
      );
    }
    return element;
  }
}
