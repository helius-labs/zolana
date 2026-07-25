import { bytes32, copyBytes, type Bytes32 } from "./bytes.js";
import { MerkleTreeError } from "./errors.js";

export interface Hasher32 {
  hash(left: Bytes32, right: Bytes32): Bytes32;
}

export interface MerkleTreeOptions {
  readonly canopyDepth?: number;
  readonly rootHistoryStartOffset?: bigint;
  readonly rootHistoryArrayLength?: number;
}

const MAX_U64 = (1n << 64n) - 1n;
const NODE_POSITION_MASK = (1n << 56n) - 1n;

function validateInteger(
  value: number,
  field: string,
  minimum: number,
  maximum: number,
  code:
    | "MERKLE_TREE_INVALID_HEIGHT"
    | "MERKLE_TREE_INVALID_CANOPY"
    | "MERKLE_TREE_INVALID_HISTORY"
    | "MERKLE_TREE_INVALID_LEVEL",
): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new MerkleTreeError(code, `${field} is out of range`, {
      details: { field, value, minimum, maximum },
    });
  }
}

function validateIndex(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new MerkleTreeError("MERKLE_TREE_INDEX_WIDTH", `${field} must fit u64`, {
      details: { field, value: typeof value === "bigint" ? value.toString() : value },
    });
  }
  return value;
}

function checkedHash(hasher: Hasher32, left: Bytes32, right: Bytes32): Bytes32 {
  try {
    return bytes32(hasher.hash(copyBytes(left), copyBytes(right)), "hash");
  } catch (cause) {
    if (cause instanceof MerkleTreeError) {
      throw cause;
    }
    throw new MerkleTreeError("MERKLE_TREE_HASH", "Hasher failed", { cause });
  }
}

function required<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new MerkleTreeError("MERKLE_TREE_INDEX", "Merkle tree invariant failed");
  }
  return value;
}

export class CoreMerkleTree {
  readonly height: number;
  readonly capacity: bigint;
  readonly canopyDepth: number;
  private readonly hasher: Hasher32;
  private readonly zeros: Bytes32[];
  private layers: Map<bigint, Bytes32>[];
  private layerLengths: bigint[];
  private nextIndex = 0n;
  private currentRoot: Bytes32;
  private sequence = 0n;
  private rootUpdates = 0n;
  private readonly rootHistoryStartOffset: bigint;
  private readonly rootHistoryArrayLength: number | undefined;
  private roots: Bytes32[];

  constructor(height: number, hasher: Hasher32, options: MerkleTreeOptions = {}) {
    validateInteger(height, "height", 1, 63, "MERKLE_TREE_INVALID_HEIGHT");
    const candidate: unknown = hasher;
    if (
      candidate === null ||
      typeof candidate !== "object" ||
      !("hash" in candidate) ||
      typeof candidate.hash !== "function"
    ) {
      throw new MerkleTreeError("MERKLE_TREE_INVALID_HASHER", "hasher must define hash()");
    }

    const canopyDepth = options.canopyDepth ?? 0;
    validateInteger(canopyDepth, "canopyDepth", 0, height, "MERKLE_TREE_INVALID_CANOPY");
    const rootHistoryStartOffset = options.rootHistoryStartOffset ?? 0n;
    validateIndex(rootHistoryStartOffset, "rootHistoryStartOffset");
    if (options.rootHistoryArrayLength !== undefined) {
      validateInteger(
        options.rootHistoryArrayLength,
        "rootHistoryArrayLength",
        1,
        65_535,
        "MERKLE_TREE_INVALID_HISTORY",
      );
    }

    this.height = height;
    this.capacity = 1n << BigInt(height);
    this.canopyDepth = canopyDepth;
    this.hasher = hasher;
    this.zeros = [bytes32(new Uint8Array(32), "zero")];
    for (let level = 0; level < height; level += 1) {
      const zero = required(this.zeros[level]);
      this.zeros.push(checkedHash(hasher, zero, zero));
    }
    this.layers = Array.from({ length: height }, () => new Map<bigint, Bytes32>());
    this.layerLengths = Array.from({ length: height }, () => 0n);
    this.currentRoot = copyBytes(required(this.zeros[height]));
    this.rootHistoryStartOffset = rootHistoryStartOffset;
    this.rootHistoryArrayLength = options.rootHistoryArrayLength;
    this.roots = [copyBytes(this.currentRoot)];
  }

  clone(): CoreMerkleTree {
    const clone = Object.create(CoreMerkleTree.prototype) as CoreMerkleTree;
    Object.assign(clone, this);
    clone.layers = this.layers.map((layer) => {
      const copy = new Map<bigint, Bytes32>();
      for (const [index, value] of layer) {
        copy.set(index, copyBytes(value));
      }
      return copy;
    });
    clone.layerLengths = [...this.layerLengths];
    clone.roots = this.roots.map(copyBytes);
    clone.currentRoot = copyBytes(this.currentRoot);
    return clone;
  }

  append(leaf: Uint8Array): bigint {
    const copy = this.clone();
    const index = copy.appendInPlace(bytes32(leaf, "leaf"));
    this.adopt(copy);
    return index;
  }

  appendBatch(leaves: readonly Uint8Array[]): readonly bigint[] {
    const copy = this.clone();
    const indices = leaves.map((leaf) => copy.appendInPlace(bytes32(leaf, "leaf")));
    this.adopt(copy);
    return indices;
  }

  update(index: bigint, leaf: Uint8Array): void {
    const copy = this.clone();
    copy.updateInPlace(validateIndex(index, "index"), bytes32(leaf, "leaf"));
    this.adopt(copy);
  }

  replaceAndAppend(index: bigint, replacement: Uint8Array, appended: Uint8Array): bigint {
    const copy = this.clone();
    copy.updateInPlace(validateIndex(index, "index"), bytes32(replacement, "replacement"));
    const appendedIndex = copy.appendInPlace(bytes32(appended, "appended"));
    this.adopt(copy);
    return appendedIndex;
  }

  root(): Bytes32 {
    return copyBytes(this.currentRoot);
  }

  proof(index: bigint, full = true): readonly Bytes32[] {
    validateIndex(index, "index");
    const limit = full ? this.height : this.height - this.canopyDepth;
    const proof: Bytes32[] = [];
    let current = index;
    for (let level = 0; level < limit; level += 1) {
      proof.push(this.node(level, current ^ 1n));
      current >>= 1n;
    }
    return proof;
  }

  path(index: bigint, full = true): readonly Bytes32[] {
    validateIndex(index, "index");
    const limit = full ? this.height : this.height - this.canopyDepth;
    const path: Bytes32[] = [];
    let current = index;
    for (let level = 0; level < limit; level += 1) {
      path.push(this.node(level, current));
      current >>= 1n;
    }
    return path;
  }

  proofs(indices: readonly bigint[]): readonly (readonly Bytes32[])[] {
    return indices.map((index) => this.proof(index));
  }

  verify(leaf: Uint8Array, proof: readonly Uint8Array[], index: bigint): boolean {
    const checkedIndex = validateIndex(index, "index");
    if (checkedIndex >= this.capacity) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index exceeds tree capacity", {
        details: { index: checkedIndex.toString(), capacity: this.capacity.toString() },
      });
    }
    if (proof.length !== this.height) {
      throw new MerkleTreeError(
        "MERKLE_TREE_INVALID_PROOF_LENGTH",
        "Proof length must equal tree height",
        { details: { actual: proof.length, required: this.height } },
      );
    }

    let hash = bytes32(leaf, "leaf");
    let current = checkedIndex;
    for (const [level, siblingValue] of proof.entries()) {
      const sibling = bytes32(siblingValue, `proof[${String(level)}]`);
      hash =
        (current & 1n) === 0n
          ? checkedHash(this.hasher, hash, sibling)
          : checkedHash(this.hasher, sibling, hash);
      current >>= 1n;
    }
    return hash.every((byte, position) => byte === this.currentRoot[position]);
  }

  leaf(index: bigint): Bytes32 {
    return this.node(0, validateIndex(index, "index"));
  }

  getLeaf(index: bigint): Bytes32 {
    const checkedIndex = validateIndex(index, "index");
    if (checkedIndex >= required(this.layerLengths[0])) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index does not exist", {
        details: {
          index: checkedIndex.toString(),
          leafCount: required(this.layerLengths[0]).toString(),
        },
      });
    }
    return this.node(0, checkedIndex);
  }

  leafIndex(leaf: Uint8Array): bigint | undefined {
    const checkedLeaf = bytes32(leaf, "leaf");
    const length = required(this.layerLengths[0]);
    for (let index = 0n; index < length; index += 1n) {
      const candidate = this.node(0, index);
      if (candidate.every((byte, position) => byte === checkedLeaf[position])) {
        return index;
      }
    }
    return undefined;
  }

  leaves(): readonly Bytes32[] {
    const length = required(this.layerLengths[0]);
    if (length > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX_WIDTH", "Leaf count exceeds array capacity", {
        details: { leafCount: length.toString() },
      });
    }
    const leaves: Bytes32[] = [];
    for (let index = 0n; index < length; index += 1n) {
      leaves.push(this.node(0, index));
    }
    return leaves;
  }

  canopy(): readonly Bytes32[] {
    const canopy: Bytes32[] = [];
    for (let depth = 0; depth < this.canopyDepth; depth += 1) {
      const level = this.height - depth - 1;
      const width = 1n << BigInt(depth + 1);
      for (let index = 0n; index < width; index += 1n) {
        canopy.push(this.node(level, index));
      }
    }
    return canopy;
  }

  history(): readonly Bytes32[] {
    return this.roots.map(copyBytes);
  }

  historyRootIndex(): number {
    if (this.rootHistoryArrayLength === undefined) {
      throw new MerkleTreeError("MERKLE_TREE_INVALID_HISTORY", "Root history is not configured");
    }
    if (this.nextIndex < this.rootHistoryStartOffset) {
      throw new MerkleTreeError(
        "MERKLE_TREE_INVALID_HISTORY",
        "Root history offset exceeds the current index",
        {
          details: {
            currentIndex: this.nextIndex.toString(),
            rootHistoryStartOffset: this.rootHistoryStartOffset.toString(),
          },
        },
      );
    }
    return Number(
      (this.nextIndex - this.rootHistoryStartOffset) % BigInt(this.rootHistoryArrayLength),
    );
  }

  historyRootIndexV2(): number {
    if (this.rootHistoryArrayLength === undefined) {
      throw new MerkleTreeError("MERKLE_TREE_INVALID_HISTORY", "Root history is not configured");
    }
    return Number(this.rootUpdates % BigInt(this.rootHistoryArrayLength));
  }

  leafCount(): bigint {
    return this.nextIndex;
  }

  nextLeafIndex(): bigint {
    return this.nextIndex;
  }

  sequenceNumber(): bigint {
    return this.sequence;
  }

  subtrees(): readonly Bytes32[] {
    const subtrees = this.zeros.slice(0, this.height).map(copyBytes);
    if (required(this.layerLengths[this.height - 1]) === 0n) {
      return subtrees;
    }
    for (let level = this.height - 1; level >= 0; level -= 1) {
      const length = required(this.layerLengths[level]);
      if (length === 0n) {
        continue;
      }
      const index = length % 2n === 0n ? length - 2n : length - 1n;
      subtrees[level] = this.node(level, index);
    }
    return subtrees;
  }

  insertNode(nodeIndex: bigint, hash: Uint8Array): void {
    const checkedIndex = validateIndex(nodeIndex, "nodeIndex");
    const level = Number(checkedIndex >> 56n);
    const position = checkedIndex & NODE_POSITION_MASK;
    if (level >= this.height) {
      throw new MerkleTreeError("MERKLE_TREE_INVALID_LEVEL", "Node level exceeds tree height", {
        details: { level, height: this.height },
      });
    }
    this.layer(level).set(position, bytes32(hash, "hash"));
    this.layerLengths[level] =
      position >= required(this.layerLengths[level])
        ? position + 1n
        : required(this.layerLengths[level]);
  }

  insertLeaf(index: bigint, hash: Uint8Array): void {
    const checkedIndex = validateIndex(index, "index");
    this.layer(0).set(checkedIndex, bytes32(hash, "hash"));
    this.layerLengths[0] =
      checkedIndex >= required(this.layerLengths[0])
        ? checkedIndex + 1n
        : required(this.layerLengths[0]);
  }

  ensureLayerCapacity(level: number, minimumIndex: bigint): void {
    validateInteger(level, "level", 0, this.height - 1, "MERKLE_TREE_INVALID_LEVEL");
    const checkedIndex = validateIndex(minimumIndex, "minimumIndex");
    this.layerLengths[level] =
      checkedIndex >= required(this.layerLengths[level])
        ? checkedIndex + 1n
        : required(this.layerLengths[level]);
  }

  private appendInPlace(leaf: Bytes32): bigint {
    if (this.nextIndex >= this.capacity) {
      throw new MerkleTreeError("MERKLE_TREE_CAPACITY", "Merkle tree is full", {
        details: { capacity: this.capacity.toString() },
      });
    }
    const index = this.nextIndex;
    this.layer(0).set(index, leaf);
    this.layerLengths[0] = index + 1n;
    this.nextIndex += 1n;
    this.recompute(index);
    this.sequence += 1n;
    return index;
  }

  private updateInPlace(index: bigint, leaf: Bytes32): void {
    if (index >= required(this.layerLengths[0])) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index does not exist", {
        details: { index: index.toString(), leafCount: required(this.layerLengths[0]).toString() },
      });
    }
    this.layer(0).set(index, leaf);
    this.recompute(index);
    this.sequence += 1n;
  }

  private recompute(index: bigint): void {
    let current = index;
    for (let level = 0; level < this.height; level += 1) {
      const parent = current >> 1n;
      const left = this.node(level, parent << 1n);
      const right = this.node(level, (parent << 1n) | 1n);
      const hash = checkedHash(this.hasher, left, right);
      if (level + 1 === this.height) {
        this.currentRoot = hash;
      } else {
        this.layer(level + 1).set(parent, hash);
        this.layerLengths[level + 1] =
          parent >= required(this.layerLengths[level + 1])
            ? parent + 1n
            : required(this.layerLengths[level + 1]);
      }
      current = parent;
    }
    this.roots.push(copyBytes(this.currentRoot));
    this.rootUpdates += 1n;
  }

  private node(level: number, index: bigint): Bytes32 {
    return copyBytes(this.layer(level).get(index) ?? required(this.zeros[level]));
  }

  private layer(level: number): Map<bigint, Bytes32> {
    return required(this.layers[level]);
  }

  private adopt(source: CoreMerkleTree): void {
    this.layers = source.layers;
    this.layerLengths = source.layerLengths;
    this.nextIndex = source.nextIndex;
    this.currentRoot = source.currentRoot;
    this.sequence = source.sequence;
    this.rootUpdates = source.rootUpdates;
    this.roots = source.roots;
  }
}

export class MerkleTree {
  private readonly tree: CoreMerkleTree;

  constructor(height: number, hasher: Hasher32, options: MerkleTreeOptions = {}) {
    this.tree = new CoreMerkleTree(height, hasher, options);
  }

  append(leaf: Bytes32): bigint {
    return this.tree.append(leaf);
  }

  appendBatch(leaves: readonly Bytes32[]): readonly bigint[] {
    return this.tree.appendBatch(leaves);
  }

  update(index: bigint, leaf: Bytes32): void {
    this.tree.update(index, leaf);
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

  proofs(indices: readonly bigint[]): readonly (readonly Bytes32[])[] {
    return this.tree.proofs(indices);
  }

  verify(leaf: Bytes32, proof: readonly Bytes32[], index: bigint): boolean {
    return this.tree.verify(leaf, proof, index);
  }

  canopy(): readonly Bytes32[] {
    return this.tree.canopy();
  }

  canopySize(): bigint {
    return (1n << BigInt(this.tree.canopyDepth + 1)) - 2n;
  }

  history(): readonly Bytes32[] {
    return this.tree.history();
  }

  historyRootIndex(): number {
    return this.tree.historyRootIndex();
  }

  historyRootIndexV2(): number {
    return this.tree.historyRootIndexV2();
  }

  leaf(index: bigint): Bytes32 {
    return this.tree.leaf(index);
  }

  getLeaf(index: bigint): Bytes32 {
    return this.tree.getLeaf(index);
  }

  leafIndex(leaf: Bytes32): bigint | undefined {
    return this.tree.leafIndex(leaf);
  }

  leaves(): readonly Bytes32[] {
    return this.tree.leaves();
  }

  subtrees(): readonly Bytes32[] {
    return this.tree.subtrees();
  }

  leafCount(): bigint {
    return this.tree.leafCount();
  }

  nextIndex(): bigint {
    return this.tree.nextLeafIndex();
  }

  sequenceNumber(): bigint {
    return this.tree.sequenceNumber();
  }

  insertNode(nodeIndex: bigint, hash: Bytes32): void {
    this.tree.insertNode(nodeIndex, hash);
  }

  insertLeaf(index: bigint, hash: Bytes32): void {
    this.tree.insertLeaf(index, hash);
  }

  ensureLayerCapacity(level: number, minimumIndex: bigint): void {
    this.tree.ensureLayerCapacity(level, minimumIndex);
  }
}
