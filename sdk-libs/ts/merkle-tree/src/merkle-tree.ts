import { bytes32, copyBytes, type Bytes32 } from "./bytes.js";
import { MerkleTreeError } from "./errors.js";

export interface Hasher32 {
  hash(left: Bytes32, right: Bytes32): Bytes32;
}

interface TreeOptions {
  readonly canopyDepth?: number;
  readonly historyCapacity?: number;
}

function validateInteger(value: number, field: string, minimum: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new MerkleTreeError("MERKLE_TREE_INVALID_HEIGHT", `${field} is out of range`, {
      details: { field, value, minimum, maximum },
    });
  }
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
  private nextIndex = 0n;
  private currentRoot: Bytes32;
  private readonly historyCapacity: number | undefined;
  private roots: Bytes32[];

  constructor(height: number, hasher: Hasher32, options: TreeOptions = {}) {
    validateInteger(height, "height", 1, 63);
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
    validateInteger(canopyDepth, "canopyDepth", 0, height);
    if (options.historyCapacity !== undefined) {
      validateInteger(options.historyCapacity, "historyCapacity", 1, 65_535);
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
    this.currentRoot = copyBytes(required(this.zeros[height]));
    this.historyCapacity = options.historyCapacity;
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

  replaceAndAppend(index: bigint, replacement: Uint8Array, appended: Uint8Array): bigint {
    const copy = this.clone();
    copy.updateInPlace(index, bytes32(replacement, "replacement"));
    const appendedIndex = copy.appendInPlace(bytes32(appended, "appended"));
    this.adopt(copy);
    return appendedIndex;
  }

  root(): Bytes32 {
    return copyBytes(this.currentRoot);
  }

  proof(index: bigint, full = true): readonly Bytes32[] {
    if (index < 0n || index >= this.nextIndex) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index does not exist", {
        details: { index: index.toString(), leafCount: this.nextIndex.toString() },
      });
    }

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
    if (index < 0n || index >= this.nextIndex) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index does not exist", {
        details: { index: index.toString(), leafCount: this.nextIndex.toString() },
      });
    }

    const limit = full ? this.height : this.height - this.canopyDepth;
    const path: Bytes32[] = [];
    let current = index;
    for (let level = 0; level < limit; level += 1) {
      path.push(this.node(level, current));
      current >>= 1n;
    }
    return path;
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

  leafCount(): bigint {
    return this.nextIndex;
  }

  private appendInPlace(leaf: Bytes32): bigint {
    if (this.nextIndex >= this.capacity) {
      throw new MerkleTreeError("MERKLE_TREE_CAPACITY", "Merkle tree is full", {
        details: { capacity: this.capacity.toString() },
      });
    }
    const index = this.nextIndex;
    this.layer(0).set(index, leaf);
    this.nextIndex += 1n;
    this.recompute(index);
    return index;
  }

  private updateInPlace(index: bigint, leaf: Bytes32): void {
    if (index < 0n || index >= this.nextIndex) {
      throw new MerkleTreeError("MERKLE_TREE_INDEX", "Leaf index does not exist", {
        details: { index: index.toString(), leafCount: this.nextIndex.toString() },
      });
    }
    this.layer(0).set(index, leaf);
    this.recompute(index);
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
      }
      current = parent;
    }
    this.roots.push(copyBytes(this.currentRoot));
    if (this.historyCapacity !== undefined && this.roots.length > this.historyCapacity) {
      this.roots.splice(0, this.roots.length - this.historyCapacity);
    }
  }

  private node(level: number, index: bigint): Bytes32 {
    return copyBytes(this.layer(level).get(index) ?? required(this.zeros[level]));
  }

  private layer(level: number): Map<bigint, Bytes32> {
    return required(this.layers[level]);
  }

  private adopt(source: CoreMerkleTree): void {
    this.layers = source.layers;
    this.nextIndex = source.nextIndex;
    this.currentRoot = source.currentRoot;
    this.roots = source.roots;
  }
}

export class MerkleTree {
  private readonly tree: CoreMerkleTree;

  constructor(height: number, hasher: Hasher32) {
    this.tree = new CoreMerkleTree(height, hasher);
  }

  append(leaf: Bytes32): bigint {
    return this.tree.append(leaf);
  }

  root(): Bytes32 {
    return this.tree.root();
  }

  proof(index: bigint): readonly Bytes32[] {
    return this.tree.proof(index);
  }
}
