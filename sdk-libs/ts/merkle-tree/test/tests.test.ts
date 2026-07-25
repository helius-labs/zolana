import { describe, expect, it } from "vitest";

import * as publicApi from "../src/index.js";
import { CoreMerkleTree } from "../src/merkle-tree.js";
import { MerkleTree, MerkleTreeError } from "../src/index.js";
import { bytesEqual, leaf, modelHasher, modelRoot, required, verifyPath } from "./helpers.js";

describe("MerkleTree", () => {
  it("exports only the runtime allowlist", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "IndexedMerkleTree",
      "IndexedMerkleTreeError",
      "MerkleTree",
      "MerkleTreeError",
      "keccakHasher",
      "poseidonHasher",
      "sha256Hasher",
      "verifyNonInclusionProof",
    ]);
  });

  it("matches the independent root model and verifies every path", () => {
    const tree = new MerkleTree(4, modelHasher);
    const leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];

    for (const [index, value] of leaves.entries()) {
      expect(tree.append(value)).toBe(BigInt(index));
      expect(tree.root()).toEqual(modelRoot(4, leaves.slice(0, index + 1)));
    }

    for (const [index, value] of leaves.entries()) {
      expect(verifyPath(value, BigInt(index), tree.proof(BigInt(index)))).toEqual(tree.root());
    }
  });

  it("returns owned roots and paths", () => {
    const tree = new MerkleTree(2, modelHasher);
    const value = leaf(7);
    tree.append(value);
    const expectedRoot = tree.root();

    value.fill(255);
    tree.root().fill(255);
    required(tree.proof(0n)[0]).fill(255);

    expect(tree.root()).toEqual(expectedRoot);
    expect(verifyPath(leaf(7), 0n, tree.proof(0n))).toEqual(expectedRoot);
  });

  it("rejects invalid configuration, bytes, capacity, indexes, and hashers", () => {
    expect(() => new MerkleTree(0, modelHasher)).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_INVALID_HEIGHT" }),
    );
    expect(() => new MerkleTree(2, {} as never)).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_INVALID_HASHER" }),
    );

    const tree = new MerkleTree(1, modelHasher);
    expect(() => tree.append(new Uint8Array(31))).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_INVALID_BYTES" }),
    );
    expect(() => tree.proof(-1n)).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_INDEX_WIDTH" }),
    );
    tree.append(leaf(1));
    tree.append(leaf(2));
    const fullRoot = tree.root();
    expect(() => tree.append(leaf(3))).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_CAPACITY" }),
    );
    expect(tree.root()).toEqual(fullRoot);
    expect(tree.leafCount()).toBe(2n);
    expect(tree.leaves()).toEqual([leaf(1), leaf(2)]);

    expect(
      () =>
        new MerkleTree(2, {
          hash() {
            return new Uint8Array(31);
          },
        }),
    ).toThrow(expect.objectContaining({ code: "MERKLE_TREE_INVALID_BYTES" }));
  });

  it("preserves state when hashing fails", () => {
    let fail = false;
    const tree = new MerkleTree(3, {
      hash(left, right) {
        if (fail) {
          throw new Error("injected failure");
        }
        return modelHasher.hash(left, right);
      },
    });
    tree.append(leaf(1));
    const root = tree.root();
    fail = true;

    expect(() => tree.append(leaf(2))).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_HASH" }),
    );
    expect(tree.root()).toEqual(root);
    expect(tree.proof(1n)).toHaveLength(3);
  });

  it("exposes update, path, verification, leaves, subtrees, and batch append", () => {
    const tree = new MerkleTree(3, modelHasher, { canopyDepth: 1 });
    expect(tree.appendBatch([leaf(1), leaf(2)])).toEqual([0n, 1n]);
    expect(tree.leafCount()).toBe(2n);
    expect(tree.nextIndex()).toBe(3n);
    expect(tree.sequenceNumber()).toBe(2n);
    expect(tree.leaves()).toEqual([leaf(1), leaf(2)]);
    expect(tree.leafIndex(leaf(2))).toBe(1n);
    expect(tree.path(1n, false)).toHaveLength(2);
    expect(tree.proof(1n, false)).toHaveLength(2);
    expect(tree.proofs([0n, 1n])).toHaveLength(2);
    expect(tree.canopy()).toHaveLength(Number(tree.canopySize()));
    expect(tree.subtrees()).toHaveLength(3);

    const proof = tree.proof(0n);
    expect(tree.verify(leaf(1), proof, 0n)).toBe(true);
    expect(tree.verify(leaf(2), proof, 0n)).toBe(false);
    tree.update(0n, leaf(3));
    expect(tree.getLeaf(0n)).toEqual(leaf(3));
    expect(tree.sequenceNumber()).toBe(3n);
  });

  it("returns sparse paths and validates proof lengths and u64 indexes", () => {
    const tree = new MerkleTree(3, modelHasher);
    tree.append(leaf(1));

    expect(tree.path(7n)).toHaveLength(3);
    expect(tree.proof(7n)).toHaveLength(3);
    expect(() => tree.getLeaf(7n)).toThrow(expect.objectContaining({ code: "MERKLE_TREE_INDEX" }));
    expect(() => tree.verify(leaf(1), tree.proof(0n).slice(1), 0n)).toThrow(
      expect.objectContaining({
        code: "MERKLE_TREE_INVALID_PROOF_LENGTH",
        details: { actual: 2, required: 3 },
      }),
    );
    expect(() => tree.path(1n << 64n)).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_INDEX_WIDTH" }),
    );
  });

  it("tracks full root history and Rust-compatible history indexes", () => {
    const tree = new MerkleTree(3, modelHasher, {
      rootHistoryStartOffset: 1n,
      rootHistoryArrayLength: 3,
    });
    tree.appendBatch([leaf(1), leaf(2), leaf(3)]);

    expect(tree.history()).toHaveLength(4);
    expect(tree.historyRootIndex()).toBe(2);
    expect(tree.historyRootIndexV2()).toBe(0);
    expect(tree.nextIndex()).toBe(4n);
  });

  it("reconstructs sparse nodes without narrowing bigint positions", () => {
    const tree = new MerkleTree(4, modelHasher);
    const position = (1n << 40n) + 7n;
    tree.insertNode((2n << 56n) | position, leaf(9));
    expect(tree.path(position << 2n)[2]).toEqual(leaf(9));
    tree.insertLeaf(5n, leaf(4));
    expect(tree.getLeaf(5n)).toEqual(leaf(4));
    tree.ensureLayerCapacity(0, 7n);
    expect(tree.getLeaf(7n)).toEqual(leaf(0));
  });
});

describe("CoreMerkleTree", () => {
  it("applies canopy truncation and bounded root history", () => {
    const tree = new CoreMerkleTree(4, modelHasher, {
      canopyDepth: 2,
      rootHistoryArrayLength: 2,
    });
    tree.append(leaf(1));
    tree.append(leaf(2));

    expect(tree.proof(0n, false)).toHaveLength(2);
    expect(tree.path(0n, false)).toHaveLength(2);
    expect(tree.canopy()).toHaveLength(6);
    expect(tree.history()).toHaveLength(3);
  });

  it("matches a model across deterministic generated sequences", () => {
    let state = 0x6d2b79f5;
    for (let run = 0; run < 20; run += 1) {
      const height = 2 + (run % 4);
      const count = 1 + (run % ((1 << height) - 1));
      const values: Uint8Array[] = [];
      const tree = new CoreMerkleTree(height, modelHasher);
      for (let index = 0; index < count; index += 1) {
        state = (Math.imul(state ^ (state >>> 15), 1 | state) + 0x9e3779b9) | 0;
        const value = leaf(state & 0xff);
        values.push(value);
        tree.append(value);
      }
      expect(bytesEqual(tree.root(), modelRoot(height, values))).toBe(true);
      for (const [index, value] of values.entries()) {
        expect(verifyPath(value, BigInt(index), tree.proof(BigInt(index)))).toEqual(tree.root());
      }
    }
  });

  it("exposes stable error metadata", () => {
    const error = new MerkleTreeError("MERKLE_TREE_INDEX", "missing", {
      details: { index: "2" },
      cause: "test",
    });
    expect(error).toMatchObject({
      name: "MerkleTreeError",
      code: "MERKLE_TREE_INDEX",
      details: { index: "2" },
      cause: "test",
    });
  });
});
