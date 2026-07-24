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
    expect(() => tree.proof(-1n)).toThrow(expect.objectContaining({ code: "MERKLE_TREE_INDEX" }));
    tree.append(leaf(1));
    tree.append(leaf(2));
    expect(() => tree.append(leaf(3))).toThrow(
      expect.objectContaining({ code: "MERKLE_TREE_CAPACITY" }),
    );

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
    expect(() => tree.proof(1n)).toThrow(expect.objectContaining({ code: "MERKLE_TREE_INDEX" }));
  });
});

describe("CoreMerkleTree", () => {
  it("applies canopy truncation and bounded root history", () => {
    const tree = new CoreMerkleTree(4, modelHasher, {
      canopyDepth: 2,
      historyCapacity: 2,
    });
    tree.append(leaf(1));
    tree.append(leaf(2));

    expect(tree.proof(0n, false)).toHaveLength(2);
    expect(tree.path(0n, false)).toHaveLength(2);
    expect(tree.canopy()).toHaveLength(6);
    expect(tree.history()).toHaveLength(2);
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
