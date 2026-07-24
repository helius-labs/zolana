import { describe, expect, it } from "vitest";

import { IndexedMerkleTree, IndexedMerkleTreeError } from "../src/index.js";
import { leaf, modelHasher, required, verifyPath } from "./helpers.js";

describe("IndexedMerkleTree", () => {
  it("inserts out of order and returns exact low and high neighbors", () => {
    const tree = new IndexedMerkleTree(4, modelHasher);

    expect(tree.insert(leaf(30))).toBe(1n);
    expect(tree.insert(leaf(10))).toBe(2n);
    expect(tree.insert(leaf(20))).toBe(3n);
    expect(tree.insert(leaf(40))).toBe(4n);

    const proof = tree.nonInclusionProof(leaf(25));
    expect(proof).toMatchObject({
      lowElement: leaf(20),
      lowElementIndex: 3n,
      highElement: leaf(30),
      highElementIndex: 1n,
    });
    const lowLeaf = modelHasher.hash(proof.lowElement, proof.highElement);
    expect(verifyPath(lowLeaf, proof.lowElementIndex, proof.path)).toEqual(proof.root);
    expect(proof.root).toEqual(tree.root());
  });

  it("uses the sentinel for proofs above the highest element", () => {
    const tree = new IndexedMerkleTree(3, modelHasher);
    tree.insert(leaf(10));

    const proof = tree.nonInclusionProof(leaf(11));
    expect(proof.lowElement).toEqual(leaf(10));
    expect(proof.lowElementIndex).toBe(1n);
    expect(proof.highElementIndex).toBe(0n);
    expect(proof.highElement).not.toEqual(new Uint8Array(32));
  });

  it("returns owned roots and non-inclusion proof bytes", () => {
    const tree = new IndexedMerkleTree(3, modelHasher);
    tree.insert(leaf(20));
    const root = tree.root();
    const proof = tree.nonInclusionProof(leaf(10));

    proof.lowElement.fill(255);
    proof.highElement.fill(255);
    required(proof.path[0]).fill(255);
    proof.root.fill(255);
    tree.root().fill(255);

    expect(tree.root()).toEqual(root);
    expect(tree.nonInclusionProof(leaf(10)).root).toEqual(root);
  });

  it("rejects duplicate, boundary, length, and capacity violations", () => {
    const tree = new IndexedMerkleTree(2, modelHasher);
    tree.insert(leaf(10));
    expect(() => tree.insert(leaf(10))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_DUPLICATE" }),
    );
    expect(() => tree.nonInclusionProof(leaf(10))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_DUPLICATE" }),
    );
    expect(() => tree.insert(new Uint8Array(31))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_VALUE" }),
    );
    expect(() => tree.insert(new Uint8Array(32))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_VALUE" }),
    );
    expect(() => tree.insert(new Uint8Array(32).fill(255))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_VALUE" }),
    );

    tree.insert(leaf(20));
    tree.insert(leaf(30));
    expect(() => tree.insert(leaf(40))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_CAPACITY" }),
    );
  });

  it("preserves links and root when hashing fails", () => {
    let fail = false;
    const tree = new IndexedMerkleTree(3, {
      hash(left, right) {
        if (fail) {
          throw new Error("injected failure");
        }
        return modelHasher.hash(left, right);
      },
    });
    tree.insert(leaf(20));
    const root = tree.root();
    fail = true;

    expect(() => tree.insert(leaf(10))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_HASH" }),
    );
    expect(tree.root()).toEqual(root);
    fail = false;
    const proof = tree.nonInclusionProof(leaf(10));
    expect(proof.lowElementIndex).toBe(0n);
    expect(proof.highElementIndex).toBe(1n);
  });

  it("matches a sorted-neighbor model for generated insertion orders", () => {
    const orders = [
      [50, 10, 40, 20, 30],
      [1, 5, 2, 4, 3],
      [90, 70, 80, 60, 100],
    ];

    for (const order of orders) {
      const tree = new IndexedMerkleTree(4, modelHasher);
      for (const value of order) {
        tree.insert(leaf(value));
      }
      const sorted = [...order].sort((left, right) => left - right);
      const first = required(sorted[0]);
      const last = required(sorted.at(-1));
      for (let value = first + 1; value < last; value += 1) {
        if (sorted.includes(value)) {
          continue;
        }
        const low = required(sorted.filter((candidate) => candidate < value).at(-1));
        const high = required(sorted.find((candidate) => candidate > value));
        const proof = tree.nonInclusionProof(leaf(value));
        expect(proof.lowElement).toEqual(leaf(low));
        expect(proof.highElement).toEqual(leaf(high));
        expect(
          verifyPath(
            modelHasher.hash(proof.lowElement, proof.highElement),
            proof.lowElementIndex,
            proof.path,
          ),
        ).toEqual(tree.root());
      }
    }
  });

  it("exposes stable indexed error metadata", () => {
    const error = new IndexedMerkleTreeError("INDEXED_MERKLE_TREE_DUPLICATE", "duplicate", {
      details: { index: "1" },
      cause: "test",
    });
    expect(error).toMatchObject({
      name: "IndexedMerkleTreeError",
      code: "INDEXED_MERKLE_TREE_DUPLICATE",
      details: { index: "1" },
      cause: "test",
    });
  });
});
