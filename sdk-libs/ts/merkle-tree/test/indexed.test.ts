import type { Bytes32 } from "@zolana/interface";
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
      value: leaf(25),
      leafLowerRangeValue: leaf(20),
      leafHigherRangeValue: leaf(30),
      leafIndex: 3n,
      nextIndex: 1n,
    });
    const lowLeaf = modelHasher.hash(proof.leafLowerRangeValue, proof.leafHigherRangeValue);
    expect(verifyPath(lowLeaf, proof.leafIndex, proof.merkleProof)).toEqual(proof.root);
    expect(tree.verifyNonInclusionProof(proof)).toBe(true);
    expect(proof.root).toEqual(tree.root());
  });

  it("uses the sentinel for proofs above the highest element", () => {
    const tree = new IndexedMerkleTree(3, modelHasher);
    tree.insert(leaf(10));

    const proof = tree.nonInclusionProof(leaf(11));
    expect(proof.leafLowerRangeValue).toEqual(leaf(10));
    expect(proof.leafIndex).toBe(1n);
    expect(proof.nextIndex).toBe(0n);
    expect(proof.leafHigherRangeValue).not.toEqual(new Uint8Array(32));
  });

  it("supports custom sentinels and enforces their open interval", () => {
    const tree = new IndexedMerkleTree(3, modelHasher, { highestValue: leaf(100) });
    tree.insert(leaf(20));
    const proof = tree.nonInclusionProof(leaf(50));

    expect(tree.highestValue()).toEqual(leaf(100));
    expect(proof.leafHigherRangeValue).toEqual(leaf(100));
    expect(tree.verifyNonInclusionProof(proof)).toBe(true);
    expect(() => tree.insert(leaf(100))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_VALUE" }),
    );
    expect(() => tree.insert(leaf(101))).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_VALUE" }),
    );
    expect(() => new IndexedMerkleTree(3, modelHasher, { highestValue: leaf(0) })).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_SENTINEL" }),
    );
    expect(
      () => new IndexedMerkleTree(3, modelHasher, { highestValue: new Uint8Array(31) }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_SENTINEL" }));
    expect(() => tree.element(1n << 64n)).toThrow(
      expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INDEX" }),
    );
  });

  it("exposes Rust-compatible path, proof, element, and update operations", () => {
    const inserted = new IndexedMerkleTree(3, modelHasher);
    inserted.insert(leaf(20));

    const updated = new IndexedMerkleTree(3, modelHasher);
    updated.update(
      { index: 0n, value: leaf(0), nextIndex: 1n },
      { index: 1n, value: leaf(20), nextIndex: 0n },
      updated.highestValue(),
    );

    expect(updated.root()).toEqual(inserted.root());
    expect(inserted.path(0n)).toHaveLength(3);
    expect(inserted.proof(0n)).toHaveLength(3);
    expect(inserted.element(1n)).toEqual({
      index: 1n,
      value: leaf(20),
      nextIndex: 0n,
    });
    expect(inserted.elementCount()).toBe(2n);
  });

  it("returns owned roots and non-inclusion proof bytes", () => {
    const tree = new IndexedMerkleTree(3, modelHasher);
    tree.insert(leaf(20));
    const root = tree.root();
    const proof = tree.nonInclusionProof(leaf(10));

    proof.value.fill(255);
    proof.leafLowerRangeValue.fill(255);
    proof.leafHigherRangeValue.fill(255);
    required(proof.merkleProof[0]).fill(255);
    proof.root.fill(255);
    tree.root().fill(255);

    expect(tree.root()).toEqual(root);
    expect(tree.nonInclusionProof(leaf(10))).toMatchObject({
      root,
      value: leaf(10),
      leafLowerRangeValue: leaf(0),
      leafHigherRangeValue: leaf(20),
    });
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
    expect(proof.leafIndex).toBe(0n);
    expect(proof.nextIndex).toBe(1n);
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
        expect(proof.value).toEqual(leaf(value));
        expect(proof.leafLowerRangeValue).toEqual(leaf(low));
        expect(proof.leafHigherRangeValue).toEqual(leaf(high));
        expect(
          verifyPath(
            modelHasher.hash(proof.leafLowerRangeValue, proof.leafHigherRangeValue),
            proof.leafIndex,
            proof.merkleProof,
          ),
        ).toEqual(tree.root());
        expect(tree.verifyNonInclusionProof(proof)).toBe(true);
      }
    }
  });

  it("rejects bound and Merkle proof mutations", () => {
    const tree = new IndexedMerkleTree(3, modelHasher);
    tree.insert(leaf(20));
    const proof = tree.nonInclusionProof(leaf(10));

    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        leafLowerRangeValue: leaf(10),
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_LOWER_BOUND" }));
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        leafHigherRangeValue: leaf(10),
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_HIGHER_BOUND" }));

    const merkleProof = proof.merkleProof.map((node) => node.slice());
    required(merkleProof[0]).fill(255);
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        merkleProof,
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        root: new Uint8Array(31) as Bytes32,
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        leafIndex: -1n,
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        root: leaf(99),
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        merkleProof: proof.merkleProof.slice(1),
      }),
    ).toThrow(
      expect.objectContaining({
        code: "INDEXED_MERKLE_TREE_INVALID_PROOF",
        details: { actual: 2, required: 3 },
      }),
    );
    expect(() =>
      tree.verifyNonInclusionProof({
        ...proof,
        leafIndex: 1n << 64n,
      }),
    ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
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
