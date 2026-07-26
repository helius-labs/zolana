import fc from "fast-check";
import { expect, it } from "vitest";

import { IndexedMerkleTree, MerkleTree } from "../src/index.js";
import { leaf, modelHasher, modelRoot, verifyPath } from "./helpers.js";

it("matches the full-tree model for generated leaves", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 5 }),
      fc.array(fc.integer({ min: 0, max: 255 }), { minLength: 1, maxLength: 16 }),
      (height, values) => {
        const selected = values.slice(0, 1 << height);
        const leaves = selected.map(leaf);
        const tree = new MerkleTree(height, modelHasher);
        for (const value of leaves) {
          tree.append(value);
        }
        expect(tree.root()).toEqual(modelRoot(height, leaves));
        for (const [index, value] of leaves.entries()) {
          expect(verifyPath(value, BigInt(index), tree.proof(BigInt(index)))).toEqual(tree.root());
        }
      },
    ),
  );
});

it("returns generated indexed neighbors in sorted order", () => {
  fc.assert(
    fc.property(
      fc.uniqueArray(fc.integer({ min: 1, max: 200 }), {
        minLength: 1,
        maxLength: 12,
      }),
      fc.integer({ min: 1, max: 200 }),
      (values, query) => {
        fc.pre(!values.includes(query));
        const tree = new IndexedMerkleTree(4, modelHasher);
        for (const value of values) {
          tree.insert(leaf(value));
        }
        const proof = tree.nonInclusionProof(leaf(query));
        const sorted = [...values].sort((left, right) => left - right);
        const low = sorted.filter((value) => value < query).at(-1) ?? 0;
        const high = sorted.find((value) => value > query);
        expect(proof.value).toEqual(leaf(query));
        expect(proof.leafLowerRangeValue).toEqual(leaf(low));
        if (high !== undefined) {
          expect(proof.leafHigherRangeValue).toEqual(leaf(high));
        }
        expect(
          verifyPath(
            modelHasher.hash(proof.leafLowerRangeValue, proof.leafHigherRangeValue),
            proof.leafIndex,
            proof.merkleProof,
          ),
        ).toEqual(tree.root());
        expect(tree.verifyNonInclusionProof(proof)).toBe(true);
      },
    ),
  );
});

it("keeps generated custom-sentinel proofs inside the configured range", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 3, max: 250 }),
      fc.integer({ min: 1, max: 249 }),
      (sentinel, query) => {
        fc.pre(query < sentinel);
        const tree = new IndexedMerkleTree(3, modelHasher, {
          highestValue: leaf(sentinel),
        });
        const proof = tree.nonInclusionProof(leaf(query));
        expect(proof.leafLowerRangeValue).toEqual(leaf(0));
        expect(proof.leafHigherRangeValue).toEqual(leaf(sentinel));
        expect(tree.verifyNonInclusionProof(proof)).toBe(true);

        const tampered = proof.merkleProof.map((node) => node.slice());
        tampered[0]?.fill(255);
        expect(() =>
          tree.verifyNonInclusionProof({
            ...proof,
            merkleProof: tampered,
          }),
        ).toThrow(expect.objectContaining({ code: "INDEXED_MERKLE_TREE_INVALID_PROOF" }));
      },
    ),
  );
});
