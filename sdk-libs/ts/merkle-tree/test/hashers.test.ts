import { expect, it } from "vitest";

import { keccakHasher, poseidonHasher, sha256Hasher } from "../src/hashers.js";
import { MerkleTree } from "../src/index.js";
import { leaf } from "./helpers.js";

it("hash adapters do not mutate caller bytes", () => {
  for (const hasher of [poseidonHasher, sha256Hasher, keccakHasher]) {
    const left = leaf(1);
    const right = leaf(2);
    const expectedLeft = left.slice();
    const expectedRight = right.slice();
    const output = hasher.hash(left, right);

    expect(left).toEqual(expectedLeft);
    expect(right).toEqual(expectedRight);
    output.fill(255);
    expect(hasher.hash(left, right)).not.toEqual(output);
  }
});

it("rejects non-canonical Poseidon values without changing tree state", () => {
  const tree = new MerkleTree(2, poseidonHasher);
  const root = tree.root();

  expect(() => tree.append(new Uint8Array(32).fill(255))).toThrow(
    expect.objectContaining({ code: "MERKLE_TREE_HASH" }),
  );
  expect(tree.root()).toEqual(root);
  expect(() => tree.proof(0n)).toThrow(expect.objectContaining({ code: "MERKLE_TREE_INDEX" }));
});
