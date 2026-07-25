import type { Bytes32 } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import fixture from "../../fixtures/merkle-tree/paths-v1.json" with { type: "json" };

import { keccakHasher, poseidonHasher, sha256Hasher } from "../src/hashers.js";
import { IndexedMerkleTree } from "../src/index.js";
import { CoreMerkleTree, type Hasher32 } from "../src/merkle-tree.js";
import { required } from "./helpers.js";

interface HashAdapter extends Hasher32 {
  hashBytes(value: Bytes32): Bytes32;
}

function hasherFor(name: string): HashAdapter {
  switch (name) {
    case "keccak":
      return keccakHasher;
    case "poseidon":
      return poseidonHasher;
    case "sha256":
      return sha256Hasher;
    default:
      throw new Error(`unknown fixture hasher: ${name}`);
  }
}

function hexBytes(hex: string): Bytes32 {
  if (!/^[0-9a-f]{64}$/u.test(hex)) {
    throw new Error("fixture value must be 32-byte lowercase hex");
  }
  const result = new Uint8Array(32);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return result as Bytes32;
}

function decimalBytes(decimal: string): Bytes32 {
  let value = BigInt(decimal);
  const result = new Uint8Array(32);
  for (let index = result.length - 1; index >= 0; index -= 1) {
    result[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (value !== 0n) {
    throw new Error("fixture value exceeds 32 bytes");
  }
  return result as Bytes32;
}

function verifyPath(
  hasher: Hasher32,
  leaf: Bytes32,
  index: bigint,
  path: readonly Bytes32[],
): Bytes32 {
  let hash = leaf;
  let position = index;
  for (const sibling of path) {
    hash = (position & 1n) === 0n ? hasher.hash(hash, sibling) : hasher.hash(sibling, hash);
    position >>= 1n;
  }
  return hash;
}

describe("frozen Merkle vectors", () => {
  for (const vector of fixture.expected.hashers) {
    const hasher = hasherFor(vector.hasher);

    it(`matches ${vector.hasher} hashes, roots, paths, canopy, and history`, () => {
      const pair = vector.pairHashInputBytes.map(hexBytes);
      expect(hasher.hash(required(pair[0]), required(pair[1]))).toEqual(
        hexBytes(vector.pairHashBytes),
      );
      const leaves = vector.leafInputBytes.map((input, index) => {
        const hash = hasher.hashBytes(hexBytes(input));
        expect(hash).toEqual(hexBytes(required(vector.leafHashBytes[index])));
        return hash;
      });
      const tree = new CoreMerkleTree(Number(vector.height), hasher, {
        canopyDepth: Number(vector.canopyDepth),
      });
      expect(tree.root()).toEqual(hexBytes(vector.emptyRootBytes));
      for (const leaf of leaves) {
        tree.append(leaf);
      }
      expect(tree.root()).toEqual(hexBytes(vector.rootBytes));
      expect(tree.history().slice(1)).toEqual(vector.rootHistoryBytes.map(hexBytes));
      expect(tree.nextLeafIndex()).toBe(BigInt(vector.nextIndex));
      expect(tree.path(9n)).toEqual(vector.sparsePathBytes.map(hexBytes));
      expect(tree.proof(9n)).toEqual(vector.sparseProofBytes.map(hexBytes));
      expect(vector.tamperedProofVerified).toBe(false);
      expect(vector.usizeBits).toBe("64");

      const historyTree = new CoreMerkleTree(Number(vector.height), hasher, {
        rootHistoryStartOffset: 1n,
        rootHistoryArrayLength: 3,
      });
      for (const leaf of leaves) {
        historyTree.append(leaf);
      }
      expect(historyTree.history()).toHaveLength(Number(vector.historyRootLength));
      expect(historyTree.historyRootIndex()).toBe(Number(vector.historyRootIndex));
      expect(historyTree.historyRootIndexV2()).toBe(Number(vector.historyRootIndexV2));
      expect(vector.failureMutation).toEqual({
        leafLength: "5",
        rightmostIndex: "4",
        rootHistoryLength: "5",
        sequenceNumber: "4",
      });

      for (const proof of vector.proofs) {
        const index = BigInt(proof.index);
        expect(tree.path(index)).toEqual(proof.pathBytes.map(hexBytes));
        expect(tree.proof(index)).toEqual(proof.proofBytes.map(hexBytes));
        expect(tree.proof(index, false)).toEqual(proof.canopyProofBytes.map(hexBytes));
        expect(
          verifyPath(hasher, required(leaves[Number(index)]), index, tree.proof(index)),
        ).toEqual(tree.root());
      }
    });
  }
});

describe("frozen indexed Merkle vectors", () => {
  for (const vector of fixture.expected.indexed) {
    const hasher = hasherFor(vector.hasher);

    it(`matches ${vector.hasher} ordering, roots, and non-inclusion proofs`, () => {
      const tree = new IndexedMerkleTree(Number(fixture.inputs.height), hasher);
      const roots: Bytes32[] = [];
      for (const insertion of vector.insertions) {
        tree.insert(decimalBytes(insertion));
        roots.push(tree.root());
      }
      expect(roots).toEqual(vector.rootHistoryBytes.slice(1).map(hexBytes));
      expect(tree.root()).toEqual(hexBytes(vector.rootBytes));

      const custom = new IndexedMerkleTree(Number(fixture.inputs.height), hasher, {
        highestValue: hexBytes(vector.customSentinel.sentinelBytes),
      });
      custom.insert(decimalBytes("30"));
      const customProof = custom.nonInclusionProof(hexBytes(vector.customSentinel.valueBytes));
      expect(customProof.root).toEqual(hexBytes(vector.customSentinel.rootBytes));
      expect(customProof.leafHigherRangeValue).toEqual(
        hexBytes(vector.customSentinel.higherValueBytes),
      );
      expect(customProof.merkleProof).toEqual(vector.customSentinel.proofBytes.map(hexBytes));
      expect(custom.verifyNonInclusionProof(customProof)).toBe(true);
      expect(vector.customSentinel.appendAtSentinel).toBe("Ok(())");
      expect(vector.errors).toMatchObject({
        shortPath: "Reference(InvalidProofLength(3, 4))",
        wrongPath: "NonInclusionProofFailed",
        wrongRoot: "NonInclusionProofFailed",
      });

      for (const element of vector.elements) {
        expect(hasher.hash(decimalBytes(element.value), decimalBytes(element.nextValue))).toEqual(
          hexBytes(element.leafHashBytes),
        );
      }

      for (const expectedProof of vector.nonInclusionProofs) {
        const proof = tree.nonInclusionProof(hexBytes(expectedProof.valueBytes));
        expect(proof).toEqual({
          root: hexBytes(expectedProof.rootBytes),
          value: hexBytes(expectedProof.valueBytes),
          leafLowerRangeValue: hexBytes(expectedProof.lowerValueBytes),
          leafHigherRangeValue: hexBytes(expectedProof.higherValueBytes),
          leafIndex: BigInt(expectedProof.leafIndex),
          nextIndex: BigInt(expectedProof.nextIndex),
          merkleProof: expectedProof.proofBytes.map(hexBytes),
        });
        expect(Object.keys(proof)).toEqual([
          "root",
          "value",
          "leafLowerRangeValue",
          "leafHigherRangeValue",
          "leafIndex",
          "nextIndex",
          "merkleProof",
        ]);
        expect(
          verifyPath(
            hasher,
            hasher.hash(proof.leafLowerRangeValue, proof.leafHigherRangeValue),
            proof.leafIndex,
            proof.merkleProof,
          ),
        ).toEqual(proof.root);
        expect(tree.verifyNonInclusionProof(proof)).toBe(true);
      }

      expect(vector.orderedValues.map(decimalBytes)).toEqual([
        decimalBytes("0"),
        decimalBytes("10"),
        decimalBytes("20"),
        decimalBytes("30"),
      ]);
      expect(vector.orderedIndices).toEqual(["0", "2", "3", "1"]);
    });
  }
});
