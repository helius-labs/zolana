import type { Bytes32 } from "@zolana/interface";
import { IndexedMerkleTree, MerkleTree, poseidonHasher } from "@zolana/merkle-tree";
import fc from "fast-check";
import { afterAll, describe, expect, it } from "vitest";

import { probe, writeReport } from "./differential.js";
import { bigintTo32, fieldLeaf } from "./generators.js";
import { hex, oracle, outcomeOf, parseOutcome } from "./oracle.js";

/**
 * Poseidon over 12 levels and six leaves keeps a full sample under a minute on
 * both sides. Heights above 40 are excluded because `MerkleTree::new` reads
 * `H::zero_bytes()[height]` and that table holds 41 entries.
 */
const MAX_HEIGHT = 12;
const MAX_LEAVES = 6;

interface TreeCase {
  readonly height: number;
  readonly canopyDepth: number;
  readonly leaves: readonly Uint8Array[];
}

interface IndexCase extends TreeCase {
  readonly index: bigint;
  readonly full: boolean;
}

interface HistoryCase extends TreeCase {
  readonly rootHistoryStartOffset: bigint;
  readonly rootHistoryArrayLength: number;
}

const wellFormedLeaf = fieldLeaf;
const anyLengthLeaf = fc.oneof(
  { arbitrary: fc.uint8Array({ minLength: 0, maxLength: 40 }), weight: 3 },
  { arbitrary: fieldLeaf, weight: 1 },
);

function treeCase(leaf: fc.Arbitrary<Uint8Array>): fc.Arbitrary<TreeCase> {
  return fc
    .record({
      height: fc.integer({ min: 1, max: MAX_HEIGHT }),
      canopyOffset: fc.nat({ max: MAX_HEIGHT }),
      leaves: fc.array(leaf, { maxLength: MAX_LEAVES }),
    })
    .map(({ height, canopyOffset, leaves }) => ({
      height,
      canopyDepth: canopyOffset % (height + 1),
      leaves,
    }));
}

function treeRequest(value: TreeCase): string {
  return JSON.stringify({
    hasher: "poseidon",
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    leaves: value.leaves.map(hex),
  });
}

function renderTree(value: TreeCase): Record<string, unknown> {
  return {
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    leaves: value.leaves.map(hex),
  };
}

/** Builds the native tree by appending every leaf, so a rejection surfaces. */
function nativeTree(value: TreeCase): MerkleTree {
  const tree = new MerkleTree(value.height, poseidonHasher, {
    canopyDepth: value.canopyDepth,
  });
  for (const leaf of value.leaves) tree.append(leaf as Bytes32);
  return tree;
}

describe("W-07 Merkle operations", () => {
  afterAll(() => {
    writeReport("w07-merkle");
  });

  it("root", () => {
    const summary = probe<TreeCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::root",
      arbitrary: treeCase(wellFormedLeaf),
      rust: (value) => parseOutcome(oracle.merkle_root(treeRequest(value))),
      typescript: (value) => outcomeOf(() => hex(nativeTree(value).root())),
      render: renderTree,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("root rejects the same leaf lengths", () => {
    const summary = probe<TreeCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::append",
      arbitrary: treeCase(anyLengthLeaf),
      rust: (value) => parseOutcome(oracle.merkle_root(treeRequest(value))),
      typescript: (value) => outcomeOf(() => hex(nativeTree(value).root())),
      render: renderTree,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("proof", () => {
    const summary = probe<IndexCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_proof_of_leaf",
      arbitrary: indexCase(),
      rust: (value) =>
        parseOutcome(
          oracle.merkle_proof(indexRequest(value)),
        ),
      typescript: (value) =>
        outcomeOf(() => nativeTree(value).proof(value.index, value.full).map(hex)),
      render: renderIndex,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("path", () => {
    const summary = probe<IndexCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_path_of_leaf",
      arbitrary: indexCase(),
      rust: (value) => parseOutcome(oracle.merkle_path(indexRequest(value))),
      typescript: (value) =>
        outcomeOf(() => nativeTree(value).path(value.index, value.full).map(hex)),
      render: renderIndex,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("get_leaf", () => {
    const summary = probe<IndexCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_leaf",
      arbitrary: indexCase(),
      rust: (value) => parseOutcome(oracle.merkle_leaf(indexRequest(value))),
      typescript: (value) => outcomeOf(() => hex(nativeTree(value).getLeaf(value.index))),
      render: renderIndex,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("subtrees", () => {
    const summary = probe<TreeCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_subtrees",
      arbitrary: treeCase(wellFormedLeaf),
      rust: (value) => parseOutcome(oracle.merkle_subtrees(treeRequest(value))),
      typescript: (value) => outcomeOf(() => nativeTree(value).subtrees().map(hex)),
      render: renderTree,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("canopy", () => {
    const summary = probe<TreeCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_canopy",
      arbitrary: treeCase(wellFormedLeaf),
      rust: (value) => parseOutcome(oracle.merkle_canopy(treeRequest(value))),
      typescript: (value) => outcomeOf(() => nativeTree(value).canopy().map(hex)),
      render: renderTree,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("verify", () => {
    const summary = probe<IndexCase & { readonly tamper: number }>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::verify",
      arbitrary: fc.record({
        base: indexCase(),
        tamper: fc.nat({ max: 3 }),
      }).map(({ base, tamper }) => ({ ...base, tamper })),
      rust: (value) => {
        const proof = honestProof(value);
        return parseOutcome(
          oracle.merkle_verify(
            JSON.stringify({
              hasher: "poseidon",
              height: String(value.height),
              canopyDepth: String(value.canopyDepth),
              leaves: value.leaves.map(hex),
              leaf: hex(leafAt(value)),
              proof: proof.map(hex).slice(0, proof.length - (value.tamper === 3 ? 1 : 0)),
              index: value.index.toString(),
            }),
          ),
        );
      },
      typescript: (value) => {
        const proof = honestProof(value);
        const trimmed = value.tamper === 3 ? proof.slice(0, proof.length - 1) : proof;
        return outcomeOf(() =>
          nativeTree(value).verify(leafAt(value) as Bytes32, trimmed as Bytes32[], value.index),
        );
      },
      render: (value) => ({ ...renderIndex(value), tamper: value.tamper }),
      cases: 300,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("history root index", () => {
    const summary = probe<HistoryCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_history_root_index",
      arbitrary: historyCase(),
      rust: (value) => parseOutcome(oracle.merkle_history_root_index(historyRequest(value))),
      typescript: (value) => outcomeOf(() => String(historyTree(value).historyRootIndex())),
      render: renderHistory,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("history root index v2", () => {
    const summary = probe<HistoryCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/lib.rs::MerkleTree::get_history_root_index_v2",
      arbitrary: historyCase(),
      rust: (value) => parseOutcome(oracle.merkle_history_root_index_v2(historyRequest(value))),
      typescript: (value) => outcomeOf(() => String(historyTree(value).historyRootIndexV2())),
      render: renderHistory,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("indexed root", () => {
    const summary = probe<IndexedCase>({
      rustSymbol: "sdk-libs/merkle-tree/src/indexed.rs::IndexedMerkleTree::append",
      arbitrary: indexedCase(),
      rust: (value) => parseOutcome(oracle.indexed_root(indexedRequest(value))),
      typescript: (value) => outcomeOf(() => hex(nativeIndexedTree(value).root())),
      render: renderIndexed,
      cases: 250,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });

  it("indexed non-inclusion proof", () => {
    const summary = probe<IndexedCase & { readonly query: bigint }>({
      rustSymbol:
        "sdk-libs/merkle-tree/src/indexed.rs::IndexedMerkleTree::get_non_inclusion_proof",
      arbitrary: fc
        .record({ base: indexedCase(), query: indexedValue })
        .map(({ base, query }) => ({ ...base, query })),
      rust: (value) =>
        parseOutcome(
          oracle.indexed_non_inclusion_proof(
            JSON.stringify({
              hasher: "poseidon",
              height: String(value.height),
              canopyDepth: String(value.canopyDepth),
              values: value.values.map(String),
              value: value.query.toString(),
            }),
          ),
        ),
      typescript: (value) =>
        outcomeOf(() => {
          const proof = nativeIndexedTree(value).nonInclusionProof(
            bigintTo32(value.query) as Bytes32,
          );
          return {
            root: hex(proof.root),
            value: hex(proof.value),
            leafLowerRangeValue: hex(proof.leafLowerRangeValue),
            leafHigherRangeValue: hex(proof.leafHigherRangeValue),
            leafIndex: proof.leafIndex.toString(),
            nextIndex: proof.nextIndex.toString(),
            merkleProof: proof.merkleProof.map(hex),
          };
        }),
      render: (value) => ({ ...renderIndexed(value), query: value.query.toString() }),
      cases: 250,
    });
    expect(summary.cases).toBeGreaterThan(0);
  });
});

function indexCase(): fc.Arbitrary<IndexCase> {
  return fc
    .record({
      base: treeCase(wellFormedLeaf),
      index: fc.bigInt({ min: 0n, max: 1n << 14n }),
      full: fc.boolean(),
    })
    .map(({ base, index, full }) => ({ ...base, index, full }));
}

function indexRequest(value: IndexCase): string {
  return JSON.stringify({
    hasher: "poseidon",
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    leaves: value.leaves.map(hex),
    index: value.index.toString(),
    full: value.full,
  });
}

function renderIndex(value: IndexCase): Record<string, unknown> {
  return { ...renderTree(value), index: value.index.toString(), full: value.full };
}

/** Proof produced by the native tree, used as the honest input to `verify`. */
function honestProof(value: IndexCase): Uint8Array[] {
  try {
    return [...nativeTree(value).proof(value.index, true)];
  } catch {
    return Array.from({ length: value.height }, () => new Uint8Array(32));
  }
}

function leafAt(value: IndexCase): Uint8Array {
  const position = Number(value.index % BigInt(Math.max(value.leaves.length, 1)));
  return value.leaves[position] ?? new Uint8Array(32);
}

function historyCase(): fc.Arbitrary<HistoryCase> {
  return fc
    .record({
      base: treeCase(wellFormedLeaf),
      rootHistoryStartOffset: fc.bigInt({ min: 0n, max: 8n }),
      rootHistoryArrayLength: fc.integer({ min: 0, max: 8 }),
    })
    .map(({ base, rootHistoryStartOffset, rootHistoryArrayLength }) => ({
      ...base,
      rootHistoryStartOffset,
      rootHistoryArrayLength,
    }));
}

function historyRequest(value: HistoryCase): string {
  return JSON.stringify({
    hasher: "poseidon",
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    leaves: value.leaves.map(hex),
    rootHistoryStartOffset: value.rootHistoryStartOffset.toString(),
    rootHistoryArrayLen: String(value.rootHistoryArrayLength),
  });
}

function historyTree(value: HistoryCase): MerkleTree {
  const tree = new MerkleTree(value.height, poseidonHasher, {
    canopyDepth: value.canopyDepth,
    rootHistoryStartOffset: value.rootHistoryStartOffset,
    rootHistoryArrayLength: value.rootHistoryArrayLength,
  });
  for (const leaf of value.leaves) tree.append(leaf as Bytes32);
  return tree;
}

function renderHistory(value: HistoryCase): Record<string, unknown> {
  return {
    ...renderTree(value),
    rootHistoryStartOffset: value.rootHistoryStartOffset.toString(),
    rootHistoryArrayLen: String(value.rootHistoryArrayLength),
  };
}

interface IndexedCase {
  readonly height: number;
  readonly canopyDepth: number;
  readonly values: readonly bigint[];
}

/** `HIGHEST_ADDRESS_PLUS_ONE`, the sentinel that closes the indexed range. */
const HIGHEST_ADDRESS_PLUS_ONE = (1n << 248n) - 1n;

const indexedValue = fc.oneof(
  { arbitrary: fc.bigInt({ min: 0n, max: 1n << 40n }), weight: 6 },
  {
    arbitrary: fc.constantFrom(
      0n,
      1n,
      HIGHEST_ADDRESS_PLUS_ONE - 1n,
      HIGHEST_ADDRESS_PLUS_ONE,
      HIGHEST_ADDRESS_PLUS_ONE + 1n,
    ),
    weight: 2,
  },
);

function indexedCase(): fc.Arbitrary<IndexedCase> {
  return fc
    .record({
      height: fc.integer({ min: 2, max: 8 }),
      canopyOffset: fc.nat({ max: 8 }),
      values: fc.array(indexedValue, { maxLength: 4 }),
    })
    .map(({ height, canopyOffset, values }) => ({
      height,
      canopyDepth: canopyOffset % (height + 1),
      values,
    }));
}

function indexedRequest(value: IndexedCase): string {
  return JSON.stringify({
    hasher: "poseidon",
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    values: value.values.map(String),
  });
}

function nativeIndexedTree(value: IndexedCase): IndexedMerkleTree {
  const tree = new IndexedMerkleTree(value.height, poseidonHasher, {
    canopyDepth: value.canopyDepth,
  });
  for (const item of value.values) tree.insert(bigintTo32(item) as Bytes32);
  return tree;
}

function renderIndexed(value: IndexedCase): Record<string, unknown> {
  return {
    height: String(value.height),
    canopyDepth: String(value.canopyDepth),
    values: value.values.map(String),
  };
}
