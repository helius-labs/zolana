import { describe, expect, it } from "vitest";

import vectors from "../../../vectors/merkle-semantics-v1.json" with { type: "json" };
import type { Bytes32 } from "../../src/bytes.js";
import { poseidonHasher } from "../../src/hashers.js";
import { IndexedMerkleTree } from "../../src/indexed.js";
import { MerkleTree } from "../../src/merkle-tree.js";

type Outcome =
  | { readonly arm: "ok"; readonly value?: string | { readonly verified: boolean } }
  | { readonly arm: "err"; readonly error: string };

interface Step {
  readonly op: string;
  readonly index?: string;
  readonly leafHex?: string;
  readonly valueDecimal?: string;
  readonly outcome: Outcome;
  readonly state: Readonly<Record<string, unknown>>;
}

interface Scenario {
  readonly id: string;
  readonly sentinel?: string;
  readonly tree: {
    readonly height: string;
    readonly canopyDepth: string;
    readonly rootHistoryStartOffset?: string;
    readonly rootHistoryArrayLength?: string;
  };
  readonly steps: readonly Step[];
}

interface Fixture {
  readonly hasher: string;
  readonly highestAddressPlusOne: string;
  readonly scenarios: readonly Scenario[];
}

// A JSON import types every array as the union of its members, which loses the
// per-operation fields. The fixture is generated from one Rust binary against
// these declarations, so it is read through them.
const fixture = vectors as unknown as Fixture;

// The two languages do not share an error taxonomy, so a rejection travels as
// its Rust variant name and this table says which code the port must raise. An
// unmapped variant fails the test rather than passing quietly, so a fixture
// that grows a case nobody translated cannot slip through.
const REJECTIONS: Readonly<Record<string, string>> = {
  IntegerOverflow: "MERKLE_TREE_CAPACITY",
  LeafDoesNotExist: "MERKLE_TREE_INDEX",
  RootHistoryArrayLenNotSet: "MERKLE_TREE_INVALID_HISTORY",
  RootHistoryStartOffsetAboveIndex: "MERKLE_TREE_INVALID_HISTORY",
  ValueOutsideIndexedRange: "INDEXED_MERKLE_TREE_INVALID_VALUE",
  "Indexed(ElementAlreadyExists)": "INDEXED_MERKLE_TREE_DUPLICATE",
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexBytes(hex: string | undefined): Bytes32 {
  if (hex === undefined || !/^[0-9a-f]{64}$/u.test(hex)) {
    throw new Error(`fixture leaf ${String(hex)} is not 32-byte lowercase hex`);
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes as Bytes32;
}

function decimalBytes(decimal: string | undefined): Bytes32 {
  if (decimal === undefined) {
    throw new Error("fixture step is missing its decimal value");
  }
  let value = BigInt(decimal);
  const bytes = new Uint8Array(32);
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (value !== 0n) {
    throw new Error(`fixture value ${decimal} exceeds 32 bytes`);
  }
  return bytes as Bytes32;
}

// Rust `Debug` renders a payload as `LeafDoesNotExist(9)` or `Variant { .. }`.
// The payload names the offending index or offset, which the port carries in
// its error details rather than its code, so only the variant matches.
function expectedCode(error: string): string {
  const variant = error.split(/[ (]/u)[0] ?? error;
  const code = REJECTIONS[error] ?? REJECTIONS[variant];
  if (code === undefined) {
    throw new Error(`no port error code is mapped for Rust ${error}`);
  }
  return code;
}

function expectOutcome(outcome: Outcome, act: () => void): void {
  if (outcome.arm === "ok") {
    expect(act).not.toThrow();
    return;
  }
  expect(act).toThrow(expect.objectContaining({ code: expectedCode(outcome.error) }));
}

// An accessor that Rust reports as a rejection is compared by code, so a
// snapshot entry is either the value or the error the reader must raise.
type Reading = string | { readonly code: string };

function reading(outcome: unknown, read: () => string): Reading {
  const expected = outcome as Outcome;
  if (expected.arm === "ok") {
    return read();
  }
  try {
    read();
  } catch (cause) {
    return { code: (cause as { code?: unknown }).code as string };
  }
  throw new Error(`expected ${expected.error} but the accessor answered`);
}

function expectedReading(outcome: unknown): Reading {
  const expected = outcome as Outcome;
  if (expected.arm === "err") {
    return { code: expectedCode(expected.error) };
  }
  if (typeof expected.value !== "string") {
    throw new Error("a history accessor reports an index, not a structure");
  }
  return expected.value;
}

function scenario(id: string): Scenario {
  const found = fixture.scenarios.find((candidate) => candidate.id === id);
  if (found === undefined) {
    throw new Error(`the fixture has no scenario ${id}`);
  }
  return found;
}

function construct(config: Scenario["tree"]): MerkleTree {
  return new MerkleTree(Number(config.height), poseidonHasher, {
    canopyDepth: Number(config.canopyDepth),
    ...(config.rootHistoryStartOffset === undefined
      ? {}
      : { rootHistoryStartOffset: BigInt(config.rootHistoryStartOffset) }),
    ...(config.rootHistoryArrayLength === undefined
      ? {}
      : { rootHistoryArrayLength: Number(config.rootHistoryArrayLength) }),
  });
}

function applyTreeStep(tree: MerkleTree, step: Step): void {
  switch (step.op) {
    case "construct":
      return;
    case "append":
      expectOutcome(step.outcome, () => tree.append(hexBytes(step.leafHex)));
      return;
    case "update":
      expectOutcome(step.outcome, () => {
        tree.update(BigInt(String(step.index)), hexBytes(step.leafHex));
      });
      return;
    case "insertLeaf":
      expectOutcome(step.outcome, () => {
        tree.insertLeaf(BigInt(String(step.index)), hexBytes(step.leafHex));
      });
      return;
    default:
      throw new Error(`the port has no Merkle operation for ${step.op}`);
  }
}

function treeSnapshot(tree: MerkleTree, step: Step): Record<string, Reading> {
  return {
    rootHex: bytesToHex(tree.root()),
    nextIndex: tree.nextIndex().toString(),
    leafCount: tree.leaves().length.toString(),
    rootHistoryLength: tree.history().length.toString(),
    sequenceNumber: tree.sequenceNumber().toString(),
    historyRootIndex: reading(step.state.historyRootIndex, () => String(tree.historyRootIndex())),
    historyRootIndexV2: reading(step.state.historyRootIndexV2, () =>
      String(tree.historyRootIndexV2()),
    ),
  };
}

function expectedTreeSnapshot(step: Step): Record<string, Reading> {
  return {
    rootHex: String(step.state.rootHex),
    nextIndex: String(step.state.nextIndex),
    leafCount: String(step.state.leafCount),
    rootHistoryLength: String(step.state.rootHistoryLength),
    sequenceNumber: String(step.state.sequenceNumber),
    historyRootIndex: expectedReading(step.state.historyRootIndex),
    historyRootIndexV2: expectedReading(step.state.historyRootIndexV2),
  };
}

function replayTree(id: string): void {
  const trace = scenario(id);
  const tree = construct(trace.tree);
  for (const [position, step] of trace.steps.entries()) {
    applyTreeStep(tree, step);
    expect({ step: position, ...treeSnapshot(tree, step) }).toEqual({
      step: position,
      ...expectedTreeSnapshot(step),
    });
  }
}

function applyIndexedStep(tree: IndexedMerkleTree, step: Step): void {
  switch (step.op) {
    case "construct":
      return;
    case "append":
      expectOutcome(step.outcome, () => tree.insert(decimalBytes(step.valueDecimal)));
      return;
    case "nonInclusionProof":
      expectOutcome(step.outcome, () => {
        const proof = tree.nonInclusionProof(decimalBytes(step.valueDecimal));
        expect(tree.verifyNonInclusionProof(proof)).toBe(true);
      });
      return;
    default:
      throw new Error(`the port has no indexed operation for ${step.op}`);
  }
}

function replayIndexed(id: string): void {
  const trace = scenario(id);
  const tree = new IndexedMerkleTree(Number(trace.tree.height), poseidonHasher, {
    canopyDepth: Number(trace.tree.canopyDepth),
    ...(trace.sentinel === undefined ? {} : { highestValue: decimalBytes(trace.sentinel) }),
  });
  for (const [position, step] of trace.steps.entries()) {
    applyIndexedStep(tree, step);
    // `IndexedMerkleTree` keeps its Merkle tree private, so the fixture's
    // `nextIndex` is checked against the element count it always equals: each
    // element owns exactly one appended leaf, starting with the zero element.
    expect(step.state.nextIndex).toBe(step.state.elementCount);
    expect({
      step: position,
      rootHex: bytesToHex(tree.root()),
      elementCount: tree.elementCount().toString(),
      highestValue: bytesToHex(tree.highestValue()),
    }).toEqual({
      step: position,
      rootHex: String(step.state.rootHex),
      elementCount: String(step.state.elementCount),
      highestValue: bytesToHex(decimalBytes(String(step.state.highestValue))),
    });
  }
}

describe("Merkle semantics against the Rust reference tree", () => {
  it("hashes with the fixture's hasher", () => {
    expect(fixture.hasher).toBe("poseidon");
  });

  it("leaves the next index free of the root-history offset", () => {
    replayTree("history-offset-does-not-shift-next-index");
  });

  it("keeps a rejected append or update from touching the tree", () => {
    replayTree("rejected-mutations-leave-the-tree-unchanged");
  });

  it("refuses both history accessors when no history is configured", () => {
    replayTree("history-accessors-reject-an-unconfigured-tree");
  });
});

describe("Indexed Merkle semantics against the Rust reference tree", () => {
  it("ships the Rust sentinel", () => {
    expect(bytesToHex(new IndexedMerkleTree(4, poseidonHasher).highestValue())).toBe(
      bytesToHex(decimalBytes(fixture.highestAddressPlusOne)),
    );
  });

  it("closes the indexed range at the sentinel", () => {
    replayIndexed("sentinel-closes-the-indexed-range");
  });

  it("keeps proving from the same root after a rejected append", () => {
    replayIndexed("rejected-indexed-appends-leave-the-tree-provable");
  });
});
