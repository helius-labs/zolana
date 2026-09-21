import { afterEach, describe, expect, it, vi } from "vitest";
import * as treeSlots from "../src/interface/tree-slot.js";
import { resolvedPublicInputHash } from "../src/client/prover/assembly.js";
import { bigintToBytes, checkedBytes } from "../src/client/internal.js";

function statement() {
  return {
    fields: [991n, 992n, 993n],
    trees: Array.from(
      treeSlots.inputTreeSlots([
        {
          id: 7,
          utxoRoot: checkedBytes(bigintToBytes(11n), 32, "root"),
          nullifierRoot: checkedBytes(bigintToBytes(12n), 32, "root"),
        },
      ]),
    ),
  };
}

afterEach(() => vi.restoreAllMocks());

describe("resolved public statement reuse", () => {
  it("hashes equal copied statements once", () => {
    const input = statement();
    resolvedPublicInputHash([994n], input.trees);
    const hashing = vi.spyOn(treeSlots, "treeSlotsHashChain");
    const expected = resolvedPublicInputHash(input.fields, input.trees);
    const copied = statement();
    expect(resolvedPublicInputHash(copied.fields, copied.trees)).toBe(expected);
    expect(hashing).toHaveBeenCalledTimes(1);
  });

  it("rejects mutable bigint coercion before cache lookup", () => {
    const input = statement();
    const expected = resolvedPublicInputHash(input.fields, input.trees);
    let value = 991n;
    Object.assign(input.fields, { 0: { valueOf: () => value } });
    expect(() => resolvedPublicInputHash(input.fields, input.trees)).toThrow();
    value = 999n;
    expect(() => resolvedPublicInputHash(input.fields, input.trees)).toThrow();
    const original = statement();
    expect(resolvedPublicInputHash(original.fields, original.trees)).toBe(expected);
  });

  it.each([
    "field",
    "fieldOrder",
    "fieldLength",
    "treeId",
    "treeOrder",
    "utxoRoot",
    "nullifierRoot",
  ] as const)("does not reuse a changed %s", (part) => {
    const input = statement();
    const expected = resolvedPublicInputHash(input.fields, input.trees);
    const hashing = vi.spyOn(treeSlots, "treeSlotsHashChain");
    const tree = input.trees[0];
    if (tree === undefined) throw new Error("missing tree");
    switch (part) {
      case "field":
        input.fields[0] = 997n;
        break;
      case "fieldOrder":
        input.fields.reverse();
        break;
      case "fieldLength":
        input.fields.push(998n);
        break;
      case "treeId":
        input.trees[0] = { ...tree, id: 8 };
        break;
      case "treeOrder":
        input.trees.reverse();
        break;
      case "utxoRoot":
        tree.utxoRoot[31] = 13;
        break;
      case "nullifierRoot":
        tree.nullifierRoot[31] = 14;
        break;
    }
    expect(resolvedPublicInputHash(input.fields, input.trees)).not.toBe(expected);
    expect(hashing).toHaveBeenCalledTimes(1);
  });

  it("rejects invalid roots and tree counts after a valid cache entry", () => {
    const input = statement();
    const expected = resolvedPublicInputHash(input.fields, input.trees);
    const tree = input.trees[0];
    if (tree === undefined) throw new Error("missing tree");
    Object.assign(tree, { utxoRoot: new Uint8Array(31) });
    expect(() => resolvedPublicInputHash(input.fields, input.trees)).toThrow();
    Object.assign(tree, {
      utxoRoot: Object.defineProperty(new Uint8Array(31), "length", { value: 32 }),
    });
    expect(() => resolvedPublicInputHash(input.fields, input.trees)).toThrow();
    const valid = statement();
    expect(() => resolvedPublicInputHash(valid.fields, valid.trees.slice(1))).toThrow();
    expect(resolvedPublicInputHash(valid.fields, valid.trees)).toBe(expected);
  });

  it("hashes the captured roots when caller getters change", () => {
    const input = statement();
    const expected = resolvedPublicInputHash(input.fields, input.trees);
    resolvedPublicInputHash([999n], input.trees);
    const first = input.trees[0];
    if (first === undefined) throw new Error("missing tree");
    let reads = 0;
    input.trees[0] = {
      ...first,
      get utxoRoot() {
        return checkedBytes(bigintToBytes(reads++ === 0 ? 11n : 19n), 32, "root");
      },
    };
    expect(resolvedPublicInputHash(input.fields, input.trees)).toBe(expected);
    expect(resolvedPublicInputHash(statement().fields, statement().trees)).toBe(expected);
    expect(reads).toBe(1);
  });
});
