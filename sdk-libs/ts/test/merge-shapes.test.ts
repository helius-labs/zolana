import { describe, expect, it } from "vitest";

import {
  MAX_MERGE_INPUTS,
  MERGE_DEFAULT_INPUT_COUNT,
  MERGE_SUPPORTED_INPUT_COUNTS,
  isSupportedMergeInputCount,
  mergePaddedInputCount,
} from "../src/interface/constants.js";
import { encodeMergeTransactInstructionData } from "../src/interface/codecs/index.js";
import type { Bytes32, Bytes64 } from "../src/interface/types.js";

const zeros32 = () => new Uint8Array(32) as Bytes32;
const zeros64 = () => new Uint8Array(64) as Bytes64;

function mergeData(inputCount: number) {
  return {
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    proof: { a: zeros32(), b: zeros64(), c: zeros32() },
    outputUtxoHash: zeros32(),
    eddsaOwner: false,
    privateTxHash: zeros32(),
    nullifiers: Array.from({ length: inputCount }, zeros32),
    utxoTreeRootIndexes: Array.from({ length: inputCount }, () => 0),
    nullifierTreeRootIndexes: Array.from({ length: inputCount }, () => 0),
  };
}

describe("merge shapes", () => {
  it("keeps the supported set consistent", () => {
    expect(MERGE_SUPPORTED_INPUT_COUNTS).toContain(MERGE_DEFAULT_INPUT_COUNT);
    expect(Math.max(...MERGE_SUPPORTED_INPUT_COUNTS)).toBe(MAX_MERGE_INPUTS);
    expect(Math.min(...MERGE_SUPPORTED_INPUT_COUNTS)).toBe(MERGE_DEFAULT_INPUT_COUNT);
  });

  it("pads to the smallest shape that fits", () => {
    expect(mergePaddedInputCount(2)).toBe(8);
    expect(mergePaddedInputCount(8)).toBe(8);
    expect(mergePaddedInputCount(9)).toBe(36);
    expect(mergePaddedInputCount(36)).toBe(36);
    expect(mergePaddedInputCount(37)).toBeUndefined();
  });

  it("accepts a count only when a circuit exists for it", () => {
    for (const count of MERGE_SUPPORTED_INPUT_COUNTS) {
      expect(isSupportedMergeInputCount(count)).toBe(true);
    }
    for (const count of [0, 1, 7, 9, 35, 37]) {
      expect(isSupportedMergeInputCount(count)).toBe(false);
    }
  });

  it("encodes every supported shape at 204 + 36 per input", () => {
    for (const count of MERGE_SUPPORTED_INPUT_COUNTS) {
      expect(encodeMergeTransactInstructionData(mergeData(count))).toHaveLength(204 + 36 * count);
    }
  });

  it("refuses a shape no circuit covers", () => {
    expect(() => encodeMergeTransactInstructionData(mergeData(9))).toThrow();
  });

  it("refuses vectors that disagree on the input count", () => {
    const data = mergeData(8);
    expect(() =>
      encodeMergeTransactInstructionData({
        ...data,
        utxoTreeRootIndexes: data.utxoTreeRootIndexes.slice(1),
      }),
    ).toThrow();
  });
});
