/**
 * Fixed layout parameters of the merge instruction data, mirroring
 * `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`.
 * Kept in a leaf module so the codecs can enforce them without importing the
 * package root, which imports the codecs.
 */

/** Input slots of the narrower merge proof, the width an automatic merge sweeps. */
export const MERGE_INPUT_COUNT = 8;

export const MAX_MERGE_INPUTS = 36;

export const MERGE_SUPPORTED_INPUT_COUNTS: readonly number[] = Object.freeze([
  MERGE_INPUT_COUNT,
  MAX_MERGE_INPUTS,
]);

/** The narrowest merge proof holding `realInputs`, undefined above `MAX_MERGE_INPUTS`. */
export function mergePaddedInputCount(realInputs: number): number | undefined {
  return MERGE_SUPPORTED_INPUT_COUNTS.find((count) => count >= realInputs);
}

export const RING_SPEND_COUNTERS_SLOT_INDEX = 0xffff_ffff;
