/**
 * Fixed layout parameters of the merge instruction data, mirroring
 * `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`.
 * Kept in a leaf module so the codecs can enforce them without importing the
 * package root, which imports the codecs.
 */

/** Input slots a merge proof spends. The shape is fixed at 8-in/1-out. */
export const MERGE_INPUT_COUNT = 8;

export const MERGE_SUPPORTED_INPUT_COUNTS: readonly number[] = Object.freeze([
  MERGE_INPUT_COUNT,
  36,
]);

export const RING_SPEND_COUNTERS_SLOT_INDEX = 0xffff_ffff;
