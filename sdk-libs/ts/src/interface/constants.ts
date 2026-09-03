/**
 * Fixed layout parameters of the merge instruction data, mirroring
 * `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`.
 * Kept in a leaf module so the codecs can enforce them without importing the
 * package root, which imports the codecs.
 */

/**
 * Input counts the merge circuits have verifying keys for, smallest first.
 *
 * Merge instruction data carries no circuit selector: the shape is the declared
 * nullifier count, so the program picks its verifying key from this set and a
 * count outside it has no key at all. Mirror `MERGE_SUPPORTED_INPUT_COUNTS` in
 * the interface crate and `SupportedInputCounts` in
 * `prover/server/circuits/spp_merge/shared/transaction.go`.
 */
export const MERGE_SUPPORTED_INPUT_COUNTS: readonly number[] = [8, 36];

/**
 * Smallest supported merge shape, and the one a routine consolidation pads up
 * to. The wide shape costs proportionally more to prove, so an automatic dust
 * sweep must not land in it.
 */
export const MERGE_DEFAULT_INPUT_COUNT = 8;

/** Largest supported merge shape. */
export const MAX_MERGE_INPUTS = 36;

/** Whether a merge circuit exists for `count` inputs. */
export function isSupportedMergeInputCount(count: number): boolean {
  return MERGE_SUPPORTED_INPUT_COUNTS.includes(count);
}

/**
 * The shape a merge of `realInputs` real UTXOs is padded to: the smallest
 * supported count that fits, or `undefined` when none is wide enough.
 */
export function mergePaddedInputCount(realInputs: number): number | undefined {
  let best: number | undefined;
  for (const supported of MERGE_SUPPORTED_INPUT_COUNTS) {
    if (supported >= realInputs && (best === undefined || supported < best)) {
      best = supported;
    }
  }
  return best;
}
