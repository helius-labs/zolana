/**
 * Fixed layout parameters of the merge instruction data, mirroring
 * `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`.
 * Kept in a leaf module so the codecs can enforce them without importing the
 * package root, which imports the codecs.
 */
/** Input slots a merge proof spends. The shape is fixed at 8-in/1-out. */
export declare const MERGE_INPUT_COUNT = 8;
