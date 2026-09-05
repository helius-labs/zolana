use borsh::{BorshDeserialize, BorshSerialize};

/// A cascade of `num_update` nullifier-tree zkp batch updates applied in one
/// instruction. `new_root` is the final root; the intermediate roots live in
/// the tree's `root_history` at indices `first_root_index .. first_root_index +
/// num_update` (mod `root_history_capacity`). The per-batch values for the
/// `i`-th applied batch (`0 <= i < num_update`) are:
/// - `old_next_index`  = `old_next_index + i * zkp_batch_size`
/// - `new_next_index`  = `old_next_index + (i + 1) * zkp_batch_size`
/// - `sequence_number` = `start_sequence_number + i`
/// - `root_index`      = `(first_root_index + i) % root_history_capacity`
///
/// An indexer must reconstruct all `num_update * zkp_batch_size` appended
/// values before comparing against `new_root`: only the final root is reported,
/// so checking after a single batch mismatches whenever a cascade occurs.
#[repr(C)]
#[derive(BorshDeserialize, BorshSerialize, Debug, PartialEq, Clone, Eq)]
pub struct NullifierTreeUpdateEvent {
    pub merkle_tree_pubkey: [u8; 32],
    pub zkp_batch_size: u16,
    pub old_next_index: u64,
    pub start_sequence_number: u64,
    pub first_root_index: u32,
    pub num_update: u32,
    pub first_zkp_batch_index: u32,
    pub new_root: [u8; 32],
}
