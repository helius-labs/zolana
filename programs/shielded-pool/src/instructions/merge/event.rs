use pinocchio::error::ProgramError;
use zolana_interface::{
    error::ShieldedPoolError,
    event::{Input, InputTreeSequence, MergeEvent},
};

/// Sequence numbers and leaf index assigned while writing the tree, mirrored into
/// the emitted event so an indexer can reconstruct the 8 nullifier insertions and
/// the single output append.
pub struct MergeTreeWrite {
    pub inputs: Vec<Input>,
    pub output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Build the emitted [`MergeEvent`]. The merged output is owner-indexed like every
/// confidential output: `output_view_tag` is the owner signing pubkey, so
/// `Wallet::sync` rediscovers it via the confidential owner-pubkey scan. The
/// output commitment, the nullifiers and a `merge_ring` output `ring_data_hash`
/// are not repeated; the indexer reads them from the instruction data.
pub fn build_merge_event(
    tree_write: MergeTreeWrite,
    output_view_tag: [u8; 32],
) -> Result<MergeEvent, ProgramError> {
    let first_input = tree_write
        .inputs
        .first()
        .ok_or(ShieldedPoolError::InvalidMergeShape)?;
    Ok(MergeEvent {
        input_trees: vec![InputTreeSequence {
            tree: first_input.tree,
            first_input_queue_seq: first_input.input_queue_seq,
        }],
        output_tree: tree_write.output_tree,
        output_leaf_index: tree_write.output_leaf_index,
        output_view_tag,
    })
}
