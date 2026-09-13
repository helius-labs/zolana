use zolana_interface::event::{InputTreeSequence, MergeEvent};

/// Values assigned while writing the tree. The event contains the first input's
/// tree and queue sequence number plus the output leaf index; an indexer counts
/// the remaining insertions up from that sequence.
pub struct MergeTreeWrite {
    pub input_tree: InputTreeSequence,
    pub output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

/// Build the emitted [`MergeEvent`]. The merged output is owner-indexed like every
/// confidential output: `output_view_tag` is the owner signing pubkey, so
/// `Wallet::sync` rediscovers it via the confidential owner-pubkey scan. The
/// output commitment, the nullifiers and a `merge_ring` output `ring_data_hash`
/// are not repeated; the indexer reads them from the instruction data.
pub fn build_merge_event(tree_write: MergeTreeWrite, output_view_tag: [u8; 32]) -> MergeEvent {
    MergeEvent {
        input_trees: vec![tree_write.input_tree],
        output_tree: tree_write.output_tree,
        output_leaf_index: tree_write.output_leaf_index,
        output_view_tag,
    }
}
