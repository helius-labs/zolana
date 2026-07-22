use zolana_interface::{
    event::{GeneralEvent, Input},
    instruction::{instruction_data::merge_transact::MergeTransactIxDataRef, OutputUtxo},
};

/// Sequence numbers and leaf index assigned while writing the tree, mirrored into
/// the emitted event so an indexer can reconstruct the 8 nullifier insertions and
/// the single output append.
pub struct MergeTreeWrite {
    pub inputs: Vec<Input>,
    pub output_leaf_index: u64,
    pub output_tree: [u8; 32],
}

pub fn build_merge_event(
    ix: &MergeTransactIxDataRef<'_>,
    tree_write: MergeTreeWrite,
    output_view_tag: [u8; 32],
    output_data: Vec<u8>,
) -> GeneralEvent {
    // The merged output is owner-indexed like every confidential output: the view
    // tag is the owner signing pubkey, so `Wallet::sync` rediscovers it via the
    // confidential owner-pubkey scan. It carries no ciphertext: the wallet
    // reconstructs it from `merge_view_tag` and its spent inputs. `merge_zone`
    // additionally publishes the output `zone_data_hash` in the output data.
    let outputs = vec![OutputUtxo {
        view_tag: output_view_tag,
        utxo_hash: *ix.output_utxo_hash,
        data: output_data,
    }];

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        messages: Vec::new(),
        tx_viewing_pk: [0u8; 33],
        salt: [0u8; 16],
        first_output_leaf_index: tree_write.output_leaf_index,
        output_tree: tree_write.output_tree,
        movements: Vec::new(),
        merge_view_tag: Some(*ix.merge_view_tag),
    }
}
