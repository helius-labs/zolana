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
) -> GeneralEvent {
    let mut tx_viewing_pk = [0u8; 33];
    if let Ok(blob_pk) = ix.tx_viewing_pk() {
        tx_viewing_pk.copy_from_slice(blob_pk);
    }

    // The merged output is owner-indexed like every confidential output: the view
    // tag is the owner signing pubkey, so `Wallet::sync` rediscovers it via the
    // confidential owner-pubkey scan.
    let outputs = vec![OutputUtxo {
        view_tag: output_view_tag,
        utxo_hash: *ix.output_utxo_hash,
        data: ix.encrypted_utxo.to_vec(),
    }];

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        tx_viewing_pk,
        salt: [0u8; 16], // TODO: send salt in instruction data
        first_output_leaf_index: tree_write.output_leaf_index,
        output_tree: tree_write.output_tree,
        relay_fee: None,
        deposit_withdraw: None,
    }
}
