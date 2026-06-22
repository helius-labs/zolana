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
    owner_tag: [u8; 32],
) -> GeneralEvent {
    let mut tx_viewing_pk = [0u8; 33];
    if let Ok(blob_pk) = ix.tx_viewing_pk() {
        tx_viewing_pk.copy_from_slice(blob_pk);
    }

    let outputs = vec![OutputUtxo {
        view_tag: owner_tag,
        utxo_hash: *ix.output_utxo_hash,
        data: ix.encrypted_utxo.to_vec(),
    }];

    GeneralEvent {
        inputs: tree_write.inputs,
        outputs,
        tx_viewing_pk,
        salt: [0u8; 16],
        first_output_leaf_index: tree_write.output_leaf_index,
        output_tree: tree_write.output_tree,
        relay_fee: None,
        deposit_withdraw: None,
    }
}

#[cfg(test)]
mod tests {
    use zolana_interface::instruction::instruction_data::merge_transact::{
        MergeTransactIxData, MergeTransactIxDataRef, MERGE_ENCRYPTED_UTXO_LEN, MERGE_INPUT_COUNT,
    };

    use super::*;

    #[test]
    fn merge_event_tags_output_with_registry_owner() {
        let mut encrypted_utxo = vec![0u8; MERGE_ENCRYPTED_UTXO_LEN];
        encrypted_utxo[0] = 3;
        encrypted_utxo[1..34].copy_from_slice(&[7u8; 33]);
        encrypted_utxo[34..].copy_from_slice(&[8u8; MERGE_ENCRYPTED_UTXO_LEN - 34]);
        let data = MergeTransactIxData {
            expiry_unix_ts: 42,
            proof: [1u8; 192],
            output_utxo_hash: [2u8; 32],
            nullifiers: vec![[3u8; 32]; MERGE_INPUT_COUNT],
            utxo_tree_root_index: vec![4u16; MERGE_INPUT_COUNT],
            nullifier_tree_root_index: vec![5u16; MERGE_INPUT_COUNT],
            private_tx_hash: [6u8; 32],
            encrypted_utxo,
            eddsa_owner: true,
        };
        let bytes = data.serialize().expect("serialize merge ix data");
        let ix = MergeTransactIxDataRef::from_bytes(&bytes).expect("parse merge ix data");
        let owner_tag = [9u8; 32];
        let tree_write = MergeTreeWrite {
            inputs: vec![Input {
                tree: [10u8; 32],
                input_queue_seq: 11,
                nullifier: [12u8; 32],
            }],
            output_leaf_index: 13,
            output_tree: [14u8; 32],
        };

        let event = build_merge_event(&ix, tree_write, owner_tag);

        assert_eq!(event.outputs.len(), 1);
        assert_eq!(event.outputs[0].view_tag, owner_tag);
        assert_eq!(event.outputs[0].utxo_hash, data.output_utxo_hash);
        assert_eq!(event.outputs[0].data, data.encrypted_utxo);
        assert_eq!(event.tx_viewing_pk, [7u8; 33]);
        assert_eq!(event.first_output_leaf_index, 13);
        assert_eq!(event.output_tree, [14u8; 32]);
        assert_eq!(event.inputs.len(), 1);
    }
}
