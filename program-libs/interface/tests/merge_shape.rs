use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeProof, MergeTransactIxData, MergeTransactIxDataRef, MAX_MERGE_INPUTS,
    MERGE_DEFAULT_INPUT_COUNT, MERGE_SUPPORTED_INPUT_COUNTS,
};

fn data_with(input_count: usize) -> MergeTransactIxData {
    MergeTransactIxData {
        expiry_unix_ts: 42,
        proof: MergeProof {
            a: [1u8; 32],
            b: [2u8; 64],
            c: [3u8; 32],
        },
        output_utxo_hash: [9u8; 32],
        nullifiers: (0..input_count).map(|i| [i as u8; 32]).collect(),
        utxo_tree_root_index: (0..input_count as u16).collect(),
        nullifier_tree_root_index: (10..10 + input_count as u16).collect(),
        private_tx_hash: [3u8; 32],
        eddsa_owner: false,
    }
}

#[test]
fn every_supported_shape_has_the_contracted_encoded_length() {
    for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
        let bytes = data_with(input_count)
            .serialize()
            .expect("serialize merge instruction");
        assert_eq!(bytes.len(), 204 + 36 * input_count);
        MergeTransactIxDataRef::from_bytes(&bytes).expect("a supported shape must parse back");
    }
}

#[test]
fn max_merge_inputs_is_the_widest_supported_shape() {
    assert_eq!(
        MERGE_SUPPORTED_INPUT_COUNTS.iter().copied().max(),
        Some(MAX_MERGE_INPUTS)
    );
    assert!(MERGE_SUPPORTED_INPUT_COUNTS.contains(&MERGE_DEFAULT_INPUT_COUNT));
}

#[test]
fn rejects_unsupported_input_counts() {
    for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
        let mut owned = data_with(input_count);
        owned.nullifiers.pop();
        owned.utxo_tree_root_index.pop();
        owned.nullifier_tree_root_index.pop();
        let bytes = owned.serialize().expect("serialize merge instruction");
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
    }
}
