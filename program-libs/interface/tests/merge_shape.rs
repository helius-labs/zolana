use zolana_interface::instruction::instruction_data::merge_transact::{
    MergeProof, MergeTransactIxData, MergeTransactIxDataRef, MAX_MERGE_INPUTS,
    MERGE_DEFAULT_INPUT_COUNT, MERGE_SUPPORTED_INPUT_COUNTS,
};

fn data_with(input_count: usize) -> MergeTransactIxData {
    MergeTransactIxData {
        cache_slot: None,
        expiry_unix_ts: 42,
        proof: MergeProof {
            a: [1u8; 32],
            b: [2u8; 128],
            c: [3u8; 32],
        },
        output_utxo_hash: [9u8; 32],
        nullifiers: (0..input_count).map(|i| [i as u8; 32]).collect(),
        utxo_tree_root_index: 4,
        nullifier_tree_root_index: 10,
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
        assert_eq!(bytes.len(), 271 + 32 * input_count);
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
        let bytes = owned.serialize().expect("serialize merge instruction");
        assert!(MergeTransactIxDataRef::from_bytes(&bytes).is_err());
    }
}

#[test]
fn cache_slot_round_trips_in_both_merge_rails() {
    use zolana_interface::instruction::{
        instruction_data::merge_ring::MergeRingIxDataRef, MergeRingIxData,
    };
    for cache_slot in [None, Some(0), Some(35)] {
        let mut data = data_with(8);
        data.cache_slot = cache_slot;
        let bytes = data.serialize().unwrap();
        assert_eq!(bytes.len(), 527 + usize::from(cache_slot.is_some()));
        assert_eq!(MergeTransactIxData::deserialize(&bytes).unwrap(), data);
        assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes)
                .unwrap()
                .cache_slot,
            cache_slot
        );
        let ring = MergeRingIxData {
            output_ring_data_hash: [7; 32],
            merge: data,
        };
        let bytes = ring.serialize().unwrap();
        assert_eq!(MergeRingIxData::deserialize(&bytes).unwrap(), ring);
        assert_eq!(
            MergeRingIxDataRef::from_bytes(&bytes)
                .unwrap()
                .merge
                .cache_slot,
            cache_slot
        );
    }
}

#[test]
fn cache_mode_address_and_slot_are_bound_by_both_merge_hashes() {
    use zolana_interface::instruction::{tag, MergeExternalDataHash};
    let address = [8; 32];
    let other_address = [9; 32];
    let mut hashes = Vec::new();
    for tag in [tag::MERGE_TRANSACT, tag::RING_MERGE_TRANSACT] {
        for cache in [
            None,
            Some((&address, 0)),
            Some((&address, 1)),
            Some((&other_address, 0)),
        ] {
            let hash = MergeExternalDataHash {
                spp_instruction_discriminator: tag,
                expiry_unix_ts: 42,
                output_utxo_hash: &[7; 32],
                cache,
            }
            .hash()
            .unwrap();
            assert!(!hashes.contains(&hash));
            hashes.push(hash);
        }
    }
}

#[test]
fn plain_merge_matches_the_shared_encoding_vector() {
    use zolana_hasher::{sha256::Sha256, Hasher};
    use zolana_interface::instruction::{tag, MergeExternalDataHash};
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../test-vectors/merge_encoding.json")).unwrap();
    let data = data_with(8);
    let hex = |bytes: [u8; 32]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(Sha256::hash(&data.serialize().unwrap()).unwrap()),
        vector["instruction_sha256"]
    );
    let hash = MergeExternalDataHash {
        spp_instruction_discriminator: tag::MERGE_TRANSACT,
        expiry_unix_ts: data.expiry_unix_ts,
        output_utxo_hash: &data.output_utxo_hash,
        cache: None,
    }
    .hash()
    .unwrap();
    assert_eq!(hex(hash), vector["external_data_hash"]);
}
