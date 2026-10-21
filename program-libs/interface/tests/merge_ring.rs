use zolana_interface::instruction::{
    instruction_data::{
        merge_ring::{MergeRingIxData, MergeRingIxDataRef, MergeRingPrefix},
        merge_transact::{
            MergeOutputEncryption, MergeProof, MergeTransactIxData, MAX_MERGE_INPUTS,
            MERGE_DEFAULT_INPUT_COUNT,
        },
    },
    tag::RING_MERGE_TRANSACT,
};

fn data() -> MergeRingIxData {
    MergeRingIxData {
        output_ring_data_hash: [8u8; 32],
        member_registry_root: [9u8; 32],
        anonymous: false,
        merge: MergeTransactIxData {
            cache_slot: None,
            expiry_unix_ts: 42,
            proof: MergeProof {
                a: [1u8; 32],
                b: [2u8; 128],
                c: [3u8; 32],
            },
            output_utxo_hash: [1u8; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: [5u8; 16],
                ciphertext: [[6u8; 32], [7u8; 32], [8u8; 32]],
            },
            nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT as u8)
                .map(|i| [i; 32])
                .collect(),
            utxo_tree_root_index: 4,
            nullifier_tree_root_index: 10,
            private_tx_hash: [3u8; 32],
        },
    }
}

#[test]
fn rejects_empty_and_oversized_nullifier_lists() {
    for count in [0, MAX_MERGE_INPUTS + 1] {
        let mut owned = data();
        owned.merge.nullifiers = vec![[1u8; 32]; count];
        let bytes = owned.serialize().unwrap();
        assert!(
            MergeRingIxDataRef::from_bytes(&bytes).is_err(),
            "{count} nullifiers"
        );
    }
}

#[test]
fn the_prefix_writer_lays_out_the_tagged_merge_ring_data() {
    let data = MergeRingIxData {
        anonymous: true,
        ..data()
    };
    let merge = data.merge.serialize().unwrap();
    let written = MergeRingPrefix {
        output_ring_data_hash: &data.output_ring_data_hash,
        member_registry_root: &data.member_registry_root,
        anonymous: data.anonymous,
    }
    .instruction_data(&merge);
    let (tag, body) = written.split_first().unwrap();
    assert_eq!(*tag, RING_MERGE_TRANSACT);
    assert_eq!(body, data.serialize().unwrap());
    assert_eq!(body.len(), MergeRingPrefix::LEN + merge.len());
    assert_eq!(written.capacity(), written.len());
    assert_eq!(
        MergeRingIxDataRef::from_bytes(body).unwrap().anonymous,
        data.anonymous
    );
}
