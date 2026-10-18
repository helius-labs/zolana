use zolana_interface::instruction::{
    instruction_data::merge_transact::{
        MergeExternalDataHash, MergeOutputEncryption, MergeProof, MergeTransactIxData,
        MergeTransactIxDataRef, MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT,
        MERGE_OUTPUT_CIPHERTEXT_SALT_LEN,
    },
    tag,
};

fn data() -> MergeTransactIxData {
    MergeTransactIxData {
        cache_slot: None,
        expiry_unix_ts: 42,
        proof: MergeProof {
            a: [1u8; 32],
            b: [2u8; 128],
            c: [3u8; 32],
        },
        output_utxo_hash: [9u8; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [5u8; MERGE_OUTPUT_CIPHERTEXT_SALT_LEN],
            ciphertext: [[6u8; 32], [7u8; 32], [8u8; 32]],
        },
        nullifiers: (0..MERGE_DEFAULT_INPUT_COUNT as u8)
            .map(|i| [i; 32])
            .collect(),
        utxo_tree_root_index: 4,
        nullifier_tree_root_index: 10,
        private_tx_hash: [3u8; 32],
        eddsa_owner: false,
    }
}

#[test]
fn fixed_shape_wire_length_matches_the_protocol_contract() {
    let bytes = data().serialize().expect("serialize merge instruction");

    assert_eq!(bytes.len(), 384 + 32 * MERGE_DEFAULT_INPUT_COUNT);
}

#[test]
fn rejects_empty_and_oversized_nullifier_lists() {
    for count in [0, MAX_MERGE_INPUTS + 1] {
        let mut owned = data();
        owned.nullifiers = vec![[1u8; 32]; count];
        let bytes = owned.serialize().unwrap();
        assert!(
            MergeTransactIxDataRef::from_bytes(&bytes).is_err(),
            "{count} nullifiers"
        );
    }
}

fn hash_of(discriminator: u8, expiry: u64, output: &[u8; 32]) -> [u8; 32] {
    MergeExternalDataHash {
        cache: None,
        spp_instruction_discriminator: discriminator,
        expiry_unix_ts: expiry,
        output_utxo_hash: output,
    }
    .hash()
    .unwrap()
}

#[test]
fn external_data_hash_is_injective() {
    let base = hash_of(tag::MERGE_TRANSACT, 1, &[1u8; 32]);
    assert_ne!(base, hash_of(tag::MERGE_TRANSACT, 2, &[1u8; 32]));
    assert_ne!(base, hash_of(tag::MERGE_TRANSACT, 1, &[2u8; 32]));
    assert_ne!(base, hash_of(tag::RING_MERGE_TRANSACT, 1, &[1u8; 32]));
}
