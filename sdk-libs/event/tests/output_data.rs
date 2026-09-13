//! Output payload encoding and the scheme markers an indexer dispatches on.

use zolana_event::{
    encode_output_data, is_confidential_encrypted_output, ring_confidential_encrypted_output_body,
    OutputDataEncoding, ProoflessOutput, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};
use zolana_event_parser::decode_output_data;

#[test]
fn encoded_output_decodes_back() {
    for data in [
        minimal(),
        every_option_present(),
        every_option_present_but_empty(),
    ] {
        let encoded = encode_output_data(data.clone());
        assert_eq!(decode_output_data(&encoded).expect("decode"), data);
    }
}

#[test]
fn confidential_marker_requires_encrypted_encoding_and_exact_body_length() {
    let marked = borsh::to_vec(&OutputDataEncoding::Encrypted(vec![
        CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        9,
    ]))
    .unwrap();
    assert!(is_confidential_encrypted_output(&marked));

    let wrong_scheme = borsh::to_vec(&OutputDataEncoding::Encrypted(vec![2, 9])).unwrap();
    assert!(!is_confidential_encrypted_output(&wrong_scheme));
    let plaintext = borsh::to_vec(&OutputDataEncoding::Plaintext(vec![
        CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    ]))
    .unwrap();
    assert!(!is_confidential_encrypted_output(&plaintext));

    let mut malformed = marked;
    malformed[1] = malformed[1].saturating_add(1);
    assert!(!is_confidential_encrypted_output(&malformed));
    assert!(!is_confidential_encrypted_output(&[]));
}

#[test]
fn ring_confidential_marker_has_a_distinct_owner_policy() {
    let marked = borsh::to_vec(&OutputDataEncoding::Encrypted(vec![
        RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
        9,
    ]))
    .unwrap();
    assert_eq!(
        ring_confidential_encrypted_output_body(&marked),
        Some(&[9][..])
    );
    assert!(!is_confidential_encrypted_output(&marked));
}

fn minimal() -> ProoflessOutput {
    ProoflessOutput {
        owner: [1u8; 32],
        blinding: [2u8; 32],
        asset: [0u8; 32],
        amount: 1_000,
        data_hash: None,
        utxo_data: None,
        ring_program_id: None,
        ring_data_hash: None,
        ring_data: None,
        memo: None,
    }
}

fn every_option_present() -> ProoflessOutput {
    ProoflessOutput {
        owner: [3u8; 32],
        blinding: [4u8; 32],
        asset: [5u8; 32],
        amount: u64::MAX,
        data_hash: Some([6u8; 32]),
        utxo_data: Some(vec![7u8; 200]),
        ring_program_id: Some([8u8; 32]),
        ring_data_hash: Some([9u8; 32]),
        ring_data: Some(vec![10u8; 64]),
        memo: Some(b"batched deposit".to_vec()),
    }
}

fn every_option_present_but_empty() -> ProoflessOutput {
    ProoflessOutput {
        data_hash: Some([11u8; 32]),
        utxo_data: Some(Vec::new()),
        ring_program_id: Some([12u8; 32]),
        ring_data_hash: Some([13u8; 32]),
        ring_data: Some(Vec::new()),
        memo: Some(Vec::new()),
        ..minimal()
    }
}

/// The single-buffer encoder writes the tag, the `u32` body length, the scheme
/// byte and the body in place; it must produce exactly the bytes borsh gives
/// for the equivalent `OutputDataEncoding` value.
#[test]
fn single_buffer_encoding_matches_the_borsh_enum_layout() {
    for output in [
        minimal(),
        every_option_present(),
        every_option_present_but_empty(),
    ] {
        let mut blob = vec![0u8];
        borsh::BorshSerialize::serialize(&output, &mut blob).unwrap();
        let expected = borsh::to_vec(&OutputDataEncoding::Plaintext(blob)).unwrap();
        assert_eq!(encode_output_data(output), expected);
    }

    let encrypted = zolana_event::EncryptedRingDepositOutput {
        owner_utxo_hash: [1u8; 32],
        asset: [2u8; 32],
        amount: 7,
        data_hash: Some([3u8; 32]),
        ring_program_id: [4u8; 32],
        ring_data_hash: [5u8; 32],
        encrypted: zolana_event::EncryptedRingDepositData {
            tx_viewing_pk: [6u8; 33],
            salt: [7u8; 16],
            ciphertext: vec![8u8; 40],
        },
    };
    let mut blob = vec![zolana_event::ENCRYPTED_RING_DEPOSIT_SCHEME];
    borsh::BorshSerialize::serialize(&encrypted, &mut blob).unwrap();
    let expected = borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap();
    assert_eq!(
        zolana_event::encode_encrypted_ring_deposit_output(encrypted),
        expected
    );
}

#[test]
fn fixed_lengths_match_the_encoders() {
    assert_eq!(
        encode_output_data(every_option_present_but_empty()).len(),
        zolana_event::PLAINTEXT_OUTPUT_FIXED_LEN
    );
    let encrypted = zolana_event::EncryptedRingDepositOutput {
        owner_utxo_hash: [1u8; 32],
        asset: [2u8; 32],
        amount: 7,
        data_hash: Some([3u8; 32]),
        ring_program_id: [4u8; 32],
        ring_data_hash: [5u8; 32],
        encrypted: zolana_event::EncryptedRingDepositData {
            tx_viewing_pk: [6u8; 33],
            salt: [7u8; 16],
            ciphertext: Vec::new(),
        },
    };
    assert_eq!(
        zolana_event::encode_encrypted_ring_deposit_output(encrypted).len(),
        zolana_event::ENCRYPTED_RING_DEPOSIT_OUTPUT_FIXED_LEN
    );
}
