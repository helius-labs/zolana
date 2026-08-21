//! `encode_output_data` writes the plaintext body once instead of serializing it
//! into a `Vec` and copying that `Vec` into the enum payload. These tests pin the
//! result to the derived-borsh encoding it replaces, so the optimization cannot
//! change the bytes an indexer or wallet parses.

use borsh::BorshSerialize;
use zolana_event::{
    decode_output_data, encode_output_data, is_confidential_encrypted_output,
    ring_confidential_encrypted_output_body, OutputDataEncoding, ProoflessOutput,
    CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, PLAINTEXT_OUTPUT_FIXED_LEN,
    RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};

/// The encoding `encode_output_data` replaced: serialize the scheme byte plus the
/// output into one `Vec`, then let derived borsh wrap that `Vec` in the enum.
fn reference_encoding(data: &ProoflessOutput) -> Vec<u8> {
    let mut blob = vec![0u8];
    data.serialize(&mut blob).expect("serialize output");
    borsh::to_vec(&OutputDataEncoding::Plaintext(blob)).expect("serialize enum")
}

#[test]
fn encoding_matches_derived_borsh_for_every_option_shape() {
    for data in [
        minimal(),
        every_option_present(),
        every_option_present_but_empty(),
    ] {
        assert_eq!(
            encode_output_data(data.clone()),
            reference_encoding(&data),
            "single-write encoding must match the derived-borsh encoding"
        );
    }
}

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

/// `PLAINTEXT_OUTPUT_FIXED_LEN` is the capacity reserved before the variable
/// contents, so it must cover the widest fixed encoding: every option present
/// with empty vectors. A new `ProoflessOutput` field breaks this.
#[test]
fn plaintext_fixed_len_covers_every_option() {
    assert_eq!(
        encode_output_data(every_option_present_but_empty()).len(),
        PLAINTEXT_OUTPUT_FIXED_LEN
    );
}

#[test]
fn variable_contents_extend_the_fixed_length() {
    let data = every_option_present();
    let variable = data.utxo_data.as_ref().map_or(0, Vec::len)
        + data.ring_data.as_ref().map_or(0, Vec::len)
        + data.memo.as_ref().map_or(0, Vec::len);
    assert_eq!(
        encode_output_data(data).len(),
        PLAINTEXT_OUTPUT_FIXED_LEN + variable
    );
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

/// The `VerifiablyEncrypted` variant is reserved for upcoming auditor
/// encryption flows (custom rings with auditor): pin its wire shape so the
/// reservation cannot rot while it has no producer.
#[test]
fn verifiably_encrypted_round_trips_with_tag_byte_two() {
    use borsh::BorshDeserialize;
    use zolana_event::encode_verifiably_encrypted;

    let blob = vec![1u8, 2, 3, 4, 5];
    let encoded = encode_verifiably_encrypted(blob.clone());
    assert_eq!(
        encoded.first(),
        Some(&OutputDataEncoding::VERIFIABLY_ENCRYPTED_TAG)
    );
    match OutputDataEncoding::try_from_slice(&encoded).expect("decode tag 2") {
        OutputDataEncoding::VerifiablyEncrypted(out) => assert_eq!(out, blob),
        other => panic!("expected VerifiablyEncrypted, got {other:?}"),
    }
}
