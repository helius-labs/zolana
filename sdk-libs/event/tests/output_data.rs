//! Output payload encoding and the scheme markers an indexer dispatches on.

use zolana_event::{
    encode_confidential_output, encode_merge_output_data, encode_output_data,
    encode_ring_anonymous_output, encode_ring_confidential_delivered_output,
    encode_ring_confidential_packed_output, is_confidential_encrypted_output,
    merge_output::MERGE_OUTPUT_SALT_LEN, ring_anonymous_encrypted_output_body,
    ring_confidential_delivered_output_body, ring_confidential_encrypted_output_body,
    ring_confidential_packed_output_body, MergeOutputDataRef, OutputDataEncoding, ProoflessOutput,
    RingPackedBody, CONFIDENTIAL_DATA_FREE_BODY_LEN, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    MERGE_OUTPUT_SCHEME, RECIPIENT_KEY_LEN, RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG,
    RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG, RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
    RING_CONFIDENTIAL_PACKED_SCHEME_TAG, RING_DELIVERED_BODY_LEN, RING_PACKED_DATA_FREE_BODY_LEN,
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

#[test]
fn ring_confidential_delivered_output_carries_one_fixed_body() {
    let body = [9u8; RING_DELIVERED_BODY_LEN];
    let encoded = encode_ring_confidential_delivered_output(&body);
    let mut expected = vec![OutputDataEncoding::ENCRYPTED_TAG, 41, 0, 0, 0, 0x0a];
    expected.extend_from_slice(&body);
    assert_eq!(encoded, expected);
    assert_eq!(
        ring_confidential_delivered_output_body(&encoded),
        Some(&body)
    );
    assert!(!is_confidential_encrypted_output(&encoded));
    assert_eq!(ring_confidential_encrypted_output_body(&encoded), None);
    assert_eq!(ring_anonymous_encrypted_output_body(&encoded), None);

    assert_eq!(
        encrypted(
            RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG,
            RING_DELIVERED_BODY_LEN
        ),
        encoded
    );
    for refused in [
        encrypted(
            RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG,
            RING_DELIVERED_BODY_LEN - 1,
        ),
        encrypted(
            RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG,
            RING_DELIVERED_BODY_LEN + 1,
        ),
        encrypted(RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG, RING_DELIVERED_BODY_LEN),
    ] {
        assert_eq!(ring_confidential_delivered_output_body(&refused), None);
    }
}

#[test]
fn ring_confidential_packed_output_is_never_shorter_than_a_data_free_body() {
    let key = [9u8; RECIPIENT_KEY_LEN];
    let ciphertext = [9u8; RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN];
    let encoded = encode_ring_confidential_packed_output(&key, &ciphertext);
    let mut expected = vec![OutputDataEncoding::ENCRYPTED_TAG, 83, 0, 0, 0, 0x0b];
    expected.extend_from_slice(&key);
    expected.extend_from_slice(&ciphertext);
    assert_eq!(encoded, expected);
    assert_eq!(
        ring_confidential_packed_output_body(&encoded),
        Some(RingPackedBody {
            key: &key,
            ciphertext: &ciphertext,
        })
    );
    assert!(!is_confidential_encrypted_output(&encoded));
    assert_eq!(ring_confidential_encrypted_output_body(&encoded), None);
    assert_eq!(ring_confidential_delivered_output_body(&encoded), None);
    assert_eq!(ring_anonymous_encrypted_output_body(&encoded), None);

    assert_eq!(
        encrypted(
            RING_CONFIDENTIAL_PACKED_SCHEME_TAG,
            RING_PACKED_DATA_FREE_BODY_LEN
        ),
        encoded
    );
    let with_data = encrypted(
        RING_CONFIDENTIAL_PACKED_SCHEME_TAG,
        RING_PACKED_DATA_FREE_BODY_LEN + 1,
    );
    assert!(ring_confidential_packed_output_body(&with_data).is_some());
    for refused in [
        encrypted(
            RING_CONFIDENTIAL_PACKED_SCHEME_TAG,
            RING_PACKED_DATA_FREE_BODY_LEN - 1,
        ),
        encrypted(
            RING_CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            RING_PACKED_DATA_FREE_BODY_LEN,
        ),
    ] {
        assert_eq!(ring_confidential_packed_output_body(&refused), None);
    }
}

#[test]
fn scheme_encoders_match_the_borsh_framing_at_exact_capacity() {
    let delivered = [9u8; RING_DELIVERED_BODY_LEN];
    for (encoded, scheme, len) in [
        (
            encode_confidential_output(&[9u8; CONFIDENTIAL_DATA_FREE_BODY_LEN]),
            CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            CONFIDENTIAL_DATA_FREE_BODY_LEN,
        ),
        (
            encode_ring_anonymous_output(&delivered),
            RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG,
            RING_DELIVERED_BODY_LEN,
        ),
        (
            encode_ring_confidential_delivered_output(&delivered),
            RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG,
            RING_DELIVERED_BODY_LEN,
        ),
        (
            encode_ring_confidential_packed_output(
                &[9u8; RECIPIENT_KEY_LEN],
                &[9u8; RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN],
            ),
            RING_CONFIDENTIAL_PACKED_SCHEME_TAG,
            RING_PACKED_DATA_FREE_BODY_LEN,
        ),
    ] {
        assert_eq!(encoded, encrypted(scheme, len), "scheme {scheme}");
        assert_eq!(encoded.capacity(), encoded.len(), "scheme {scheme}");
    }
    assert!(is_confidential_encrypted_output(
        &encode_confidential_output(&[9u8; 1])
    ));
    assert_eq!(
        ring_anonymous_encrypted_output_body(&encode_ring_anonymous_output(&delivered)),
        Some(&delivered[..])
    );
}

#[test]
fn merge_output_data_matches_the_borsh_framing_at_exact_capacity() {
    let salt = [3u8; MERGE_OUTPUT_SALT_LEN];
    let ciphertext = [[4u8; 32], [5u8; 32], [6u8; 32]];
    let hash = [7u8; 32];
    for ring_data_hash in [None, Some(&hash)] {
        let encoded = encode_merge_output_data(MergeOutputDataRef {
            salt: &salt,
            ciphertext: &ciphertext,
            ring_data_hash,
        });
        let mut blob = vec![MERGE_OUTPUT_SCHEME];
        blob.extend(ring_data_hash.into_iter().flatten());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(ciphertext.as_flattened());
        let framed = borsh::to_vec(&OutputDataEncoding::VerifiablyEncrypted(blob)).unwrap();
        assert_eq!(encoded, framed, "{ring_data_hash:?}");
        assert_eq!(encoded.capacity(), encoded.len());
    }
}

/// `Encrypted(scheme || payload)` with `len` payload bytes of 9.
fn encrypted(scheme: u8, len: usize) -> Vec<u8> {
    let mut blob = vec![scheme];
    blob.resize(1 + len, 9);
    borsh::to_vec(&OutputDataEncoding::Encrypted(blob)).unwrap()
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
