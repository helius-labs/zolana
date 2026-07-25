//! `encode_output_data` writes the plaintext body once instead of serializing it
//! into a `Vec` and copying that `Vec` into the enum payload. These tests pin the
//! result to the derived-borsh encoding it replaces, so the optimization cannot
//! change the bytes an indexer or wallet parses.

use borsh::BorshSerialize;
use zolana_event::{
    decode_output_data, encode_output_data, OutputDataEncoding, ProoflessOutput,
    PLAINTEXT_OUTPUT_FIXED_LEN,
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
        + data.zone_data.as_ref().map_or(0, Vec::len)
        + data.memo.as_ref().map_or(0, Vec::len);
    assert_eq!(
        encode_output_data(data).len(),
        PLAINTEXT_OUTPUT_FIXED_LEN + variable
    );
}

fn minimal() -> ProoflessOutput {
    ProoflessOutput {
        owner: [1u8; 32],
        blinding: [2u8; 31],
        asset: [0u8; 32],
        amount: 1_000,
        data_hash: None,
        utxo_data: None,
        zone_program_id: None,
        zone_data_hash: None,
        zone_data: None,
        memo: None,
    }
}

fn every_option_present() -> ProoflessOutput {
    ProoflessOutput {
        owner: [3u8; 32],
        blinding: [4u8; 31],
        asset: [5u8; 32],
        amount: u64::MAX,
        data_hash: Some([6u8; 32]),
        utxo_data: Some(vec![7u8; 200]),
        zone_program_id: Some([8u8; 32]),
        zone_data_hash: Some([9u8; 32]),
        zone_data: Some(vec![10u8; 64]),
        memo: Some(b"batched deposit".to_vec()),
    }
}

fn every_option_present_but_empty() -> ProoflessOutput {
    ProoflessOutput {
        data_hash: Some([11u8; 32]),
        utxo_data: Some(Vec::new()),
        zone_program_id: Some([12u8; 32]),
        zone_data_hash: Some([13u8; 32]),
        zone_data: Some(Vec::new()),
        memo: Some(Vec::new()),
        ..minimal()
    }
}
