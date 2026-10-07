use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::{
            merge_ring::MergeRingIxDataRef,
            merge_transact::{
                merge_circuit_width, MergeBody, MergeEnvelope, MergeProof, MergeProofCommitment,
                MergeTransactIxData, MergeTransactIxDataRef, MAX_MERGE_INPUTS,
                MERGE_CIPHERTEXT_LEN, MERGE_DEFAULT_INPUT_COUNT, MERGE_SUPPORTED_INPUT_COUNTS,
            },
        },
        MergeRingIxData,
    },
};

const BODY_FIXED_LEN: usize = 271;
const PROOF_COMMITMENT_LEN: usize = 64;
const ENVELOPE_LEN: usize = 33 + MERGE_CIPHERTEXT_LEN;
const DEFAULT_RAIL_FIXED_LEN: usize = 408;
const RING_RAIL_FIXED_LEN: usize = 303;

const VECTOR_PROOF_COMMITMENT: MergeProofCommitment = MergeProofCommitment {
    commitment: [0x41; 32],
    commitment_pok: [0x42; 32],
};

const VECTOR_ENVELOPE: MergeEnvelope = MergeEnvelope {
    ephemeral_pk: {
        let mut point = [0x43; 33];
        point[0] = 0x02;
        point
    },
    ciphertext: [0x44; MERGE_CIPHERTEXT_LEN],
};

const VECTOR_RING_DATA_HASH: [u8; 32] = [7; 32];

fn body_with(input_count: usize) -> MergeBody {
    MergeBody {
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

fn data_with(input_count: usize) -> MergeTransactIxData {
    MergeTransactIxData {
        body: body_with(input_count),
        proof_commitment: VECTOR_PROOF_COMMITMENT,
        envelope: VECTOR_ENVELOPE,
    }
}

fn ring_data_with(input_count: usize) -> MergeRingIxData {
    MergeRingIxData {
        output_ring_data_hash: VECTOR_RING_DATA_HASH,
        body: body_with(input_count),
    }
}

#[test]
fn rail_lengths_add_up_from_the_shared_body() {
    assert_eq!(
        DEFAULT_RAIL_FIXED_LEN,
        BODY_FIXED_LEN + PROOF_COMMITMENT_LEN + ENVELOPE_LEN
    );
    assert_eq!(RING_RAIL_FIXED_LEN, 32 + BODY_FIXED_LEN);
}

#[test]
fn every_supported_shape_has_the_contracted_encoded_length() {
    for input_count in MERGE_SUPPORTED_INPUT_COUNTS {
        let bytes = data_with(input_count)
            .serialize()
            .expect("serialize merge instruction");
        assert_eq!(bytes.len(), DEFAULT_RAIL_FIXED_LEN + 32 * input_count);
        MergeTransactIxDataRef::from_bytes(&bytes).expect("a supported shape must parse back");

        let bytes = ring_data_with(input_count)
            .serialize()
            .expect("serialize merge_ring instruction");
        assert_eq!(bytes.len(), RING_RAIL_FIXED_LEN + 32 * input_count);
        MergeRingIxDataRef::from_bytes(&bytes).expect("a supported shape must parse back");
    }
}

/// `merge_transact` is the body followed by the commitment and the envelope
/// with no option tags; `merge_ring` is the ring data hash followed by the same
/// body bytes.
#[test]
fn both_rails_lay_the_shared_body_out_identically() {
    let body = wincode::serialize(&body_with(MERGE_DEFAULT_INPUT_COUNT)).unwrap();
    assert_eq!(body.len(), BODY_FIXED_LEN + 32 * MERGE_DEFAULT_INPUT_COUNT);

    let mut expected_default = body.clone();
    expected_default.extend_from_slice(&VECTOR_PROOF_COMMITMENT.commitment);
    expected_default.extend_from_slice(&VECTOR_PROOF_COMMITMENT.commitment_pok);
    expected_default.extend_from_slice(&VECTOR_ENVELOPE.ephemeral_pk);
    expected_default.extend_from_slice(&VECTOR_ENVELOPE.ciphertext);
    assert_eq!(
        data_with(MERGE_DEFAULT_INPUT_COUNT).serialize().unwrap(),
        expected_default
    );

    let mut expected_ring = VECTOR_RING_DATA_HASH.to_vec();
    expected_ring.extend_from_slice(&body);
    assert_eq!(
        ring_data_with(MERGE_DEFAULT_INPUT_COUNT)
            .serialize()
            .unwrap(),
        expected_ring
    );
}

#[test]
fn ring_rail_rejects_a_default_rail_payload() {
    let default_payload = data_with(MERGE_DEFAULT_INPUT_COUNT).serialize().unwrap();
    assert_eq!(
        MergeRingIxDataRef::from_bytes(&default_payload),
        Err(ShieldedPoolError::InvalidMergeShape)
    );

    let mut prefixed = VECTOR_RING_DATA_HASH.to_vec();
    prefixed.extend_from_slice(&default_payload);
    assert_eq!(
        MergeRingIxDataRef::from_bytes(&prefixed),
        Err(ShieldedPoolError::InvalidMergeShape)
    );
}

#[test]
fn default_rail_rejects_a_payload_without_the_commitment_or_envelope() {
    let full = data_with(MERGE_DEFAULT_INPUT_COUNT).serialize().unwrap();
    for missing in [ENVELOPE_LEN, PROOF_COMMITMENT_LEN + ENVELOPE_LEN, 1] {
        let truncated = full.get(..full.len() - missing).unwrap();
        assert_eq!(
            MergeTransactIxDataRef::from_bytes(truncated),
            Err(ShieldedPoolError::InvalidMergeShape),
            "{missing} bytes short"
        );
    }
    let ring_payload = ring_data_with(MERGE_DEFAULT_INPUT_COUNT)
        .serialize()
        .unwrap();
    assert_eq!(
        MergeTransactIxDataRef::from_bytes(&ring_payload),
        Err(ShieldedPoolError::InvalidMergeShape)
    );
}

#[test]
fn both_rails_reject_trailing_bytes() {
    let mut bytes = data_with(8).serialize().unwrap();
    bytes.push(0);
    assert_eq!(
        MergeTransactIxDataRef::from_bytes(&bytes),
        Err(ShieldedPoolError::InvalidMergeShape)
    );
    let mut bytes = ring_data_with(8).serialize().unwrap();
    bytes.push(0);
    assert_eq!(
        MergeRingIxDataRef::from_bytes(&bytes),
        Err(ShieldedPoolError::InvalidMergeShape)
    );
}

#[test]
fn max_merge_inputs_is_the_widest_supported_shape() {
    assert_eq!(MERGE_SUPPORTED_INPUT_COUNTS, [8, 24, 54]);
    assert_eq!(
        MERGE_SUPPORTED_INPUT_COUNTS.iter().copied().max(),
        Some(MAX_MERGE_INPUTS)
    );
    assert!(MERGE_SUPPORTED_INPUT_COUNTS.contains(&MERGE_DEFAULT_INPUT_COUNT));
}

#[test]
fn rejects_unsupported_input_counts() {
    for input_count in [0, MAX_MERGE_INPUTS + 1] {
        assert_eq!(merge_circuit_width(input_count), None, "{input_count}");
        let bytes = data_with(input_count)
            .serialize()
            .expect("serialize merge instruction");
        assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes),
            Err(ShieldedPoolError::InvalidMergeShape),
            "{input_count} nullifiers"
        );
        let bytes = ring_data_with(input_count).serialize().unwrap();
        assert_eq!(
            MergeRingIxDataRef::from_bytes(&bytes),
            Err(ShieldedPoolError::InvalidMergeShape),
            "{input_count} nullifiers"
        );
    }
}

/// A shorter list selects the narrowest circuit that holds it; the remaining
/// slots are compact padding.
#[test]
fn every_count_up_to_the_widest_shape_selects_the_narrowest_circuit() {
    for input_count in 1..=MAX_MERGE_INPUTS {
        let expected = match input_count {
            1..=8 => 8,
            9..=24 => 24,
            _ => 54,
        };
        assert_eq!(merge_circuit_width(input_count), Some(expected));
        let bytes = data_with(input_count)
            .serialize()
            .expect("serialize merge instruction");
        MergeTransactIxDataRef::from_bytes(&bytes).expect("a compact-padded merge must parse");
    }
}

#[test]
fn cache_slot_round_trips_in_both_merge_rails() {
    for (cache_slot, encoded_len) in [(None, 664), (Some(0), 665), (Some(35), 665)] {
        let mut data = data_with(8);
        data.body.cache_slot = cache_slot;
        let bytes = data.serialize().unwrap();
        assert_eq!(bytes.len(), encoded_len);
        assert_eq!(
            MergeTransactIxDataRef::from_bytes(&bytes)
                .unwrap()
                .body
                .cache_slot,
            cache_slot
        );
        let mut ring = ring_data_with(8);
        ring.body.cache_slot = cache_slot;
        let bytes = ring.serialize().unwrap();
        assert_eq!(
            bytes.len(),
            encoded_len - DEFAULT_RAIL_FIXED_LEN + RING_RAIL_FIXED_LEN
        );
        assert_eq!(
            MergeRingIxDataRef::from_bytes(&bytes)
                .unwrap()
                .body
                .cache_slot,
            cache_slot
        );
    }
}

#[test]
fn external_data_hash_is_injective() {
    use zolana_interface::instruction::{tag, MergeExternalDataHash};
    let hash_of = |discriminator: u8, expiry: u64, output: &[u8; 32]| {
        MergeExternalDataHash {
            cache: None,
            spp_instruction_discriminator: discriminator,
            expiry_unix_ts: expiry,
            output_utxo_hash: output,
        }
        .hash()
        .unwrap()
    };
    let base = hash_of(tag::MERGE_TRANSACT, 1, &[1u8; 32]);
    assert_ne!(base, hash_of(tag::MERGE_TRANSACT, 2, &[1u8; 32]));
    assert_ne!(base, hash_of(tag::MERGE_TRANSACT, 1, &[2u8; 32]));
    assert_ne!(base, hash_of(tag::RING_MERGE_TRANSACT, 1, &[1u8; 32]));
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

const MERGE_ENCODING_VECTOR_JSON: &str = include_str!("../../../test-vectors/merge_encoding.json");
const VECTOR_CACHE_ADDRESS: [u8; 32] = [0x77; 32];
const VECTOR_CACHE_SLOT: u8 = 5;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn merge_encoding(input_count: usize, cache: Option<(&[u8; 32], u8)>) -> ([u8; 32], [u8; 32]) {
    use zolana_hasher::{sha256::Sha256, Hasher};
    use zolana_interface::instruction::{tag, MergeExternalDataHash};
    let mut data = data_with(input_count);
    data.body.cache_slot = cache.map(|(_, slot)| slot);
    let instruction_sha256 = Sha256::hash(&data.serialize().unwrap()).unwrap();
    let external_data_hash = MergeExternalDataHash {
        spp_instruction_discriminator: tag::MERGE_TRANSACT,
        expiry_unix_ts: data.body.expiry_unix_ts,
        output_utxo_hash: &data.body.output_utxo_hash,
        cache,
    }
    .hash()
    .unwrap();
    (instruction_sha256, external_data_hash)
}

fn compute_merge_encoding_vector() -> serde_json::Value {
    use zolana_hasher::{sha256::Sha256, Hasher};
    let (instruction_sha256, external_data_hash) = merge_encoding(MERGE_DEFAULT_INPUT_COUNT, None);
    let (cached_instruction_sha256, cached_external_data_hash) = merge_encoding(
        MERGE_DEFAULT_INPUT_COUNT,
        Some((&VECTOR_CACHE_ADDRESS, VECTOR_CACHE_SLOT)),
    );
    let (wide_instruction_sha256, _) = merge_encoding(MAX_MERGE_INPUTS, None);
    let ring_instruction_sha256 = Sha256::hash(
        &ring_data_with(MERGE_DEFAULT_INPUT_COUNT)
            .serialize()
            .unwrap(),
    )
    .unwrap();
    serde_json::json!({
        "proof_commitment": {
            "commitment": hex(&VECTOR_PROOF_COMMITMENT.commitment),
            "commitment_pok": hex(&VECTOR_PROOF_COMMITMENT.commitment_pok),
        },
        "envelope": {
            "ephemeral_pk": hex(&VECTOR_ENVELOPE.ephemeral_pk),
            "ciphertext": hex(&VECTOR_ENVELOPE.ciphertext),
        },
        "instruction_sha256": hex(&instruction_sha256),
        "external_data_hash": hex(&external_data_hash),
        "ring": {
            "output_ring_data_hash": hex(&VECTOR_RING_DATA_HASH),
            "instruction_sha256": hex(&ring_instruction_sha256),
        },
        "cached": {
            "cache_address": hex(&VECTOR_CACHE_ADDRESS),
            "cache_slot": VECTOR_CACHE_SLOT,
            "instruction_sha256": hex(&cached_instruction_sha256),
            "external_data_hash": hex(&cached_external_data_hash),
        },
        "wide": {
            "input_count": MAX_MERGE_INPUTS,
            "instruction_sha256": hex(&wide_instruction_sha256),
        },
    })
}

fn committed_merge_encoding_vector() -> serde_json::Value {
    serde_json::from_str(MERGE_ENCODING_VECTOR_JSON).unwrap()
}

#[test]
fn plain_merge_matches_the_shared_encoding_vector() {
    let vector = committed_merge_encoding_vector();
    let computed = compute_merge_encoding_vector();
    assert_eq!(vector["instruction_sha256"], computed["instruction_sha256"]);
    assert_eq!(vector["external_data_hash"], computed["external_data_hash"]);
}

#[test]
fn cached_merge_matches_the_shared_encoding_vector() {
    let vector = committed_merge_encoding_vector();
    assert_eq!(vector["cached"], compute_merge_encoding_vector()["cached"]);
    assert_ne!(
        vector["cached"]["instruction_sha256"],
        vector["instruction_sha256"]
    );
    assert_ne!(
        vector["cached"]["external_data_hash"],
        vector["external_data_hash"]
    );
}

#[test]
fn wide_merge_matches_the_shared_encoding_vector() {
    assert_eq!(
        committed_merge_encoding_vector()["wide"],
        compute_merge_encoding_vector()["wide"]
    );
}

#[test]
fn envelope_and_ring_merges_match_the_shared_encoding_vector() {
    let vector = committed_merge_encoding_vector();
    let computed = compute_merge_encoding_vector();
    assert_eq!(vector["proof_commitment"], computed["proof_commitment"]);
    assert_eq!(vector["envelope"], computed["envelope"]);
    assert_eq!(vector["ring"], computed["ring"]);
}

#[test]
#[ignore = "regenerates test-vectors/merge_encoding.json; run with --nocapture and commit the output"]
fn print_merge_encoding_vector() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_merge_encoding_vector()).unwrap()
    );
}
