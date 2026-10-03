use zolana_event::{merge_output::MERGE_MASK_SEED_LEN, MergeOutputDerivation};

fn derivation(output_ring_data_hash: Option<[u8; 32]>) -> MergeOutputDerivation {
    MergeOutputDerivation {
        masked_amount: [1; 32],
        masked_mint: [[2; 32], [3; 32]],
        mask_seed: [4; MERGE_MASK_SEED_LEN],
        output_ring_data_hash,
    }
}

#[test]
fn a_default_merge_publishes_the_masked_amount_mint_and_seed() {
    let mut expected = vec![1; 32];
    expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[4; MERGE_MASK_SEED_LEN]);
    assert_eq!(derivation(None).encode(), expected);
    assert_eq!(expected.len(), 127);
    assert_eq!(
        MergeOutputDerivation::decode(&expected),
        Some(derivation(None))
    );
}

#[test]
fn a_ring_merge_appends_the_output_ring_data_hash() {
    let mut encoded = derivation(None).encode();
    encoded.extend_from_slice(&[5; 32]);
    assert_eq!(encoded.len(), 159);
    assert_eq!(
        MergeOutputDerivation::decode(&encoded),
        Some(derivation(Some([5; 32])))
    );
    assert_eq!(derivation(Some([5; 32])).encode(), encoded);
}

#[test]
fn any_other_length_is_not_a_merge_derivation() {
    for len in [0, 32, 96, 126, 128, 158, 160, 191] {
        assert_eq!(MergeOutputDerivation::decode(&vec![7; len]), None, "{len}");
    }
}
