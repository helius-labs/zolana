use zolana_event::MergeOutputDerivation;

#[test]
fn a_default_merge_publishes_only_the_masked_amount() {
    let derivation = MergeOutputDerivation {
        masked_amount: [1; 32],
        output_ring_data_hash: None,
    };
    assert_eq!(derivation.encode(), vec![1; 32]);
    assert_eq!(MergeOutputDerivation::decode(&[1; 32]), Some(derivation));
}

#[test]
fn a_ring_merge_appends_the_output_ring_data_hash() {
    let mut encoded = vec![1; 32];
    encoded.extend_from_slice(&[2; 32]);
    assert_eq!(
        MergeOutputDerivation::decode(&encoded),
        Some(MergeOutputDerivation {
            masked_amount: [1; 32],
            output_ring_data_hash: Some([2; 32]),
        })
    );
}

#[test]
fn any_other_length_is_not_a_merge_derivation() {
    for len in [0, 31, 33, 63, 65, 96] {
        assert_eq!(MergeOutputDerivation::decode(&vec![7; len]), None, "{len}");
    }
}
