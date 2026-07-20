use zolana_hasher::primitives::split_be_128;

const VALUE: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

#[test]
fn splits_into_right_aligned_limbs() {
    let (low, high) = split_be_128(&VALUE);

    let expected_low: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31,
    ];
    let expected_high: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15,
    ];

    assert_eq!(low, expected_low);
    assert_eq!(high, expected_high);
}

/// Pinned `Poseidon(low, high)` output; a change means the pubkey field
/// encoding drifted from the circuits.
#[cfg(feature = "poseidon")]
#[test]
fn bytes32_proof_input_hash_matches_pinned_vector() {
    use zolana_hasher::primitives::bytes32_proof_input_hash;

    let got = bytes32_proof_input_hash(&VALUE).unwrap();
    let expected: [u8; 32] = [
        43, 206, 220, 148, 200, 204, 113, 121, 112, 250, 116, 12, 238, 24, 70, 113, 34, 21, 110,
        22, 33, 54, 68, 90, 112, 8, 157, 204, 11, 182, 90, 81,
    ];
    assert_eq!(got, expected);
}
