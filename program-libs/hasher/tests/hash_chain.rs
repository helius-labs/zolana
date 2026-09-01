use zolana_hasher::{
    hash_chain::{
        create_hash_chain_from_slice, create_hash_chain_from_slice_ref,
        create_two_inputs_hash_chain,
    },
    HasherError,
};

/// Tests for `create_hash_chain_from_slice` function:
/// Functional tests:
/// 1. Functional - with hardcoded values (known-answer tests).
/// 2. Functional - for determinism (hashing the same input twice).
/// 3. Functional - empty input case returns zero hash.
///
/// Failing tests:
/// 4. Failing - input larger than modulus
#[test]
fn test_create_hash_chain_from_slice() {
    // 1. Functional tests with hardcoded values (known-answer tests).
    {
        let inputs: [[u8; 32]; 2] = [[4u8; 32], [5u8; 32]];
        let hard_coded_expected_hash = [
            13, 250, 206, 124, 182, 159, 160, 87, 57, 23, 80, 155, 25, 43, 40, 136, 228, 255, 201,
            1, 22, 168, 211, 220, 176, 187, 23, 176, 46, 198, 140, 211,
        ];

        let result = create_hash_chain_from_slice(&inputs).unwrap();

        assert_eq!(result, hard_coded_expected_hash);
    }

    {
        let inputs = [[4u8; 32], [5u8; 32], [6u8; 32]];
        let hard_coded_expected_hash = [
            12, 74, 32, 81, 132, 82, 10, 115, 75, 248, 169, 125, 228, 230, 140, 167, 149, 181, 244,
            194, 63, 201, 26, 150, 142, 4, 60, 16, 77, 145, 194, 152,
        ];

        let result = create_hash_chain_from_slice(&inputs).unwrap();

        assert_eq!(result, hard_coded_expected_hash);
    }

    // 2. Functional test for determinism (hashing the same input twice).
    {
        // Define inputs.
        let inputs: [[u8; 32]; 2] = [[6u8; 32], [7u8; 32]];

        // Compute hash chain the first time.
        let first_hash = create_hash_chain_from_slice(&inputs).unwrap();

        // Compute hash chain the second time.
        let second_hash = create_hash_chain_from_slice(&inputs).unwrap();

        // Assert that both hashes are identical.
        assert_eq!(
            first_hash, second_hash,
            "Determinism test failed: Hashes do not match."
        );
    }

    // 3. Test empty input case
    {
        let inputs: [[u8; 32]; 0] = [];
        let result = create_hash_chain_from_slice(&inputs).unwrap();
        assert_eq!(result, [0u8; 32], "Empty input should return zero hash");
    }
    // 4. Failing - input larger than modulus
    {
        use ark_ff::PrimeField;
        use light_poseidon::PoseidonError;
        use num_bigint::BigUint;
        use zolana_hasher::bigint::bigint_to_be_bytes_array;
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let modulus_bytes: [u8; 32] = bigint_to_be_bytes_array(&modulus).unwrap();
        let huge_input = vec![modulus_bytes, modulus_bytes];
        let result = create_hash_chain_from_slice(&huge_input);
        assert!(
            matches!(result, Err(HasherError::Poseidon(error)) if error  == PoseidonError::InputLargerThanModulus),
        );
    }
}

/// Tests for `create_two_inputs_hash_chain` function:
/// 1. Functional - empty inputs.
/// 2. Functional - 1 input each (known-answer test).
/// 3. Functional - 2 inputs each (known-answer test).
/// 4. Failing - invalid input length for hashes_first.
/// 5. Failing - invalid input length for hashes_second.
#[test]
fn test_create_two_inputs_hash_chain() {
    // 1. Functional test with empty inputs.
    {
        let hashes_first: &[[u8; 32]] = &[];
        let hashes_second: &[[u8; 32]] = &[];
        let result = create_two_inputs_hash_chain(hashes_first, hashes_second).unwrap();
        assert_eq!(result, [0u8; 32], "Empty input should return zero hash");
    }

    // 2. Functional test with 1 input each (known-answer test).
    {
        let hashes_first: &[[u8; 32]] = &[[1u8; 32]];
        let hashes_second: &[[u8; 32]] = &[[2u8; 32]];
        // Precomputed with Poseidon (BN254) over ([1u8; 32], [2u8; 32]).
        let hard_coded_expected_hash = [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144,
        ];
        let result = create_two_inputs_hash_chain(hashes_first, hashes_second).unwrap();
        assert_eq!(result, hard_coded_expected_hash);
    }

    // 3. Functional test with 2 inputs each (known-answer test).
    {
        let hashes_first: &[[u8; 32]] = &[[1u8; 32], [2u8; 32]];
        let hashes_second: &[[u8; 32]] = &[[3u8; 32], [4u8; 32]];
        // Precomputed hash chain over hashes_first = [[1u8; 32], [2u8; 32]],
        // hashes_second = [[3u8; 32], [4u8; 32]].
        let hard_coded_expected_hash = [
            23, 56, 17, 250, 53, 173, 216, 47, 50, 140, 214, 143, 156, 83, 114, 135, 158, 61, 234,
            194, 122, 74, 28, 112, 84, 212, 16, 150, 231, 146, 148, 29,
        ];
        let result = create_two_inputs_hash_chain(hashes_first, hashes_second).unwrap();
        assert_eq!(result, hard_coded_expected_hash);
    }

    // 4. Failing test with invalid input length for hashes_first.
    {
        let hashes_first: &[[u8; 32]] = &[[1u8; 32]];
        let hashes_second: &[[u8; 32]] = &[[2u8; 32], [3u8; 32]];
        let result = create_two_inputs_hash_chain(hashes_first, hashes_second);
        assert!(
            matches!(result, Err(HasherError::InvalidInputLength(1, 2))),
            "Invalid input length for hashes_first test failed"
        );
    }

    // 5. Failing test with invalid input length for hashes_second.
    {
        let hashes_first: &[[u8; 32]] = &[[1u8; 32], [2u8; 32]];
        let hashes_second: &[[u8; 32]] = &[[3u8; 32]];
        let result = create_two_inputs_hash_chain(hashes_first, hashes_second);
        assert!(
            matches!(result, Err(HasherError::InvalidInputLength(2, 1))),
            "Invalid input length for hashes_second test failed"
        );
    }
}

/// `create_hash_chain_from_slice_ref` is the borrowed-slice entry point used by
/// the on-chain public-input assembly (`transact/verify.rs`): it must agree
/// with the canonical slice variant on the same inputs, and both must match
/// the pinned digest.
#[test]
fn slice_ref_matches_the_slice_variant_and_the_kat() {
    let inputs: [[u8; 32]; 2] = [[4u8; 32], [5u8; 32]];
    // Same KAT as `test_create_hash_chain_from_slice` for these inputs.
    let hard_coded_expected_hash = [
        13, 250, 206, 124, 182, 159, 160, 87, 57, 23, 80, 155, 25, 43, 40, 136, 228, 255, 201, 1,
        22, 168, 211, 220, 176, 187, 23, 176, 46, 198, 140, 211,
    ];

    let refs: Vec<&[u8; 32]> = inputs.iter().collect();
    let via_ref = create_hash_chain_from_slice_ref(&refs).unwrap();

    assert_eq!(via_ref, create_hash_chain_from_slice(&inputs).unwrap());
    assert_eq!(via_ref, hard_coded_expected_hash);
}
