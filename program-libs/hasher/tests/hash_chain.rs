use serde::{Deserialize, Serialize};
use zolana_hasher::{
    hash_chain::{
        create_hash_chain_4_from_slice, create_hash_chain_4_from_slice_ref,
        create_hash_chain_from_slice, create_hash_chain_from_slice_ref,
        create_two_inputs_hash_chain,
    },
    Hasher, HasherError, Poseidon,
};

/// Shared cross-language known-answer vectors for the 4-input fold.
///
/// `test-vectors/hash_chain_4.json` pins the fold formula for every
/// implementation (Rust here, Go under `prover/server`, TypeScript in
/// `sdk-libs/ts`). Regenerate it with the ignored printer and commit the
/// output:
///
/// ```bash
/// cargo test -p zolana-hasher --test hash_chain print_hash_chain_4_vectors -- --ignored --nocapture
/// ```
const HASH_CHAIN_4_VECTORS_JSON: &str = include_str!("../../../test-vectors/hash_chain_4.json");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HashChain4Vectors {
    description: String,
    vectors: Vec<HashChain4Vector>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HashChain4Vector {
    name: String,
    inputs: Vec<String>,
    output: String,
}

fn field(value: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&value.to_be_bytes());
    out
}

fn hash_chain_4_vector(name: &str, inputs: &[[u8; 32]]) -> HashChain4Vector {
    HashChain4Vector {
        name: name.to_string(),
        inputs: inputs.iter().map(hex::encode).collect(),
        output: hex::encode(create_hash_chain_4_from_slice(inputs).unwrap()),
    }
}

fn compute_hash_chain_4_vectors() -> HashChain4Vectors {
    let mut vectors: Vec<HashChain4Vector> = [0u32, 1, 2, 3, 4, 5, 7, 8, 16, 36]
        .iter()
        .map(|&len| {
            let inputs: Vec<[u8; 32]> = (1..=len).map(field).collect();
            hash_chain_4_vector(&format!("len_{len}"), &inputs)
        })
        .collect();
    vectors.push(hash_chain_4_vector(
        "zero_element_in_the_middle",
        &[field(1), field(0), field(3), field(4), field(5)],
    ));
    HashChain4Vectors {
        description: "Known-answer vectors for hash_chain_4, the 4-input Poseidon fold over \
                      32-byte big-endian BN254 field elements: L == 0 -> 0, L == 1 -> e[0], \
                      otherwise h = e[0] and for each group of up to 3 following elements \
                      h = Poseidon(h, g[0], g[1] or 0, g[2] or 0). A partial trailing group \
                      is zero-padded; the 4-input permutation is used for every step. The \
                      len_<L> entries fold e[i] = i + 1; zero_element_in_the_middle shows a \
                      zero element is positional and distinct from padding. Produced by \
                      program-libs/hasher/tests/hash_chain.rs print_hash_chain_4_vectors."
            .to_string(),
        vectors,
    }
}

#[test]
fn committed_hash_chain_4_vectors_match() {
    let committed: HashChain4Vectors = serde_json::from_str(HASH_CHAIN_4_VECTORS_JSON).unwrap();
    assert_eq!(committed, compute_hash_chain_4_vectors());
}

/// Every committed entry is a known-answer test for both entry points; the
/// borrowed-slice variant used by the on-chain public-input assembly must
/// agree with the owned-slice variant.
#[test]
fn hash_chain_4_matches_every_committed_vector() {
    let committed: HashChain4Vectors = serde_json::from_str(HASH_CHAIN_4_VECTORS_JSON).unwrap();
    assert_eq!(committed.vectors.len(), 11);
    for vector in &committed.vectors {
        let inputs: Vec<[u8; 32]> = vector
            .inputs
            .iter()
            .map(|input| hex::decode(input).unwrap().try_into().unwrap())
            .collect();
        let expected: [u8; 32] = hex::decode(&vector.output).unwrap().try_into().unwrap();
        let refs: Vec<&[u8; 32]> = inputs.iter().collect();
        assert_eq!(
            create_hash_chain_4_from_slice(&inputs).unwrap(),
            expected,
            "vector {}",
            vector.name
        );
        assert_eq!(
            create_hash_chain_4_from_slice_ref(&refs).unwrap(),
            expected,
            "vector {} via slice_ref",
            vector.name
        );
    }
}

/// Up to four elements fold in exactly one 4-input Poseidon call, with the
/// missing trailing inputs zero-padded.
#[test]
fn hash_chain_4_with_at_most_four_elements_is_one_poseidon_call() {
    let zero = [0u8; 32];
    let e = [field(1), field(2), field(3), field(4)];
    let [e1, e2, e3, e4] = &e;
    assert_eq!(
        create_hash_chain_4_from_slice(&e[..2]).unwrap(),
        Poseidon::hashv(&[e1, e2, &zero, &zero]).unwrap()
    );
    assert_eq!(
        create_hash_chain_4_from_slice(&e[..3]).unwrap(),
        Poseidon::hashv(&[e1, e2, e3, &zero]).unwrap()
    );
    assert_eq!(
        create_hash_chain_4_from_slice(&e[..4]).unwrap(),
        Poseidon::hashv(&[e1, e2, e3, e4]).unwrap()
    );
    let five = create_hash_chain_4_from_slice(&[*e1, *e2, *e3, *e4, field(5)]).unwrap();
    assert_eq!(
        five,
        Poseidon::hashv(&[
            &Poseidon::hashv(&[e1, e2, e3, e4]).unwrap(),
            &field(5),
            &zero,
            &zero
        ])
        .unwrap()
    );
}

/// A zero element inside the chain shifts every later element to another
/// input position, so it is not confused with the zero padding of a shorter
/// chain. Only equal-length chains are compared by the protocol; a trailing
/// zero element IS indistinguishable from padding, which the doc comment on
/// `create_hash_chain_4_from_slice` requires callers to rule out by fixing the
/// length per circuit.
#[test]
fn hash_chain_4_zero_element_is_positional() {
    let with_zero = [field(1), field(0), field(3), field(4), field(5)];
    let padded = [field(1), field(0), field(3), field(4)];
    let without_zero = [field(1), field(3), field(4), field(5)];
    let with_zero_hash = create_hash_chain_4_from_slice(&with_zero).unwrap();
    assert_ne!(
        with_zero_hash,
        create_hash_chain_4_from_slice(&padded).unwrap()
    );
    assert_ne!(
        with_zero_hash,
        create_hash_chain_4_from_slice(&without_zero).unwrap()
    );
    assert_eq!(
        create_hash_chain_4_from_slice(&[field(1), field(2)]).unwrap(),
        create_hash_chain_4_from_slice(&[field(1), field(2), field(0), field(0)]).unwrap(),
        "trailing zeros equal padding, which is why chain lengths are fixed per circuit"
    );
}

#[test]
fn hash_chain_4_empty_and_single_element_match_the_binary_chain() {
    let empty: [[u8; 32]; 0] = [];
    assert_eq!(create_hash_chain_4_from_slice(&empty).unwrap(), [0u8; 32]);
    assert_eq!(create_hash_chain_4_from_slice_ref(&[]).unwrap(), [0u8; 32]);
    let single = [7u8; 32];
    assert_eq!(create_hash_chain_4_from_slice(&[single]).unwrap(), single);
    assert_eq!(
        create_hash_chain_4_from_slice_ref(&[&single]).unwrap(),
        single
    );
    assert_eq!(
        create_hash_chain_4_from_slice(&[single]).unwrap(),
        create_hash_chain_from_slice(&[single]).unwrap()
    );
}

#[test]
fn hash_chain_4_rejects_inputs_larger_than_the_modulus() {
    use ark_ff::PrimeField;
    use light_poseidon::PoseidonError;
    use num_bigint::BigUint;
    use zolana_hasher::bigint::bigint_to_be_bytes_array;
    let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
    let modulus_bytes: [u8; 32] = bigint_to_be_bytes_array(&modulus).unwrap();
    for inputs in [
        vec![modulus_bytes, modulus_bytes],
        vec![field(1), modulus_bytes],
        vec![field(1), field(2), field(3), field(4), modulus_bytes],
    ] {
        let result = create_hash_chain_4_from_slice(&inputs);
        assert!(
            matches!(
                result,
                Err(HasherError::Poseidon(PoseidonError::InputLargerThanModulus))
            ),
            "{result:?}"
        );
    }
    assert_eq!(
        create_hash_chain_4_from_slice(&[modulus_bytes]).unwrap(),
        modulus_bytes,
        "a single element is returned unhashed, as in the binary chain"
    );
}

#[test]
#[ignore = "regenerates test-vectors/hash_chain_4.json; run with --nocapture and commit the output"]
fn print_hash_chain_4_vectors() {
    println!(
        "{}",
        serde_json::to_string_pretty(&compute_hash_chain_4_vectors()).unwrap()
    );
}

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
