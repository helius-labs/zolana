use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use spr_circuit::{ArrayVec, CircuitErrorKind, Field, from_bytes, hash_bytes, poseidon, to_bytes};

fn reference(values: &[u64]) -> String {
    let values: Vec<_> = values.iter().copied().map(ark_bn254::Fr::from).collect();
    Poseidon::<ark_bn254::Fr>::new_circom(values.len())
        .unwrap()
        .hash(&values)
        .unwrap()
        .into_bigint()
        .to_string()
}

#[test]
fn every_protocol_hash_arity_matches_light_poseidon() {
    for n in 1..=12 {
        for seed in [0, 1, 255, u64::MAX] {
            let values: Vec<_> = (0..n).map(|i| seed.wrapping_add(i as u64)).collect();
            let input: Vec<_> = values.iter().copied().map(Field::from).collect();
            assert_eq!(
                poseidon(&input).unwrap().to_decimal(),
                reference(&values),
                "arity {n}, seed {seed}"
            );
        }
    }
}

#[test]
fn byte_commitments_keep_big_endian_chunking_and_leading_zeroes() {
    let input = [0, 1, 2];
    assert_eq!(hash_bytes(&input).unwrap().to_decimal(), "258");
    let input = [0xff; 32];
    let first = Field::from_be_bytes(&[0xff; 31]).to_decimal();
    use std::str::FromStr;
    let expected = Poseidon::<ark_bn254::Fr>::new_circom(2)
        .unwrap()
        .hash(&[
            ark_bn254::Fr::from_str(&first).unwrap(),
            ark_bn254::Fr::from(255u64),
        ])
        .unwrap()
        .into_bigint()
        .to_string();
    assert_eq!(hash_bytes(&input).unwrap().to_decimal(), expected);
}

#[test]
fn hash_chain_skips_zeroes_and_uses_the_first_nonzero_value_directly() {
    use spr_circuit::nonzero_hash_chain;
    use spr_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
    let values = [
        Field::zero(),
        Field::from(7u64),
        Field::zero(),
        Field::from(9u64),
        Field::zero(),
    ];
    let bytes = values.map(|value| to_bytes(&value));
    assert_eq!(
        [
            nonzero_hash_chain(&[]),
            nonzero_hash_chain(&values[..3]),
            nonzero_hash_chain(&values)
        ]
        .map(|chain| to_bytes(&chain.unwrap())),
        [
            create_nonzero_hash_chain_from_slice(&[]).unwrap(),
            to_bytes(&Field::from(7u64)),
            create_nonzero_hash_chain_from_slice(&bytes).unwrap(),
        ]
    );
}

#[test]
fn single_element_nonzero_chains_preserve_zero_and_nonzero_values() {
    for value in [Field::zero(), Field::one(), -Field::one()] {
        assert_eq!(
            to_bytes(&spr_circuit::nonzero_hash_chain(&[value]).unwrap()),
            to_bytes(&value)
        );
    }
}

#[test]
fn field_decoding_refuses_modular_aliases() {
    let modulus = ark_bn254::Fr::MODULUS.to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&modulus);
    assert_eq!(
        from_bytes(&bytes).unwrap_err().kind(),
        &CircuitErrorKind::NonCanonicalField
    );
    assert_eq!(to_bytes(&from_bytes(&[0; 32]).unwrap()), [0; 32]);
}

#[test]
fn bounded_inputs_encode_padding_and_refuse_excess_items() {
    use xark::input::leaves;
    let inputs = ArrayVec::<u64, 3>::new([7u64]).unwrap();
    assert_eq!(leaves(&inputs, "amounts"), leaves(&[7u64, 0, 0], "amounts"));
    assert_eq!(
        ArrayVec::<u64, 1>::new([0u64, 0, 0]).unwrap_err().kind(),
        &CircuitErrorKind::TooManyItems {
            capacity: 1,
            found: 3
        },
    );
}
