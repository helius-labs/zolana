use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use zolana_circuit::{CircuitErrorKind, Field, ArrayVec, from_bytes, hash_bytes, poseidon, to_bytes};

fn reference(values: &[u64]) -> String {
    let values: Vec<_> = values.iter().copied().map(ark_bn254::Fr::from).collect();
    Poseidon::<ark_bn254::Fr>::new_circom(values.len()).unwrap().hash(&values).unwrap().into_bigint().to_string()
}

#[test]
fn every_protocol_hash_arity_matches_light_poseidon() {
    for n in 1..=12 {
        for seed in [0, 1, 255, u64::MAX] {
            let values: Vec<_> = (0..n).map(|i| seed.wrapping_add(i as u64)).collect();
            let input: Vec<_> = values.iter().copied().map(Field::from).collect();
            assert_eq!(poseidon(&input).unwrap().to_decimal(), reference(&values), "arity {n}, seed {seed}");
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
    let expected = Poseidon::<ark_bn254::Fr>::new_circom(2).unwrap().hash(&[
        ark_bn254::Fr::from_str(&first).unwrap(), ark_bn254::Fr::from(255u64),
    ]).unwrap().into_bigint().to_string();
    assert_eq!(hash_bytes(&input).unwrap().to_decimal(), expected);
}

#[test]
fn hash_chain_skips_zeroes_and_uses_the_first_nonzero_value_directly() {
    use zolana_circuit::nonzero_hash_chain;
    let values = [Field::zero(), Field::from(7u64), Field::zero(), Field::from(9u64), Field::zero()];
    let actual = [nonzero_hash_chain(&[]).unwrap(), nonzero_hash_chain(&values[..3]).unwrap(), nonzero_hash_chain(&values).unwrap()];
    let expected = [Field::zero(), Field::from(7u64), poseidon(&[Field::from(7u64), Field::from(9u64)]).unwrap()];
    assert_eq!(actual.map(to_bytes_ref), expected.map(to_bytes_ref));
}

fn to_bytes_ref(value: Field) -> [u8; 32] { to_bytes(&value) }

#[test]
fn field_decoding_refuses_modular_aliases() {
    let modulus = ark_bn254::Fr::MODULUS.to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&modulus);
    assert_eq!(from_bytes(&bytes).unwrap_err().kind(), &CircuitErrorKind::NonCanonicalField);
    assert_eq!(to_bytes(&from_bytes(&[0; 32]).unwrap()), [0; 32]);
}

#[test]
fn bounded_inputs_encode_padding_and_refuse_excess_items() {
    use xark::input::leaves;
    let inputs = ArrayVec::<u64, 3>::new([7u64]).unwrap();
    let padded = inputs.padded();
    let expected = ArrayVec::<u64, 3>::new(padded).unwrap();
    assert_eq!(leaves(&inputs, "amounts"), leaves(&expected, "amounts"));
    assert_eq!(
        ArrayVec::<u64, 1>::new([0u64, 0u64]).unwrap_err().kind(),
        &CircuitErrorKind::TooManyItems { capacity: 1, found: 2 },
    );
}
