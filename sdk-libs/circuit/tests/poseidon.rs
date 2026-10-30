use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use proptest::prelude::*;
use spr_circuit::{Field, from_decimal, poseidon};

#[test]
fn full_field_vectors_match_light_poseidon() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../gnark-sdk/testdata/poseidon.json")).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 60);
    for vector in vectors {
        let inputs: Vec<_> = vector["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| from_decimal(value.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(
            poseidon(&inputs).unwrap().to_decimal(),
            vector["hash"].as_str().unwrap(),
            "arity {}, pattern {}",
            vector["arity"],
            vector["pattern"]
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn arbitrary_field_inputs_match_light_poseidon(
        bytes in prop::collection::vec(any::<[u8; 32]>(), 1..=12)
    ) {
        let values: Vec<_> = bytes.iter().map(|value| ark_bn254::Fr::from_be_bytes_mod_order(value)).collect();
        let inputs: Vec<_> = values.iter().map(|value| Field::from_be_bytes(&value.into_bigint().to_bytes_be())).collect();
        let expected = Poseidon::<ark_bn254::Fr>::new_circom(values.len()).unwrap().hash(&values).unwrap();
        prop_assert_eq!(poseidon(&inputs).unwrap().to_decimal(), expected.into_bigint().to_string());
    }
}
