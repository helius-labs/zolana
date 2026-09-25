use ark_relations::r1cs::ConstraintSystem;
use circuit_lib::{
    constant,
    convert::{field_bytes, to_bytes},
    poseidon, value, Allocator, CircuitVar, Field, ProofInput,
};
use zolana_hasher::{Hasher, Poseidon};

#[test]
fn poseidon_matches_zolana_hasher_on_constants_and_in_r1cs() {
    for arity in 1..=7u64 {
        let inputs: Vec<CircuitVar> = (0..arity)
            .map(|i| constant(Field::from(1_000 * arity + i)))
            .collect();
        let input_bytes: Vec<[u8; 32]> = inputs
            .iter()
            .map(|input| field_bytes(&value(input).unwrap()))
            .collect();
        let expected = Poseidon::hashv(
            &input_bytes
                .iter()
                .map(|bytes| bytes.as_slice())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let cs = ConstraintSystem::<Field>::new_ref();
        let allocator = Allocator::R1cs(cs.clone());
        let allocated: Vec<CircuitVar> = inputs
            .iter()
            .map(|input| input.instantiate(&allocator).unwrap())
            .collect();

        assert_eq!(
            (
                to_bytes(&poseidon(&inputs).unwrap()).unwrap(),
                to_bytes(&poseidon(&allocated).unwrap()).unwrap(),
                cs.is_satisfied().unwrap(),
            ),
            (expected, expected, true),
            "arity {arity}"
        );
    }
}
