use zk_program_sdk::{
    circuit::{constant, poseidon, value, CircuitVar, ConstraintSystem, Field},
    conversion::{field_bytes, to_bytes, Allocator, ProofInput},
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

        let cs = ConstraintSystem::new_ref();
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
