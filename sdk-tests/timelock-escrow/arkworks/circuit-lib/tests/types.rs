use ark_relations::r1cs::ConstraintSystem;
use circuit_lib::{constant, Allocator, Bool, CircuitVar, Field, ProofInput, Uint, U16, U64};

fn satisfied(input: &impl ProofInput) -> (bool, usize) {
    let cs = ConstraintSystem::<Field>::new_ref();
    let allocator = Allocator::R1cs(cs.clone());
    input.instantiate(&allocator).map(|_| ()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

fn native(input: &impl ProofInput) -> Result<(), String> {
    input
        .instantiate(&Allocator::Native)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn integers_are_range_checked_when_instantiated() {
    let max = U64::from(u64::MAX);
    let too_wide = U64::new(constant(Field::from(u64::MAX) + Field::from(1u64)));
    let u16_max = U16::from(u64::from(u16::MAX));
    let u16_over = U16::from(u64::from(u16::MAX) + 1);

    assert_eq!(
        (
            native(&max),
            native(&too_wide),
            native(&u16_max),
            native(&u16_over),
            satisfied(&max),
            satisfied(&too_wide),
            satisfied(&u16_over),
        ),
        (
            Ok(()),
            Err("a value does not fit in 64 bits".to_string()),
            Ok(()),
            Err("a value does not fit in 16 bits".to_string()),
            (true, 65),
            (false, 65),
            (false, 17),
        )
    );
}

#[test]
fn bools_and_plain_values_are_instantiated() {
    let two = Bool::new(constant(2u64));
    let wide = Uint::<32>::from(7u64);
    let hash: CircuitVar = constant(Field::from(u64::MAX) * Field::from(u64::MAX));
    let array = [U64::from(1u64), U64::from(2u64)];

    assert_eq!(
        (
            native(&Bool::from(true)),
            native(&two),
            satisfied(&Bool::from(false)),
            satisfied(&two),
            native(&wide),
            satisfied(&hash),
            satisfied(&array),
        ),
        (
            Ok(()),
            Err("a value is neither 0 nor 1".to_string()),
            (true, 1),
            (false, 1),
            Ok(()),
            (true, 0),
            (true, 130),
        )
    );
}
