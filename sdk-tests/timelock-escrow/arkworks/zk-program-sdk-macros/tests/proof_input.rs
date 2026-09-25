use zk_program_sdk::{
    circuit::{value, CircuitType, ConstraintSystem, Field},
    conversion::{to_bytes, Allocator, Placeholder, ProofInput},
};

#[derive(Clone, ProofInput)]
struct Transfer {
    amount: u64,
    flags: [bool; 2],
    label: [u8; 32],
}

#[derive(Clone, ProofInput)]
struct Batch<const N: usize> {
    amounts: [u64; N],
}

#[derive(Clone, ProofInput)]
struct Nothing;

fn assert_circuit_type<T: CircuitType>() {}

fn native<T: ProofInput>(value: &T) -> T::Circuit {
    value
        .instantiate(&Allocator::native())
        .expect("native instantiation")
}

#[test]
fn instantiation_maps_every_field_to_its_circuit_form() {
    let circuit: TransferCircuit = native(&Transfer {
        amount: 7,
        flags: [true, false],
        label: [9u8; 32],
    });
    assert_eq!(value(&circuit.amount).expect("amount"), Field::from(7u64));
    assert_eq!(
        circuit
            .flags
            .each_ref()
            .map(|flag| value(&flag.var()).expect("flag")),
        [Field::from(1u64), Field::from(0u64)]
    );
    assert_eq!(to_bytes(&circuit.label).expect("label"), [9u8; 32]);
}

#[test]
fn placeholders_are_built_field_by_field() {
    let placeholder = Transfer::placeholder().expect("placeholder");
    assert_eq!(placeholder.amount, 0);
    assert_eq!(placeholder.flags, [false, false]);
    assert_eq!(placeholder.label, [0u8; 32]);
}

#[test]
fn a_generic_struct_instantiates_with_its_shape() {
    let circuit: BatchCircuit<3> = native(&Batch { amounts: [1, 2, 3] });
    assert_eq!(
        circuit
            .amounts
            .each_ref()
            .map(|amount| value(amount).expect("amount")),
        [Field::from(1u64), Field::from(2u64), Field::from(3u64)]
    );
}

#[test]
fn a_unit_struct_instantiates_to_a_unit_twin() {
    let NothingCircuit = native(&Nothing);
    let Nothing = Nothing::placeholder().expect("placeholder");
}

#[test]
fn twins_are_circuit_types() {
    assert_circuit_type::<TransferCircuit>();
    assert_circuit_type::<BatchCircuit<4>>();
    assert_circuit_type::<NothingCircuit>();
}

#[test]
fn r1cs_instantiation_range_checks_every_field_like_its_type() {
    let cs = ConstraintSystem::new_ref();
    Transfer {
        amount: 7,
        flags: [true, false],
        label: [9u8; 32],
    }
    .instantiate(&Allocator::R1cs(cs.clone()))
    .expect("r1cs instantiation");
    assert_eq!(cs.num_constraints(), 65 + 1 + 1);
}
