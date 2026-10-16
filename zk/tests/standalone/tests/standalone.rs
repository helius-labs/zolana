use zolana_zk_dsl::{
    circuit::{constant, value, Circuit, Field},
    conversion::{field_bytes, Allocator, FromCircuit, ProofInput},
    Groth16Prover, ZkCircuit,
};
use zolana_zk_gadgets::poseidon;
use zolana_zk_standalone_fixture::{Opening, Point, PublicOpening, RULE};

fn opening(commitment: Field) -> Opening {
    Opening {
        point: Point {
            x: Field::from(3u64),
            y: Field::from(4u64),
        },
        commitment,
    }
}

fn commitment() -> Field {
    value(&poseidon(&[constant(3u64), constant(4u64)]).expect("hash")).expect("constant")
}

#[test]
fn a_standalone_circuit_checks_its_constraints() {
    assert!(
        opening(commitment())
            .check_constraints()
            .expect("satisfied")
            > 0
    );
}

#[test]
fn a_standalone_circuit_refuses_a_wrong_opening_by_its_rule() {
    let error = opening(Field::from(5u64))
        .instantiate(&Allocator::native())
        .expect("native instantiation")
        .circuit()
        .expect_err("a wrong commitment");
    assert_eq!(error.broken_rule(), Some(RULE));
}

#[test]
fn a_standalone_circuit_exports_its_r1cs() {
    assert!(!Opening::export_r1cs().expect("r1cs").is_empty());
}

#[test]
fn a_standalone_circuit_type_converts_back() {
    let point = opening(commitment()).point;
    let circuit = point
        .instantiate(&Allocator::native())
        .expect("native instantiation");
    assert_eq!(Point::from_circuit(&circuit).expect("from circuit"), point);
}

#[test]
fn standalone_proof_inputs_round_trip_through_json() {
    let json = serde_json::to_value(opening(commitment())).expect("serialize");
    let back: Opening = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(serde_json::to_value(back).expect("serialize"), json);
}

#[test]
fn a_standalone_circuit_with_a_public_hash_proves_and_verifies() {
    let inputs = PublicOpening {
        point: opening(commitment()).point,
    };
    let prover = Groth16Prover::<PublicOpening>::new_with_test_setup().expect("test setup");
    let mut result = prover.prove(&inputs).expect("proof");
    assert_eq!(result.public_hash, field_bytes(&commitment()));
    prover.verify(&result).expect("the proof verifies");
    result.public_hash = field_bytes(&Field::from(5u64));
    assert!(prover.verify(&result).is_err());
}
