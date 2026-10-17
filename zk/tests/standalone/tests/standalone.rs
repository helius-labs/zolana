use zolana_zk_dsl::verifier::VerifyError;
use zolana_zk_dsl::{
    circuit::{constant, value, Circuit, Field},
    conversion::{field_bytes, Allocator, FromCircuit, ProofInput},
    Groth16Prover, ZkCircuit,
};
use zolana_zk_gadgets::poseidon;
use zolana_zk_standalone_fixture::{
    verifier::withdrawal, Opening, Payout, Point, PublicOpening, Withdrawal, PAYOUT_RULE, RULE,
};

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
    assert_eq!(result.public_inputs, vec![field_bytes(&commitment())]);
    prover.verify(&result).expect("the proof verifies");
    result.public_inputs = vec![field_bytes(&Field::from(5u64))];
    assert!(prover.verify(&result).is_err());
}

fn withdrawal() -> Withdrawal {
    Withdrawal::example()
}

fn on_chain_inputs(payout: &Payout) -> withdrawal::PublicInputs {
    withdrawal::PublicInputs {
        commitment: field_bytes(&payout.commitment),
        amount: payout.amount,
        destination: *payout.destination.as_array(),
    }
}

/// The verifier module `zolana zk compile` generated accepts a proof from the
/// deterministic test setup, which is the key it embeds.
#[test]
fn the_generated_verifier_accepts_a_proof_of_a_standalone_circuit() {
    let inputs = withdrawal();
    let prover = Groth16Prover::<Withdrawal>::new_with_test_setup().expect("test setup");
    let result = prover.prove(&inputs).expect("proof");
    let proof = result.compressed().expect("compressed proof");
    let public_inputs = on_chain_inputs(&inputs.public);
    assert_eq!(result.public_inputs, public_inputs.public_inputs().to_vec());
    assert_eq!(withdrawal::verify(&proof, &public_inputs), Ok(()));
    let other_destination = withdrawal::PublicInputs {
        destination: [8u8; 32],
        ..public_inputs
    };
    assert_eq!(
        withdrawal::verify(&proof, &other_destination),
        Err(VerifyError::Proof)
    );
}

#[test]
fn a_standalone_payout_must_open_its_note() {
    let mut inputs = withdrawal();
    inputs.public.amount = 251;
    let error = inputs
        .instantiate(&Allocator::native())
        .expect("native instantiation")
        .circuit()
        .expect_err("a wrong amount");
    assert_eq!(error.broken_rule(), Some(PAYOUT_RULE));
}

/// The inputs, the public inputs and the gnark verifying key the wasm test
/// (`wasm/standalone.test.mjs`) proves and verifies with. The keys are the
/// deterministic test setup's, which `zolana zk compile` also writes.
fn wasm_fixture() -> serde_json::Value {
    let inputs = withdrawal();
    let prover = Groth16Prover::<Withdrawal>::new_with_test_setup().expect("test setup");
    let public_inputs = on_chain_inputs(&inputs.public).public_inputs();
    serde_json::json!({
        "inputs": serde_json::to_value(inputs).expect("serialize"),
        "publicInputs": public_inputs,
        "verifyingKey": prover.keys().gnark_verifying_key().expect("gnark verifying key"),
    })
}

fn wasm_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wasm/withdrawal.json")
}

#[test]
#[ignore = "rewrites the committed wasm fixture"]
fn write_wasm_fixture() {
    let text = serde_json::to_string_pretty(&wasm_fixture()).expect("json") + "\n";
    std::fs::write(wasm_fixture_path(), text).expect("write the fixture");
}

#[test]
fn the_committed_wasm_fixture_matches_the_native_path() {
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(wasm_fixture_path()).expect("read the fixture"),
    )
    .expect("json");
    assert_eq!(committed, wasm_fixture());
}
