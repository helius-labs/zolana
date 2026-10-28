use spr_zk_standalone_fixture::{WithdrawalInputs, verifier::withdrawal};
use spr_program::{proof, to_bytes};
use std::path::{Path, PathBuf};
fn artifacts() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/zk/spr-zk-standalone-fixture") }

fn wasm_fixture() -> serde_json::Value {
    let input = WithdrawalInputs::example();
    let payout = withdrawal::PublicInputs { commitment: to_bytes(&input.public.commitment), amount: input.public.amount, destination: input.public.destination() };
    serde_json::json!({
        "inputs": {
            "private": xark::client::to_json(&input.private).unwrap(),
            "public": {
                "commitment": input.public.commitment.to_decimal(),
                "amount": input.public.amount.to_string(),
                "destination_hi": input.public.destination_hi.to_decimal(),
                "destination_lo": input.public.destination_lo,
            },
        },
        "publicInputs": payout.public_inputs(),
        "verifyingKey": std::fs::read(artifacts().join("vk.bin")).expect("compile the standalone circuit and test keys first"),
    })
}

#[test]
fn the_committed_wasm_fixture_matches_the_native_path() {
    let expected: serde_json::Value = serde_json::from_str(include_str!("../wasm/withdrawal.json")).unwrap();
    assert_eq!(wasm_fixture(), expected);
}

#[test]
#[ignore = "regenerates the synthetic standalone WASM fixture"]
fn write_standalone_wasm_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("wasm/withdrawal.json");
    std::fs::write(path, serde_json::to_string_pretty(&wasm_fixture()).unwrap() + "\n").unwrap();
}
#[test]
fn native_inputs_round_trip_through_the_xark_codec() {
    let input = WithdrawalInputs::example();
    let json = xark::client::to_json(&input.public).unwrap();
    let back: spr_zk_standalone_fixture::Payout = xark::client::from_json(&json).unwrap();
    assert_eq!((back.amount, back.destination()), (input.public.amount, input.public.destination()));
}
#[test]
fn compiled_constraints_bind_the_note_and_each_public_payout_field() {
    let circuit = xark::prover::circuit_at(artifacts());
    circuit.check(WithdrawalInputs::example()).unwrap();
    let mut amount = WithdrawalInputs::example(); amount.public.amount += 1;
    let mut destination = WithdrawalInputs::example(); destination.public.destination_lo ^= 1;
    let mut opening = WithdrawalInputs::example(); opening.private.blinding += xark::Field::one();
    for input in [amount, destination, opening] { assert!(circuit.check(input).is_err()); }
}
#[test]
fn standalone_xark_proof_verifies_through_the_compressed_solana_abi() {
    let input = WithdrawalInputs::example();
    let payout = withdrawal::PublicInputs { commitment: to_bytes(&input.public.commitment), amount: input.public.amount, destination: input.public.destination() };
    let result = xark::prover::circuit_at(artifacts()).prove(input).unwrap();
    let compressed = proof::compressed_proof(&result.proof).unwrap();
    withdrawal::verify(&compressed, &payout).unwrap();
    let changed = withdrawal::PublicInputs { amount: payout.amount + 1, ..payout };
    assert!(withdrawal::verify(&compressed, &changed).is_err());
}
