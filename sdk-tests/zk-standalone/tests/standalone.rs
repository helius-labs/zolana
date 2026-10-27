use zolana_zk_standalone_fixture::{WithdrawalInputs, verifier::withdrawal};
use zolana_program::{proof, to_bytes};
use std::path::{Path, PathBuf};
fn artifacts() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/zk/zolana-zk-standalone-fixture") }
#[test]
fn native_inputs_round_trip_through_the_xark_codec() {
    let input = WithdrawalInputs::example();
    let json = xark::client::to_json(&input.public).unwrap();
    let back: zolana_zk_standalone_fixture::Payout = xark::client::from_json(&json).unwrap();
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
