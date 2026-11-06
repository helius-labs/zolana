use spr_program::{proof, to_bytes};
use spr_zk_standalone_fixture::{verifier::withdrawal, WithdrawalInputs};
use std::path::{Path, PathBuf};
fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/zk/spr-zk-standalone-fixture")
}

fn wasm_fixture() -> serde_json::Value {
    let input = WithdrawalInputs::example();
    let payout = withdrawal::PublicInputs {
        commitment: to_bytes(&input.public.commitment),
        amount: input.public.amount,
        destination: input.public.destination(),
    };
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
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../wasm/withdrawal.json")).unwrap();
    assert_eq!(wasm_fixture(), expected);
}

#[test]
#[ignore = "regenerates the synthetic standalone WASM fixture"]
fn write_standalone_wasm_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("wasm/withdrawal.json");
    std::fs::write(
        path,
        serde_json::to_string_pretty(&wasm_fixture()).unwrap() + "\n",
    )
    .unwrap();
}
#[test]
fn compiled_constraints_bind_the_note_and_each_public_payout_field() {
    let circuit = xark::prover::circuit_at(artifacts());
    circuit.check(WithdrawalInputs::example()).unwrap();
    let mut amount = WithdrawalInputs::example();
    amount.public.amount += 1;
    let mut destination = WithdrawalInputs::example();
    destination.public.destination_lo ^= 1;
    let mut opening = WithdrawalInputs::example();
    opening.private.blinding += xark::Field::one();
    let amount_site = site("require_eq(private.amount, public.amount);");
    let commitment = site("poseidon(&[");
    for (input, site) in [
        (amount, &amount_site),
        (destination, &commitment),
        (opening, &commitment),
    ] {
        let error = circuit
            .check(input)
            .expect_err("the circuit must refuse a changed payout")
            .to_string();
        assert!(error.contains(site.as_str()), "expected `{site}`: {error}");
    }
}

/// The `src/circuits.rs:<line>:` location of the `require_eq` whose statement
/// contains `needle`, read from the source so formatting cannot stale it.
fn site(needle: &str) -> String {
    let source = include_str!("../src/circuits.rs");
    let line = source
        .lines()
        .position(|line| line.contains(needle))
        .expect("the circuit source contains the requirement");
    let start = source
        .lines()
        .take(line + 1)
        .collect::<Vec<_>>()
        .iter()
        .rposition(|line| line.trim_start().starts_with("require_eq("))
        .expect("the requirement starts with require_eq");
    format!("src/circuits.rs:{}:", start + 1)
}
#[test]
fn standalone_xark_proof_verifies_through_the_compressed_solana_abi() {
    let input = WithdrawalInputs::example();
    let payout = withdrawal::PublicInputs {
        commitment: to_bytes(&input.public.commitment),
        amount: input.public.amount,
        destination: input.public.destination(),
    };
    let result = xark::prover::circuit_at(artifacts()).prove(input).unwrap();
    let compressed = proof::compressed_proof(&result.proof).unwrap();
    withdrawal::verify(&compressed, &payout).unwrap();
    let changed = withdrawal::PublicInputs {
        amount: payout.amount + 1,
        ..payout
    };
    assert_eq!(
        withdrawal::verify(&compressed, &changed),
        Err(spr_program::verifier::VerifyError::Proof)
    );
}
