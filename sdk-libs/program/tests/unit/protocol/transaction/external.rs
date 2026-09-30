#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::ZkCircuit;

use super::{
    fixtures::{Asserted, Refresh},
    labels::allocated,
    vectors::{funds, payments, refreshes, settles},
};
use crate::harness::{
    fixture::{assignment, export, with_wires},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

#[test]
fn snarkjs_accepts_every_honest_refresh_and_rejects_each_tampered_hash_claim() {
    let work = WorkDir::new("transaction-wtns");
    let r1cs = work.write("refresh.r1cs", &export::<Asserted<Refresh>>());
    let checked: Vec<_> = refreshes()
        .into_iter()
        .enumerate()
        .map(|(index, (name, program))| {
            let fixture = Asserted::honest(program);
            let honest = assignment(&fixture);
            let check = |label: String, witness: &[Fr]| {
                let wtns = work.write(&format!("{label}-{index}.wtns"), &write_wtns(witness));
                snarkjs::wtns_check(&r1cs, &wtns)
            };
            let tampered: Vec<_> = allocated(&fixture, "a field proof input")
                .into_iter()
                .map(|wire| {
                    let witness = with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
                    check(format!("claim-{wire}"), &witness)
                })
                .collect();
            (name, check("honest".to_string(), &honest), tampered)
        })
        .collect();
    assert_eq!(
        checked,
        refreshes()
            .into_iter()
            .map(|(name, _)| (name, WtnsCheck::Accepted, vec![WtnsCheck::Rejected; 3]))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_whole_refresh() {
    let work = WorkDir::new("transaction-groth16");
    let r1cs = work.write("refresh.r1cs", &export::<Asserted<Refresh>>());
    let fixture = Asserted::honest(refreshes().swap_remove(1).1);
    let wtns = work.write("refresh.wtns", &write_wtns(&assignment(&fixture)));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}

fn prove_and_tamper<F: ZkCircuit>(name: &str, fixture: F) {
    let work = WorkDir::new(name);
    let r1cs = work.write("transaction.r1cs", &export::<F>());
    let honest = assignment(&fixture);
    let wtns = work.write("honest.wtns", &write_wtns(&honest));
    assert_eq!(snarkjs::wtns_check(&r1cs, &wtns), WtnsCheck::Accepted);
    let claims = allocated(&fixture, "a field proof input");
    assert_eq!(
        claims.len(),
        3,
        "private transaction, transaction and public hash claims"
    );
    for wire in claims {
        let changed = *honest.get(wire).expect("hash claim") + Fr::one();
        let witness = with_wires(honest.clone(), &[(wire, changed)]);
        let tampered = work.write("tampered.wtns", &write_wtns(&witness));
        assert_eq!(snarkjs::wtns_check(&r1cs, &tampered), WtnsCheck::Rejected);
    }
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}

#[test]
fn snarkjs_proves_a_payment_with_dummy_padding_and_rejects_changed_hashes() {
    let (_, program) = payments().into_iter().next().expect("payment vector");
    prove_and_tamper("transaction-payment", Asserted::honest(program));
}

#[test]
fn snarkjs_proves_a_data_utxo_update_and_rejects_changed_hashes() {
    let (_, program) = funds().into_iter().next().expect("funding vector");
    prove_and_tamper("transaction-data-update", Asserted::honest(program));
}

#[test]
fn snarkjs_proves_public_deposit_and_withdrawal_and_rejects_changed_hashes() {
    let (_, program) = settles().into_iter().next().expect("settlement vector");
    prove_and_tamper("transaction-settlement", Asserted::honest(program));
}
