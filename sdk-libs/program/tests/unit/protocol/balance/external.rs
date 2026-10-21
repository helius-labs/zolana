#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_transaction::Mint;

use super::{
    fixtures::{balance, Balance, TOKEN, TRANSFER, WITHDRAW},
    vectors::{TRANSFERS, WITHDRAWALS},
};
use crate::{
    harness::{
        fixture::{assignment, export, with_wires},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
    protocol::transaction::labels::allocated,
};

type Transfer = Balance<TOKEN, TOKEN, TRANSFER, true>;
type Withdraw = Balance<TOKEN, TOKEN, WITHDRAW, true>;

#[test]
fn snarkjs_accepts_every_honest_balance_pair_and_rejects_a_tampered_balance() {
    let work = WorkDir::new("balance-wtns");
    let r1cs = work.write("transfer.r1cs", &export::<Transfer>());
    let checked: Vec<_> = TRANSFERS
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let fixture = balance::<TOKEN, TOKEN, TRANSFER, true>(Mint::SOL, vector);
            let honest = assignment(&fixture);
            let wire = allocated(&fixture, "a field proof input")[0];
            let tampered = with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            (
                vector.name,
                snarkjs::wtns_check(
                    &r1cs,
                    &work.write(&format!("honest-{index}.wtns"), &write_wtns(&honest)),
                ),
                snarkjs::wtns_check(
                    &r1cs,
                    &work.write(&format!("tampered-{index}.wtns"), &write_wtns(&tampered)),
                ),
            )
        })
        .collect();
    assert_eq!(
        checked,
        TRANSFERS
            .iter()
            .map(|vector| (vector.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_withdrawal() {
    let work = WorkDir::new("balance-groth16");
    let r1cs = work.write("withdraw.r1cs", &export::<Withdraw>());
    let fixture = balance::<TOKEN, TOKEN, WITHDRAW, true>(Mint::SOL, &WITHDRAWALS[2]);
    let wtns = work.write("withdraw.wtns", &write_wtns(&assignment(&fixture)));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
