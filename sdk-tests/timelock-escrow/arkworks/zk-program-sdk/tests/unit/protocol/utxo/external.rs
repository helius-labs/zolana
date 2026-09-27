#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use serde_json::json;
use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::{UtxoHash, CLAIM_WIRE},
    vectors::preimages,
};
use crate::harness::{
    fixture::{assignment, export, with_wires},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

#[test]
fn snarkjs_accepts_every_preimage_and_rejects_a_claimed_commitment_of_another() {
    let work = WorkDir::new("snarkjs-utxo-hash");
    let r1cs = work.write("utxo.r1cs", &export::<UtxoHash>());
    let preimages = preimages();
    let checked: Vec<_> = preimages
        .iter()
        .enumerate()
        .map(|(index, preimage)| {
            let fixture = UtxoHash {
                hash: preimage.hash(),
                utxo: preimage.wallet(),
            };
            let other = preimages[(index + 1) % preimages.len()].hash();
            let tampered = with_wires(assignment(&fixture), &[(CLAIM_WIRE, Fr::from(other))]);
            let honest = work.write(
                &format!("honest-{index}.wtns"),
                &fixture.export_assignment().expect("assignment"),
            );
            let tampered = work.write(&format!("tampered-{index}.wtns"), &write_wtns(&tampered));
            (
                preimage.name,
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &tampered),
            )
        })
        .collect();
    assert_eq!(
        checked,
        preimages
            .iter()
            .map(|preimage| (preimage.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_utxo_hash_circuit_for_a_data_utxo_in_a_ring() {
    let work = WorkDir::new("snarkjs-utxo-groth16");
    let preimage = &preimages()[3];
    let r1cs = work.write("utxo.r1cs", &export::<UtxoHash>());
    let wtns = work.write(
        "utxo.wtns",
        &UtxoHash {
            hash: preimage.hash(),
            utxo: preimage.wallet(),
        }
        .export_assignment()
        .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
