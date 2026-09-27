#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use serde_json::json;
use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::{AssetHash, HASH_WIRE},
    vectors::MINTS,
};
use crate::harness::{
    fixture::{assignment, export, with_wires},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

#[test]
fn snarkjs_accepts_every_mint_and_rejects_a_claimed_hash_of_another_mint() {
    let work = WorkDir::new("snarkjs-asset-hash");
    let r1cs = work.write("asset.r1cs", &export::<AssetHash>());
    let checked: Vec<_> = MINTS
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let fixture = AssetHash {
                hash: vector.hash(),
                mint: vector.mint,
            };
            let other = MINTS[(index + 1) % MINTS.len()].hash();
            let tampered = with_wires(assignment(&fixture), &[(HASH_WIRE, Fr::from(other))]);
            let honest = work.write(
                &format!("honest-{index}.wtns"),
                &fixture.export_assignment().expect("assignment"),
            );
            let tampered = work.write(&format!("tampered-{index}.wtns"), &write_wtns(&tampered));
            (
                vector.name,
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &tampered),
            )
        })
        .collect();
    assert_eq!(
        checked,
        MINTS
            .iter()
            .map(|vector| (vector.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_asset_hash_circuit() {
    let work = WorkDir::new("snarkjs-asset-groth16");
    let vector = &MINTS[3];
    let r1cs = work.write("asset.r1cs", &export::<AssetHash>());
    let wtns = work.write(
        "asset.wtns",
        &AssetHash {
            hash: vector.hash(),
            mint: vector.mint,
        }
        .export_assignment()
        .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
