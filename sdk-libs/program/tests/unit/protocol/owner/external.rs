#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use serde_json::json;
use zolana_program::ZkCircuit;

use super::{
    fixtures::{OwnerHash, CLAIM_WIRE},
    keys,
    vectors::keys,
};
use crate::{
    harness::{
        fixture::{assignment, export, with_wires},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
    protocol::asset::vectors::field_of,
};

#[test]
fn snarkjs_accepts_every_key_and_rejects_a_claimed_hash_of_another_key() {
    let work = WorkDir::new("snarkjs-owner-hash");
    let r1cs = work.write("owner.r1cs", &export::<OwnerHash>());
    let keys = keys();
    let checked: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let fixture = OwnerHash {
                hash: field_of(&key.native_hash()),
                owner: key.address,
            };
            let other = field_of(&keys[(index + 1) % keys.len()].native_hash());
            let tampered = with_wires(assignment(&fixture), &[(CLAIM_WIRE, Fr::from(other))]);
            let honest = work.write(
                &format!("honest-{index}.wtns"),
                &fixture.export_assignment().expect("assignment"),
            );
            let tampered = work.write(&format!("tampered-{index}.wtns"), &write_wtns(&tampered));
            (
                key.name,
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &tampered),
            )
        })
        .collect();
    assert_eq!(
        checked,
        keys.iter()
            .map(|key| (key.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_owner_hash_circuit_for_a_p256_key() {
    let work = WorkDir::new("snarkjs-owner-groth16");
    let key = keys::p256(7);
    let r1cs = work.write("owner.r1cs", &export::<OwnerHash>());
    let wtns = work.write(
        "owner.wtns",
        &OwnerHash {
            hash: field_of(&key.native_hash()),
            owner: key.address,
        }
        .export_assignment()
        .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
