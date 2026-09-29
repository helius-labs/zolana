#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::{Pow5, FIRST_WITNESS_WIRE, POWER_WIRE},
    vectors::{Vector, INVALID, VALID},
};
use crate::harness::{
    circom::{self, Compiled},
    fixture::with_wires,
    iden3::{read_r1cs, read_wtns, write_wtns, R1csHeader},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

fn circom_pow() -> Compiled {
    circom::compile("circuit_var/pow/pow.circom")
}

fn sdk_r1cs() -> Vec<u8> {
    Pow5::export_r1cs().expect("r1cs export")
}

fn sdk_witness(vector: &Vector) -> Vec<Fr> {
    let (x, power) = vector.fields();
    read_wtns(&Pow5 { x, power }.export_assignment().expect("assignment"))
}

#[test]
fn circom_rows_normalize_to_the_sdk_rows_over_the_same_wires() {
    let compiled = circom_pow();
    let (sdk, circom) = (read_r1cs(&sdk_r1cs()), compiled.read_r1cs());
    let one = Fr::one();
    let product = |a: usize, b: usize, c: usize| Constraint::Quadratic {
        a: vec![(a, one)],
        b: vec![(b, one)],
        c: vec![(c, one)],
    };
    let rows = vec![
        Constraint::Linear(vec![(POWER_WIRE, one), (5, -one)]),
        product(1, 1, 3),
        product(1, 4, 5),
        product(3, 3, 4),
    ];
    assert_eq!(
        (
            ["main.x2", "main.x4", "main.x5"].map(|signal| compiled.wire(signal)),
            &sdk.header,
            &circom.header,
            &sdk.wire_labels,
            constraints(&sdk),
            constraints(&circom),
        ),
        (
            [
                FIRST_WITNESS_WIRE,
                FIRST_WITNESS_WIRE + 1,
                FIRST_WITNESS_WIRE + 2
            ],
            &R1csHeader::bn254(6, 0, 5, 4),
            &R1csHeader::bn254(6, 0, 2, 4),
            &circom.wire_labels,
            rows.clone(),
            rows,
        )
    );
}

#[test]
fn circom_witnesses_equal_the_sdk_witnesses() {
    let circom = circom_pow();
    assert_eq!(
        VALID.map(|vector| (vector.name, circom.witness(&vector.inputs()))),
        VALID.map(|vector| (vector.name, Ok(sdk_witness(&vector))))
    );
}

#[test]
fn circom_witness_calculation_fails_for_every_invalid_vector() {
    let circom = circom_pow();
    assert_eq!(
        INVALID.map(|vector| (vector.name, circom.witness(&vector.inputs()).err())),
        INVALID.map(|vector| (vector.name, Some("Assert Failed".to_string())))
    );
}

#[test]
fn each_r1cs_accepts_the_others_witness() {
    let compiled = circom_pow();
    let (sdk, circom) = (read_r1cs(&sdk_r1cs()), compiled.read_r1cs());
    assert_eq!(
        VALID.map(|vector| {
            let circom_witness = compiled.witness(&vector.inputs()).expect("circom witness");
            (
                vector.name,
                circom.first_unsatisfied(&sdk_witness(&vector)),
                sdk.first_unsatisfied(&circom_witness),
            )
        }),
        VALID.map(|vector| (vector.name, None, None))
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire() {
    let work = WorkDir::new("pow-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let wires = [
        POWER_WIRE,
        FIRST_WITNESS_WIRE,
        FIRST_WITNESS_WIRE + 1,
        FIRST_WITNESS_WIRE + 2,
    ];
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let honest = sdk_witness(vector);
            let check = |label: String, witness: &[Fr]| {
                let wtns = work.write(&format!("{label}-{index}.wtns"), &write_wtns(witness));
                snarkjs::wtns_check(&r1cs, &wtns)
            };
            let tampered: Vec<_> = wires
                .iter()
                .map(|wire| {
                    let witness = with_wires(honest.clone(), &[(*wire, honest[*wire] + Fr::one())]);
                    check(format!("wire-{wire}"), &witness)
                })
                .collect();
            (vector.name, check("honest".to_string(), &honest), tampered)
        })
        .collect();
    assert_eq!(
        checked,
        VALID
            .iter()
            .map(|vector| (
                vector.name,
                WtnsCheck::Accepted,
                vec![WtnsCheck::Rejected; wires.len()]
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_accepts_the_sdk_r1cs_with_the_circom_witness() {
    let compiled = circom_pow();
    let work = WorkDir::new("pow-snarkjs-cross-pairs");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let circom_witness = compiled.witness(&vector.inputs()).expect("circom witness");
            let sdk_wtns = work.write(
                &format!("sdk-{index}.wtns"),
                &write_wtns(&sdk_witness(vector)),
            );
            let circom_wtns = work.write(
                &format!("circom-{index}.wtns"),
                &write_wtns(&circom_witness),
            );
            (
                vector.name,
                snarkjs::wtns_check(&compiled.r1cs, &sdk_wtns),
                snarkjs::wtns_check(&r1cs, &circom_wtns),
            )
        })
        .collect();
    assert_eq!(
        checked,
        VALID
            .iter()
            .map(|vector| (vector.name, WtnsCheck::Accepted, WtnsCheck::Accepted))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_sdk_circuit() {
    let work = WorkDir::new("pow-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let wtns = work.write("sdk.wtns", &write_wtns(&sdk_witness(&VALID[4])));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
