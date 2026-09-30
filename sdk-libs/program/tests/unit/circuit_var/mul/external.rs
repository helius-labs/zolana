#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::ZkCircuit;

use super::{
    fixtures::{Variables, CLAIMED_WIRE, WITNESS_WIRE},
    vectors::{Vector, INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    circom::{self, Compiled},
    iden3::{read_r1cs, read_wtns, write_wtns, R1csHeader},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

type Sdk = Variables<3>;

fn circom_mul() -> Compiled {
    circom::compile("circuit_var/mul/mul.circom")
}

fn sdk_r1cs() -> Vec<u8> {
    Sdk::export_r1cs().expect("r1cs export")
}

fn sdk_wtns(vector: &Vector) -> Vec<u8> {
    let (left, right, product) = vector.fields();
    Sdk {
        left,
        right,
        product,
    }
    .export_assignment()
    .expect("assignment")
}

#[test]
fn circom_rows_normalize_to_the_sdk_rows_over_the_same_wires() {
    let (sdk, circom) = (read_r1cs(&sdk_r1cs()), circom_mul().read_r1cs());
    let one = Fr::one();
    let rows = vec![
        Constraint::Linear(vec![(CLAIMED_WIRE, one), (WITNESS_WIRE, -one)]),
        Constraint::Quadratic {
            a: vec![(1, one)],
            b: vec![(2, one)],
            c: vec![(WITNESS_WIRE, one)],
        },
    ];
    assert_eq!(
        (
            &sdk.header,
            &circom.header,
            &sdk.wire_labels,
            constraints(&sdk),
            constraints(&circom)
        ),
        (
            &R1csHeader::bn254(5, 0, 4, 2),
            &R1csHeader::bn254(5, 0, 3, 2),
            &circom.wire_labels,
            rows.clone(),
            rows
        )
    );
}

#[test]
fn circom_witnesses_equal_the_sdk_witnesses() {
    let circom = circom_mul();
    assert_eq!(
        VALID.map(|vector| (vector.name, circom.witness(&vector.inputs()))),
        VALID.map(|vector| (vector.name, Ok(read_wtns(&sdk_wtns(&vector)))))
    );
}

#[test]
fn circom_witness_calculation_fails_for_every_invalid_vector() {
    let circom = circom_mul();
    let invalid = || INVALID.iter().chain([&NON_CANONICAL]);
    assert_eq!(
        invalid()
            .map(|vector| (vector.name, circom.witness(&vector.inputs()).err()))
            .collect::<Vec<_>>(),
        invalid()
            .map(|vector| (vector.name, Some("Assert Failed".to_string())))
            .collect::<Vec<_>>()
    );
}

#[test]
fn each_r1cs_accepts_the_others_witness() {
    let compiled = circom_mul();
    let (sdk, circom) = (read_r1cs(&sdk_r1cs()), compiled.read_r1cs());
    let accepted: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let circom_witness = compiled.witness(&vector.inputs()).expect("circom witness");
            (
                vector.name,
                circom.first_unsatisfied(&read_wtns(&sdk_wtns(vector))),
                sdk.first_unsatisfied(&circom_witness),
            )
        })
        .collect();
    assert_eq!(
        accepted,
        VALID
            .iter()
            .map(|vector| (vector.name, None, None))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire() {
    let work = WorkDir::new("mul-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let honest = sdk_wtns(vector);
            let tampered = |wire: usize| {
                let mut witness = read_wtns(&honest);
                witness[wire] += Fr::one();
                work.write(
                    &format!("tampered-{index}-{wire}.wtns"),
                    &write_wtns(&witness),
                )
            };
            let (claimed, computed) = (tampered(CLAIMED_WIRE), tampered(WITNESS_WIRE));
            let honest = work.write(&format!("honest-{index}.wtns"), &honest);
            (
                vector.name,
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &claimed),
                snarkjs::wtns_check(&r1cs, &computed),
            )
        })
        .collect();
    assert_eq!(
        checked,
        VALID
            .iter()
            .map(|vector| (
                vector.name,
                WtnsCheck::Accepted,
                WtnsCheck::Rejected,
                WtnsCheck::Rejected
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_accepts_both_cross_pairs() {
    let compiled = circom_mul();
    let work = WorkDir::new("mul-snarkjs-cross-pairs");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let circom_witness = compiled.witness(&vector.inputs()).expect("circom witness");
            let sdk_wtns = work.write(&format!("sdk-{index}.wtns"), &sdk_wtns(vector));
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
    let work = WorkDir::new("mul-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let wtns = work.write("sdk.wtns", &sdk_wtns(&VALID[7]));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
