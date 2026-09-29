#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::ZkCircuit;

use super::{
    fixtures::Negated,
    vectors::{Vector, INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    circom::{self, Compiled},
    iden3::{read_r1cs, read_wtns, write_wtns},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

type Sdk = Negated<1>;

fn circom_neg() -> Compiled {
    circom::compile("circuit_var/neg/neg.circom")
}

fn sdk_r1cs() -> Vec<u8> {
    Sdk::export_r1cs().expect("r1cs export")
}

fn sdk_wtns(vector: &Vector) -> Vec<u8> {
    let (value, negation) = vector.fields();
    Sdk { value, negation }
        .export_assignment()
        .expect("assignment")
}

#[test]
fn circom_rows_normalize_to_the_sdk_rows_under_an_equal_header() {
    let (sdk, circom) = (read_r1cs(&sdk_r1cs()), circom_neg().read_r1cs());
    let one = Fr::one();
    let linear = vec![Constraint::Linear(vec![(1, one), (2, one)])];
    assert_eq!(
        (
            &sdk.header,
            &sdk.wire_labels,
            constraints(&sdk),
            constraints(&circom)
        ),
        (&circom.header, &circom.wire_labels, linear.clone(), linear)
    );
}

#[test]
fn circom_witnesses_equal_the_sdk_witnesses() {
    let circom = circom_neg();
    assert_eq!(
        VALID.map(|vector| (vector.name, circom.witness(&vector.inputs()))),
        VALID.map(|vector| (vector.name, Ok(read_wtns(&sdk_wtns(&vector)))))
    );
}

#[test]
fn circom_witness_calculation_fails_for_every_invalid_vector() {
    let circom = circom_neg();
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
    let compiled = circom_neg();
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
fn snarkjs_accepts_the_sdk_pair_and_rejects_a_tampered_witness() {
    let work = WorkDir::new("neg-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let honest = sdk_wtns(vector);
            let mut tampered = read_wtns(&honest);
            if let Some(negation) = tampered.last_mut() {
                *negation += Fr::one();
            }
            let honest = work.write(&format!("honest-{index}.wtns"), &honest);
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
        VALID
            .iter()
            .map(|vector| (vector.name, WtnsCheck::Accepted, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_accepts_both_cross_pairs() {
    let compiled = circom_neg();
    let work = WorkDir::new("neg-snarkjs-cross-pairs");
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
    let work = WorkDir::new("neg-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &sdk_r1cs());
    let wtns = work.write("sdk.wtns", &sdk_wtns(&VALID[6]));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
