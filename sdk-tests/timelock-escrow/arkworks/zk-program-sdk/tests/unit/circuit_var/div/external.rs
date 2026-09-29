#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{honest, Div, INVERSE_WIRE, PRODUCT_WIRE, QUOTIENT_WIRE},
    vectors::{Vector, INVALID, VALID, ZERO},
};
use crate::harness::{
    circom::{self, Asserts, Compiled},
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export, with_wires, Size},
    iden3::{read_r1cs, write_wtns},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

fn circom_div() -> Compiled {
    circom::compile("circuit_var/div/div.circom")
}

fn circom_inputs(vector: &Vector) -> Vec<(&'static str, Vec<String>)> {
    let (dividend, divisor, quotient) = vector.fields();
    vec![
        ("dividend", vec![decimal(dividend)]),
        ("divisor", vec![decimal(divisor)]),
        ("quotient", vec![decimal(quotient)]),
    ]
}

fn case(vector: &Vector, holds: bool) -> Case<Div> {
    let (dividend, divisor, quotient) = vector.fields();
    let sdk_witness = match (holds, divisor == Field::from(0u64)) {
        (true, _) => SdkWitness::Assignment,
        (false, true) => SdkWitness::Explicit(vec![
            Fr::one(),
            dividend.into(),
            divisor.into(),
            quotient.into(),
            Fr::from(0u64),
            quotient.into(),
        ]),
        (false, false) => SdkWitness::Tampered {
            honest: honest(dividend, divisor),
            wires: vec![(QUOTIENT_WIRE, quotient.into())],
        },
    };
    Case {
        name: vector.name,
        holds,
        fixture: Div {
            dividend,
            divisor,
            quotient,
        },
        sdk_witness,
        circom: circom_inputs(vector),
    }
}

#[test]
fn circom_accepts_exactly_the_cases_the_sdk_accepts() {
    let cases: Vec<_> = VALID
        .iter()
        .map(|vector| case(vector, true))
        .chain(
            INVALID
                .iter()
                .chain(&ZERO)
                .map(|vector| case(vector, false)),
        )
        .collect();
    assert_relation_equivalent(&circom_div(), &cases);
}

#[test]
fn the_rows_normalize_equal_and_both_sizes_are_pinned() {
    let compiled = circom_div();
    let one = Fr::one();
    let rows = vec![
        Constraint::Linear(vec![(QUOTIENT_WIRE, one), (PRODUCT_WIRE, -one)]),
        Constraint::Quadratic {
            a: vec![(1, one)],
            b: vec![(INVERSE_WIRE, one)],
            c: vec![(PRODUCT_WIRE, one)],
        },
        Constraint::Quadratic {
            a: vec![(2, one)],
            b: vec![(INVERSE_WIRE, one)],
            c: vec![(0, one)],
        },
    ];
    let mut sorted = rows.clone();
    sorted.sort();
    assert_eq!(
        (
            [compiled.wire("main.inv"), compiled.wire("main.product")],
            sizes::<Div>(&compiled),
            constraints(&read_r1cs(&export::<Div>())),
            constraints(&compiled.read_r1cs()),
        ),
        (
            [INVERSE_WIRE, PRODUCT_WIRE],
            (
                Size {
                    constraints: 3,
                    variables: 6
                },
                Size {
                    constraints: 3,
                    variables: 6
                }
            ),
            sorted.clone(),
            sorted,
        )
    );
}

#[test]
fn circom_witnesses_equal_the_sdk_assignments() {
    let compiled = circom_div();
    assert_eq!(
        VALID.map(|vector| (
            vector.name,
            compiled.calculate(&circom_inputs(&vector), Asserts::Abort)
        )),
        VALID.map(|vector| {
            let (dividend, divisor, _) = vector.fields();
            (vector.name, Ok(assignment(&honest(dividend, divisor))))
        })
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire() {
    let work = WorkDir::new("div-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &export::<Div>());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let (dividend, divisor, _) = vector.fields();
            let honest = assignment(&honest(dividend, divisor));
            let check = |label: &str, witness: &[Fr]| {
                let wtns = work.write(&format!("{label}-{index}.wtns"), &write_wtns(witness));
                snarkjs::wtns_check(&r1cs, &wtns)
            };
            let tampered =
                |wire: usize| with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            (
                vector.name,
                [
                    check("honest", &honest),
                    check("quotient", &tampered(QUOTIENT_WIRE)),
                    check("inverse", &tampered(INVERSE_WIRE)),
                    check("product", &tampered(PRODUCT_WIRE)),
                ],
            )
        })
        .collect();
    assert_eq!(
        checked,
        VALID
            .iter()
            .map(|vector| (
                vector.name,
                [
                    WtnsCheck::Accepted,
                    WtnsCheck::Rejected,
                    WtnsCheck::Rejected,
                    WtnsCheck::Rejected
                ]
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_sdk_circuit() {
    let work = WorkDir::new("div-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &export::<Div>());
    let (dividend, divisor, _) = VALID[6].fields();
    let wtns = work.write(
        "sdk.wtns",
        &honest(dividend, divisor)
            .export_assignment()
            .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
