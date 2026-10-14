#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{honest, Inverse, CLAIMED_WIRE, INVERSE_WIRE},
    vectors::{Vector, INVALID, VALID, ZERO},
};
use crate::harness::{
    circom::{self, Compiled},
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export, with_wires, Size},
    iden3::{read_r1cs, write_wtns},
    normalize::{constraints, Constraint},
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

fn circom_inverse() -> Compiled {
    circom::compile("circuit_var/inverse/inverse.circom")
}

fn circom_inputs(x: Field, inverse: Field) -> Vec<(&'static str, Vec<String>)> {
    vec![("x", vec![decimal(x)]), ("inverse", vec![decimal(inverse)])]
}

fn case(vector: &Vector, holds: bool) -> Case<Inverse> {
    let (x, inverse) = vector.fields();
    let fixture = Inverse { x, inverse };
    let sdk_witness = match (holds, x == Field::from(0u64)) {
        (true, _) => SdkWitness::Assignment,
        (false, true) => {
            SdkWitness::Explicit(vec![Fr::one(), x.into(), inverse.into(), Fr::from(0u64)])
        }
        (false, false) => SdkWitness::Tampered {
            honest: honest(x),
            wires: vec![(CLAIMED_WIRE, inverse.into())],
        },
    };
    Case {
        name: vector.name,
        holds,
        fixture,
        sdk_witness,
        circom: circom_inputs(x, inverse),
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
    assert_relation_equivalent(&circom_inverse(), &cases);
}

#[test]
fn the_rows_normalize_equal_and_both_sizes_are_pinned() {
    let compiled = circom_inverse();
    let one = Fr::one();
    let rows = vec![
        Constraint::Linear(vec![(CLAIMED_WIRE, one), (INVERSE_WIRE, -one)]),
        Constraint::Quadratic {
            a: vec![(1, one)],
            b: vec![(INVERSE_WIRE, one)],
            c: vec![(0, one)],
        },
    ];
    let sdk = read_r1cs(&export::<Inverse>());
    assert_eq!(
        (
            compiled.wire("main.inv"),
            sizes::<Inverse>(&compiled),
            constraints(&sdk),
            constraints(&compiled.read_r1cs()),
        ),
        (
            INVERSE_WIRE,
            (
                Size {
                    constraints: 2,
                    variables: 4
                },
                Size {
                    constraints: 2,
                    variables: 4
                }
            ),
            rows.clone(),
            rows,
        )
    );
}

#[test]
fn circom_witnesses_equal_the_sdk_assignments() {
    let compiled = circom_inverse();
    assert_eq!(
        VALID.map(|vector| {
            let (x, inverse) = vector.fields();
            (
                vector.name,
                compiled.calculate(&circom_inputs(x, inverse), circom::Asserts::Abort),
            )
        }),
        VALID.map(|vector| {
            let (x, inverse) = vector.fields();
            (vector.name, Ok(assignment(&Inverse { x, inverse })))
        })
    );
}

#[test]
fn snarkjs_accepts_the_sdk_pair_and_rejects_each_tampered_wire() {
    let work = WorkDir::new("inverse-snarkjs-sdk-pair");
    let r1cs = work.write("sdk.r1cs", &export::<Inverse>());
    let checked: Vec<_> = VALID
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let (x, inverse) = vector.fields();
            let honest = assignment(&Inverse { x, inverse });
            let file = |label: &str, witness: &[Fr]| {
                work.write(&format!("{label}-{index}.wtns"), &write_wtns(witness))
            };
            let tampered =
                |wire: usize| with_wires(honest.clone(), &[(wire, honest[wire] + Fr::one())]);
            (
                vector.name,
                snarkjs::wtns_check(&r1cs, &file("honest", &honest)),
                snarkjs::wtns_check(&r1cs, &file("claimed", &tampered(CLAIMED_WIRE))),
                snarkjs::wtns_check(&r1cs, &file("inverse", &tampered(INVERSE_WIRE))),
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
fn snarkjs_rejects_a_zero_x_with_every_inverse_witness() {
    let work = WorkDir::new("inverse-snarkjs-zero");
    let r1cs = work.write("sdk.r1cs", &export::<Inverse>());
    let checked: Vec<_> = ZERO
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            let (x, inverse) = vector.fields();
            let witness = [Fr::one(), x.into(), inverse.into(), inverse.into()];
            let wtns = work.write(&format!("zero-{index}.wtns"), &write_wtns(&witness));
            (vector.name, snarkjs::wtns_check(&r1cs, &wtns))
        })
        .collect();
    assert_eq!(
        checked,
        ZERO.iter()
            .map(|vector| (vector.name, WtnsCheck::Rejected))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_the_sdk_circuit() {
    let work = WorkDir::new("inverse-snarkjs-groth16");
    let r1cs = work.write("sdk.r1cs", &export::<Inverse>());
    let (x, inverse) = VALID[6].fields();
    let wtns = work.write(
        "sdk.wtns",
        &Inverse { x, inverse }
            .export_assignment()
            .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
