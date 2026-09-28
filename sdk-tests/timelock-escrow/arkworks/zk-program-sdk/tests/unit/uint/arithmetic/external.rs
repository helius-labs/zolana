#![cfg(feature = "external-tools")]

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{result, witness, Add, CheckedAdd, CheckedMul, CheckedSub, Mul, Op, CLAIMED_WIRE},
    vectors::{edges, Edge},
};
use crate::{
    harness::{
        circom::Compiled,
        circomlib,
        equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
        field::decimal,
        fixture::{assignment, export, with_wires, Fixture, Size, Visit},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
    uint::rows::field,
};

pub fn compiled(name: &str) -> Compiled {
    circomlib::compile(&format!("uint/arithmetic/{name}.circom"))
}

/// (name with the true claim, name with a claim 1 too large, x, y)
const PAIRS: [(&str, &str, u64, u64); 9] = [
    ("0 and 0", "0 and 0, claim + 1", 0, 0),
    ("1 and 1", "1 and 1, claim + 1", 1, 1),
    ("3 and 5", "3 and 5, claim + 1", 3, 5),
    ("7 and 8", "7 and 8, claim + 1", 7, 8),
    ("8 and 8", "8 and 8, claim + 1", 8, 8),
    ("15 and 1", "15 and 1, claim + 1", 15, 1),
    ("1 and 15", "1 and 15, claim + 1", 1, 15),
    ("15 and 15", "15 and 15, claim + 1", 15, 15),
    ("16 and 0", "16 and 0, claim + 1", 16, 0),
];

fn fits_4(op: Op, x: u64, y: u64) -> bool {
    let fits = match op {
        Op::Add | Op::Mul => true,
        Op::CheckedAdd => x + y < 16,
        Op::CheckedMul => x * y < 16,
        Op::CheckedSub => x >= y,
    };
    x < 16 && y < 16 && fits
}

fn case<F>(
    name: &'static str,
    holds: bool,
    op: Op,
    bits: u32,
    (x, y, claimed): (Fr, Fr, Fr),
    make: &impl Fn(Field, Field, Field) -> F,
) -> Case<F> {
    Case {
        name,
        holds,
        fixture: make(field(x), field(y), field(claimed)),
        sdk_witness: if holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Explicit(witness(op, bits, x, y, claimed))
        },
        circom: vec![
            ("x", vec![decimal(field(x))]),
            ("y", vec![decimal(field(y))]),
            ("claimed", vec![decimal(field(claimed))]),
        ],
    }
}

fn cases_4<F>(op: Op, make: impl Fn(Field, Field, Field) -> F) -> Vec<Case<F>> {
    PAIRS
        .iter()
        .flat_map(|(honest, wrong, x, y)| {
            let (x_fr, y_fr) = (Fr::from(*x), Fr::from(*y));
            let claimed = result(op, x_fr, y_fr);
            let fits = fits_4(op, *x, *y);
            [
                case(honest, fits, op, 4, (x_fr, y_fr, claimed), &make),
                case(
                    wrong,
                    false,
                    op,
                    4,
                    (x_fr, y_fr, claimed + Fr::one()),
                    &make,
                ),
            ]
        })
        .collect()
}

fn cases_64<F>(op: Op, make: impl Fn(Field, Field, Field) -> F) -> Vec<Case<F>> {
    edges()
        .into_iter()
        .filter(|edge| edge.op == op && edge.bits == 64)
        .map(
            |Edge {
                 name, x, y, fits, ..
             }| { case(name, fits, op, 64, (x, y, result(op, x, y)), &make) },
        )
        .collect()
}

fn equivalent<F: ZkCircuit>(file: &str, cases: Vec<Case<F>>) -> (Size, Size) {
    let compiled = compiled(file);
    assert_relation_equivalent(&compiled, &cases);
    sizes::<F>(&compiled)
}

#[test]
fn every_4_bit_operation_is_relation_equivalent_to_its_circom_reference() {
    assert_eq!(
        [
            equivalent(
                "add_4",
                cases_4(Op::Add, |x, y, claimed| Add::<4, 5> { x, y, claimed })
            ),
            equivalent(
                "mul_4",
                cases_4(Op::Mul, |x, y, claimed| Mul::<4, 8> { x, y, claimed })
            ),
            equivalent(
                "checked_add_4",
                cases_4(Op::CheckedAdd, |x, y, claimed| CheckedAdd::<4> {
                    x,
                    y,
                    claimed
                })
            ),
            equivalent(
                "checked_mul_4",
                cases_4(Op::CheckedMul, |x, y, claimed| CheckedMul::<4> {
                    x,
                    y,
                    claimed
                })
            ),
            equivalent(
                "checked_sub_4",
                cases_4(Op::CheckedSub, |x, y, claimed| CheckedSub::<4> {
                    x,
                    y,
                    claimed
                })
            ),
        ],
        [
            (size(11, 12), size(13, 14)),
            (size(12, 13), size(14, 15)),
            (size(16, 16), size(19, 19)),
            (size(17, 17), size(20, 20)),
            (size(16, 16), size(19, 19)),
        ]
    );
}

#[test]
fn every_64_bit_checked_operation_is_relation_equivalent_at_its_edges() {
    assert_eq!(
        [
            equivalent(
                "checked_add_64",
                cases_64(Op::CheckedAdd, |x, y, claimed| CheckedAdd::<64> {
                    x,
                    y,
                    claimed
                })
            ),
            equivalent(
                "checked_mul_64",
                cases_64(Op::CheckedMul, |x, y, claimed| CheckedMul::<64> {
                    x,
                    y,
                    claimed
                })
            ),
            equivalent(
                "checked_sub_64",
                cases_64(Op::CheckedSub, |x, y, claimed| CheckedSub::<64> {
                    x,
                    y,
                    claimed
                })
            ),
        ],
        [
            (size(196, 196), size(199, 199)),
            (size(197, 197), size(200, 200)),
            (size(196, 196), size(199, 199)),
        ]
    );
}

fn size(constraints: usize, variables: usize) -> Size {
    Size {
        constraints,
        variables,
    }
}

struct Snarkjs<'a>(&'a WorkDir, &'a str);

impl Visit for Snarkjs<'_> {
    type Output = (WtnsCheck, WtnsCheck);

    fn visit<F: Fixture>(&self, fixture: &F) -> Self::Output {
        let r1cs = self.0.write(&format!("{}.r1cs", self.1), &export::<F>());
        let honest = assignment(fixture);
        let claimed = *honest.get(CLAIMED_WIRE).expect("claim");
        let tampered = with_wires(honest.clone(), &[(CLAIMED_WIRE, claimed + Fr::one())]);
        let honest = self
            .0
            .write(&format!("{}-honest.wtns", self.1), &write_wtns(&honest));
        let tampered = self
            .0
            .write(&format!("{}-tampered.wtns", self.1), &write_wtns(&tampered));
        (
            snarkjs::wtns_check(&r1cs, &honest),
            snarkjs::wtns_check(&r1cs, &tampered),
        )
    }
}

#[test]
fn snarkjs_accepts_every_fitting_wide_sdk_pair_and_rejects_a_tampered_claim() {
    let work = WorkDir::new("uint-arithmetic-wtns");
    let fitting = || edges().into_iter().filter(|edge| edge.fits);
    assert_eq!(
        fitting()
            .enumerate()
            .map(|(index, edge)| {
                let file = format!("edge-{index}");
                (edge.name, edge.visit(&Snarkjs(&work, &file)))
            })
            .collect::<Vec<_>>(),
        fitting()
            .map(|edge| (edge.name, (WtnsCheck::Accepted, WtnsCheck::Rejected)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_a_64_bit_checked_product() {
    let work = WorkDir::new("uint-arithmetic-groth16");
    let r1cs = work.write("sdk.r1cs", &export::<CheckedMul<64>>());
    let (x, y) = (
        Fr::from(u64::from(u32::MAX)),
        Fr::from(u64::from(u32::MAX) + 1),
    );
    let fixture = CheckedMul::<64> {
        x: field(x),
        y: field(y),
        claimed: field(x * y),
    };
    let wtns = work.write(
        "sdk.wtns",
        &fixture.export_assignment().expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}

#[test]
fn sum_matches_circom_and_snarkjs_accepts_only_the_true_claim() {
    use super::fixtures::Sum;
    let circuit = compiled("sum_4");
    let cases: Vec<_> = [[0u64, 0, 0], [1, 7, 15], [15, 15, 15]]
        .into_iter()
        .flat_map(|values| {
            let sum: u64 = values.iter().sum();
            let honest = Sum::<4, 6> {
                values: values.map(Field::from),
                claimed: sum.into(),
            };
            [false, true].map(|wrong| {
                let claimed = sum + u64::from(wrong);
                Case {
                    name: "sum",
                    holds: !wrong,
                    fixture: Sum::<4, 6> {
                        values: values.map(Field::from),
                        claimed: claimed.into(),
                    },
                    sdk_witness: SdkWitness::Tampered {
                        honest,
                        wires: vec![(4, Fr::from(claimed))],
                    },
                    circom: vec![
                        ("values", values.map(|v| v.to_string()).to_vec()),
                        ("claimed", vec![claimed.to_string()]),
                    ],
                }
            })
        })
        .collect();
    assert_relation_equivalent(&circuit, &cases);
    let work = WorkDir::new("uint-sum-snarkjs");
    let fixture = Sum::<4, 6> {
        values: [15u64.into(); 3],
        claimed: 45u64.into(),
    };
    let r1cs = work.write("sum.r1cs", &export::<Sum<4, 6>>());
    let honest = assignment(&fixture);
    let wrong = work.write(
        "wrong.wtns",
        &write_wtns(&with_wires(honest.clone(), &[(4, Fr::from(46u64))])),
    );
    let wtns = work.write("sum.wtns", &write_wtns(&honest));
    assert_eq!(snarkjs::wtns_check(&r1cs, &wrong), WtnsCheck::Rejected);
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
