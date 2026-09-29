#![cfg(feature = "external-tools")]

use std::time::Duration;

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zk_program_sdk::{circuit::Field, ZkCircuit};

use super::{
    fixtures::{AssertEqualIf, AssertNotEqual, IsEqual},
    vectors::{Pair, DIFFERENT, EQUAL},
};
use crate::harness::{
    circom::{self, Asserts, Compiled},
    circomlib,
    equivalence::{assert_relation_equivalent, picus_verdicts, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export, exported, with_wires, Size},
    iden3::{read_wtns, write_wtns},
    normalize::{constraints, Constraint},
    picus::Verdict,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

const CLAIMED_WIRE: usize = 3;
const CONDITION_WIRE: usize = 3;
const RIGHT_WIRE: usize = 2;
const PICUS_LIMIT: Duration = Duration::from_secs(60);

fn circom_not_equal() -> Compiled {
    circom::compile("ops/assert/assert_not_equal.circom")
}

fn inputs(pair: &Pair) -> [(&'static str, &'static str); 2] {
    [("left", pair.left), ("right", pair.right)]
}

fn not_equal_wtns(pair: &Pair) -> Vec<u8> {
    let (left, right) = pair.fields();
    AssertNotEqual { left, right }
        .export_assignment()
        .expect("assignment")
}

fn signals(pairs: &[(&'static str, Field)]) -> Vec<(&'static str, Vec<String>)> {
    pairs
        .iter()
        .map(|(name, value)| (*name, vec![decimal(*value)]))
        .collect()
}

#[test]
fn the_assert_not_equal_reference_normalizes_to_the_sdk_row_over_the_same_variables() {
    let (sdk, circom) = (exported::<AssertNotEqual>(), circom_not_equal().read_r1cs());
    let one = Fr::one();
    let row = vec![Constraint::Quadratic {
        a: vec![(1, one), (2, -one)],
        b: vec![(3, one)],
        c: vec![(0, one)],
    }];
    assert_eq!(
        (
            (
                sdk.header.variables,
                sdk.header.private_inputs,
                sdk.header.constraints
            ),
            (
                circom.header.variables,
                circom.header.private_inputs,
                circom.header.constraints
            ),
            constraints(&sdk),
            constraints(&circom),
        ),
        ((4, 3, 1), (4, 2, 1), row.clone(), row)
    );
}

#[test]
fn the_circom_inverse_witness_equals_the_sdk_assignment() {
    let circom = circom_not_equal();
    assert_eq!(
        DIFFERENT.map(|pair| (pair.name, circom.witness(&inputs(&pair)))),
        DIFFERENT.map(|pair| (pair.name, Ok(read_wtns(&not_equal_wtns(&pair)))))
    );
}

#[test]
fn circom_witness_calculation_fails_for_every_equal_pair() {
    let circom = circom_not_equal();
    assert_eq!(
        EQUAL.map(|pair| (pair.name, circom.witness(&inputs(&pair)).err())),
        EQUAL.map(|pair| (pair.name, Some("Assert Failed".to_string())))
    );
}

#[test]
fn each_assert_not_equal_r1cs_accepts_the_others_witness() {
    let compiled = circom_not_equal();
    let (sdk, circom) = (exported::<AssertNotEqual>(), compiled.read_r1cs());
    assert_eq!(
        DIFFERENT.map(|pair| {
            let circom_witness = compiled.witness(&inputs(&pair)).expect("circom witness");
            (
                pair.name,
                circom.first_unsatisfied(&read_wtns(&not_equal_wtns(&pair))),
                sdk.first_unsatisfied(&circom_witness),
            )
        }),
        DIFFERENT.map(|pair| (pair.name, None, None))
    );
}

fn tampered_last(wtns: &[u8]) -> Vec<u8> {
    let mut witness = read_wtns(wtns);
    if let Some(last) = witness.last_mut() {
        *last += Fr::one();
    }
    write_wtns(&witness)
}

#[test]
fn snarkjs_accepts_the_sdk_assert_not_equal_pair_and_both_cross_pairs() {
    let compiled = circom_not_equal();
    let work = WorkDir::new("snarkjs-assert-not-equal");
    let r1cs = work.write("sdk.r1cs", &export::<AssertNotEqual>());
    let checked: Vec<_> = DIFFERENT
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let honest = not_equal_wtns(pair);
            let circom_witness = compiled.witness(&inputs(pair)).expect("circom witness");
            let tampered = work.write(&format!("tampered-{index}.wtns"), &tampered_last(&honest));
            let honest = work.write(&format!("honest-{index}.wtns"), &honest);
            let circom_wtns = work.write(
                &format!("circom-{index}.wtns"),
                &write_wtns(&circom_witness),
            );
            (
                pair.name,
                [
                    snarkjs::wtns_check(&r1cs, &honest),
                    snarkjs::wtns_check(&r1cs, &tampered),
                    snarkjs::wtns_check(&compiled.r1cs, &honest),
                    snarkjs::wtns_check(&r1cs, &circom_wtns),
                ],
            )
        })
        .collect();
    assert_eq!(
        checked,
        DIFFERENT
            .iter()
            .map(|pair| (
                pair.name,
                [
                    WtnsCheck::Accepted,
                    WtnsCheck::Rejected,
                    WtnsCheck::Accepted,
                    WtnsCheck::Accepted
                ]
            ))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snarkjs_proves_and_verifies_assert_not_equal() {
    let work = WorkDir::new("snarkjs-groth16-assert-not-equal");
    let r1cs = work.write("sdk.r1cs", &export::<AssertNotEqual>());
    let wtns = work.write("sdk.wtns", &not_equal_wtns(&DIFFERENT[5]));
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}

fn named(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

fn is_equal_case(pair: &Pair, equal: bool, claimed: Field) -> Case<IsEqual> {
    let (left, right) = pair.fields();
    let honest = IsEqual {
        left,
        right,
        claimed: Field::from(u64::from(equal)),
    };
    let holds = claimed == honest.claimed;
    Case {
        name: named(format!("{} claims {}", pair.name, decimal(claimed))),
        holds,
        fixture: IsEqual {
            left,
            right,
            claimed,
        },
        sdk_witness: if holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Explicit(with_wires(
                assignment(&honest),
                &[(CLAIMED_WIRE, claimed.into())],
            ))
        },
        circom: signals(&[("left", left), ("right", right), ("claimed", claimed)]),
    }
}

fn is_equal_cases() -> Vec<Case<IsEqual>> {
    let (zero, one, two) = (Field::from(0u64), Field::from(1u64), Field::from(2u64));
    let mut cases = vec![];
    for (pairs, equal) in [(&EQUAL[..], true), (&DIFFERENT[..], false)] {
        for pair in pairs {
            for claimed in [zero, one, two] {
                cases.push(is_equal_case(pair, equal, claimed));
            }
        }
    }
    cases
}

#[test]
fn is_equal_is_relation_equivalent_to_circomlib_is_equal_and_both_are_deterministic() {
    let compiled = circomlib::compile("ops/assert/is_equal.circom");
    let work = WorkDir::new("picus-is-equal");
    assert_relation_equivalent(&compiled, &is_equal_cases());
    let claimed = compiled.wire("main.claimed");
    assert_eq!(
        (
            sizes::<IsEqual>(&compiled),
            picus_verdicts::<IsEqual>(
                &work,
                "is-equal",
                &[CLAIMED_WIRE],
                &compiled,
                &[claimed],
                PICUS_LIMIT,
            ),
        ),
        (
            (
                Size {
                    constraints: 3,
                    variables: 6,
                },
                Size {
                    constraints: 7,
                    variables: 10,
                }
            ),
            (Verdict::Safe, Verdict::Safe)
        )
    );
}

fn equal_if_case(pair: &Pair, equal: bool, condition: bool) -> Case<AssertEqualIf> {
    let (left, right) = pair.fields();
    let holds = equal || !condition;
    Case {
        name: named(format!("{} if {condition}", pair.name)),
        holds,
        fixture: AssertEqualIf {
            left,
            right,
            condition,
        },
        sdk_witness: if holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Tampered {
                honest: AssertEqualIf {
                    left,
                    right,
                    condition: false,
                },
                wires: vec![(CONDITION_WIRE, Fr::one())],
            }
        },
        circom: signals(&[
            ("left", left),
            ("right", right),
            ("condition", Field::from(u64::from(condition))),
        ]),
    }
}

fn equal_if_cases() -> Vec<Case<AssertEqualIf>> {
    let mut cases = vec![];
    for (pairs, equal) in [(&EQUAL[..], true), (&DIFFERENT[..], false)] {
        for pair in pairs {
            for condition in [false, true] {
                cases.push(equal_if_case(pair, equal, condition));
            }
        }
    }
    cases
}

#[test]
fn assert_equal_if_is_relation_equivalent_to_force_equal_if_enabled_and_neither_binds_right() {
    let compiled = circomlib::compile("ops/assert/force_equal_if_enabled.circom");
    let work = WorkDir::new("picus-force-equal-if-enabled");
    assert_relation_equivalent(&compiled, &equal_if_cases());
    let right = compiled.wire("main.right");
    assert_eq!(
        (
            sizes::<AssertEqualIf>(&compiled),
            picus_verdicts::<AssertEqualIf>(
                &work,
                "force-equal-if-enabled",
                &[RIGHT_WIRE],
                &compiled,
                &[right],
                PICUS_LIMIT,
            ),
        ),
        (
            (
                Size {
                    constraints: 2,
                    variables: 4,
                },
                Size {
                    constraints: 8,
                    variables: 10,
                }
            ),
            (Verdict::Unsafe, Verdict::Unsafe)
        )
    );
}

#[test]
fn both_assert_equal_if_circuits_refuse_a_condition_of_two() {
    let compiled = circomlib::compile("ops/assert/force_equal_if_enabled.circom");
    let two = Field::from(2u64);
    let refused = EQUAL.map(|pair| {
        let (left, right) = pair.fields();
        let honest = assignment(&AssertEqualIf {
            left,
            right,
            condition: false,
        });
        let circom = signals(&[("left", left), ("right", right), ("condition", two)]);
        (
            pair.name,
            exported::<AssertEqualIf>()
                .first_unsatisfied(&with_wires(honest, &[(CONDITION_WIRE, two.into())])),
            compiled.calculate(&circom, Asserts::Abort).err(),
        )
    });
    assert_eq!(
        refused,
        EQUAL.map(|pair| (pair.name, Some(0), Some("Assert Failed".to_string())))
    );
}

#[test]
fn snarkjs_accepts_the_sdk_equality_pairs_and_rejects_a_tampered_claim() {
    let work = WorkDir::new("snarkjs-is-equal");
    let is_equal = work.write("is-equal.r1cs", &export::<IsEqual>());
    let equal_if = work.write("equal-if.r1cs", &export::<AssertEqualIf>());
    let checked: Vec<_> = DIFFERENT
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let (left, right) = pair.fields();
            let claim = assignment(&IsEqual {
                left,
                right,
                claimed: Field::from(0u64),
            });
            let flipped = with_wires(claim.clone(), &[(CLAIMED_WIRE, Fr::one())]);
            let conditional = assignment(&AssertEqualIf {
                left,
                right,
                condition: false,
            });
            let forced = with_wires(conditional.clone(), &[(CONDITION_WIRE, Fr::one())]);
            let file = |name: &str, witness: &[Fr]| {
                work.write(&format!("{name}-{index}.wtns"), &write_wtns(witness))
            };
            (
                pair.name,
                [
                    snarkjs::wtns_check(&is_equal, &file("claim", &claim)),
                    snarkjs::wtns_check(&is_equal, &file("flipped", &flipped)),
                    snarkjs::wtns_check(&equal_if, &file("conditional", &conditional)),
                    snarkjs::wtns_check(&equal_if, &file("forced", &forced)),
                ],
            )
        })
        .collect();
    assert_eq!(
        checked,
        DIFFERENT
            .iter()
            .map(|pair| (
                pair.name,
                [
                    WtnsCheck::Accepted,
                    WtnsCheck::Rejected,
                    WtnsCheck::Accepted,
                    WtnsCheck::Rejected
                ]
            ))
            .collect::<Vec<_>>()
    );
}
