#![cfg(feature = "external-tools")]

use std::time::Duration;

use ark_bn254::Fr;
use ark_ff::One;
use serde_json::json;
use zolana_program::{circuit::Field, ZkCircuit};

use super::{
    fixtures::Selected,
    vectors::{Branches, BRANCHES, CONDITIONS},
};
use crate::harness::{
    circomlib,
    equivalence::{assert_relation_equivalent, picus_verdicts, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export, with_wires, Size},
    iden3::write_wtns,
    picus::Verdict,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};

const SELECTED_WIRE: usize = 4;
const PICUS_LIMIT: Duration = Duration::from_secs(60);

type Sdk = Selected<0>;

fn named(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

fn fixture(branches: &Branches, condition: bool, selected: Field) -> Sdk {
    let (if_true, if_false) = branches.fields();
    Selected {
        condition,
        if_true,
        if_false,
        selected,
    }
}

fn case(branches: &Branches, condition: bool, selected: Field) -> Case<Sdk> {
    let honest = fixture(branches, condition, branches.chosen(condition));
    let holds = selected == honest.selected;
    Case {
        name: named(format!(
            "{} if {condition} selects {}",
            branches.name,
            decimal(selected)
        )),
        holds,
        fixture: fixture(branches, condition, selected),
        sdk_witness: if holds {
            SdkWitness::Assignment
        } else {
            SdkWitness::Tampered {
                honest,
                wires: vec![(SELECTED_WIRE, selected.into())],
            }
        },
        circom: [
            ("condition", Field::from(u64::from(condition))),
            ("if_true", branches.fields().0),
            ("if_false", branches.fields().1),
            ("selected", selected),
        ]
        .iter()
        .map(|(name, value)| (*name, vec![decimal(*value)]))
        .collect(),
    }
}

fn cases() -> Vec<Case<Sdk>> {
    let mut cases = vec![];
    for branches in &BRANCHES {
        for condition in CONDITIONS {
            let chosen = branches.chosen(condition);
            for selected in [
                chosen,
                branches.chosen(!condition),
                chosen + Field::from(1u64),
            ] {
                cases.push(case(branches, condition, selected));
            }
        }
    }
    cases
}

#[test]
fn select_is_relation_equivalent_to_circomlib_mux1_and_both_are_deterministic() {
    let compiled = circomlib::compile("ops/select/select.circom");
    let work = WorkDir::new("picus-mux1");
    assert_relation_equivalent(&compiled, &cases());
    let selected = compiled.wire("main.selected");
    assert_eq!(
        (
            sizes::<Sdk>(&compiled),
            picus_verdicts::<Sdk>(
                &work,
                "mux1",
                &[SELECTED_WIRE],
                &compiled,
                &[selected],
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
                    constraints: 10,
                    variables: 13,
                }
            ),
            (Verdict::Safe, Verdict::Safe)
        )
    );
}

#[test]
fn snarkjs_accepts_every_sdk_selection_and_rejects_a_tampered_one() {
    let work = WorkDir::new("snarkjs-select");
    let r1cs = work.write("sdk.r1cs", &export::<Sdk>());
    let mut checked = vec![];
    for (index, branches) in BRANCHES.iter().enumerate() {
        for condition in CONDITIONS {
            let honest = assignment(&fixture(branches, condition, branches.chosen(condition)));
            let tampered = with_wires(
                honest.clone(),
                &[(SELECTED_WIRE, honest[SELECTED_WIRE] + Fr::one())],
            );
            let file = |name: &str, witness: &[Fr]| {
                work.write(
                    &format!("{name}-{index}-{condition}.wtns"),
                    &write_wtns(witness),
                )
            };
            checked.push((
                branches.name,
                condition,
                snarkjs::wtns_check(&r1cs, &file("honest", &honest)),
                snarkjs::wtns_check(&r1cs, &file("tampered", &tampered)),
            ));
        }
    }
    let expected: Vec<_> = BRANCHES
        .iter()
        .flat_map(|branches| {
            CONDITIONS.map(|condition| {
                (
                    branches.name,
                    condition,
                    WtnsCheck::Accepted,
                    WtnsCheck::Rejected,
                )
            })
        })
        .collect();
    assert_eq!(checked, expected);
}

#[test]
fn snarkjs_proves_and_verifies_select() {
    let work = WorkDir::new("snarkjs-groth16-select");
    let r1cs = work.write("sdk.r1cs", &export::<Sdk>());
    let branches = &BRANCHES[6];
    let wtns = work.write(
        "sdk.wtns",
        &fixture(branches, true, branches.chosen(true))
            .export_assignment()
            .expect("assignment"),
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &wtns), (true, json!([])));
}
