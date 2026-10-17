#![cfg(feature = "external-tools")]
use super::fixtures::*;
use crate::{
    bytes::support::{decimals, fields, low_bits},
    harness::{
        circomlib,
        equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
        fixture::{assignment, with_wires},
        iden3::write_wtns,
        snarkjs::{self, WtnsCheck},
        WorkDir,
    },
};
use ark_bn254::Fr;
use serde_json::json;
use zolana_program::{circuit::Field, Bytes, ZkCircuit};
fn right_wires(bytes: &[u8; 32]) -> Vec<(usize, Fr)> {
    bytes
        .iter()
        .enumerate()
        .flat_map(|(index, byte)| {
            let wire = 289 + 9 * index;
            std::iter::once((wire, Fr::from(*byte))).chain((wire + 1..).zip(low_bits(*byte)))
        })
        .collect()
}
fn inputs(left: &[u8; 32], right: &[u8; 32]) -> Vec<(&'static str, Vec<String>)> {
    vec![("left", decimals(left)), ("right", decimals(right))]
}
fn verify<F: ZkCircuit>(name: &str, cases: Vec<Case<F>>, counts: (usize, usize, usize, usize)) {
    let compiled = circomlib::compile(&format!("bytes/ops/{name}.circom"));
    assert_relation_equivalent(&compiled, &cases);
    let (sdk, reference) = sizes::<F>(&compiled);
    assert_eq!(
        (
            sdk.constraints,
            sdk.variables,
            reference.constraints,
            reference.variables
        ),
        counts
    );
}
#[test]
fn equality_and_inequality_match_circomlib_across_the_chunk_boundary() {
    let mut equal = Vec::new();
    let mut not_equal = Vec::new();
    let mut is_equal = Vec::new();
    let mut conditional = Vec::new();
    for changed in [None, Some(0), Some(30), Some(31)] {
        let left = [3; 32];
        let mut right = left;
        if let Some(index) = changed {
            *right.get_mut(index).expect("byte") = 7;
        }
        let holds = left == right;
        equal.push(Case {
            name: "equal",
            holds,
            fixture: AssertEqual {
                left: Bytes(left),
                right: Bytes(right),
            },
            sdk_witness: SdkWitness::Tampered {
                honest: AssertEqual {
                    left: Bytes(left),
                    right: Bytes(left),
                },
                wires: right_wires(&right),
            },
            circom: inputs(&left, &right),
        });
        let mut reference = inputs(&left, &right);
        reference.push(("claimed", vec!["0".into()]));
        not_equal.push(Case {
            name: "not equal",
            holds: !holds,
            fixture: AssertNotEqual {
                left: Bytes(left),
                right: Bytes(right),
            },
            sdk_witness: if holds {
                SdkWitness::Tampered {
                    honest: AssertNotEqual {
                        left: Bytes(left),
                        right: Bytes([7; 32]),
                    },
                    wires: right_wires(&right),
                }
            } else {
                SdkWitness::Assignment
            },
            circom: reference,
        });
        for condition in [false, true] {
            let mut reference = inputs(&left, &right);
            reference.push(("condition", vec![u8::from(condition).to_string()]));
            conditional.push(Case {
                name: "conditional",
                holds: !condition || holds,
                fixture: AssertEqualIf {
                    left: Bytes(left),
                    right: Bytes(right),
                    condition,
                },
                sdk_witness: SdkWitness::Tampered {
                    honest: AssertEqualIf {
                        left: Bytes(left),
                        right: Bytes(right),
                        condition: false,
                    },
                    wires: vec![(577, Fr::from(u8::from(condition)))],
                },
                circom: reference,
            });
            let mut reference = inputs(&left, &right);
            reference.push(("claimed", vec![u8::from(condition).to_string()]));
            let honest = IsEqual {
                left: Bytes(left),
                right: Bytes(right),
                claimed: holds,
            };
            is_equal.push(Case {
                name: "equality claim",
                holds: condition == holds,
                fixture: IsEqual {
                    claimed: condition,
                    ..honest
                },
                sdk_witness: SdkWitness::Tampered {
                    honest,
                    wires: vec![(577, Fr::from(u8::from(condition)))],
                },
                circom: reference,
            });
        }
    }
    verify("equal", equal, (578, 577, 842, 841));
    verify("not_equal", not_equal, (583, 583, 858, 857));
    verify("is_equal", is_equal, (584, 584, 857, 857));
    verify("equal_if", conditional, (579, 578, 843, 842));
}
#[test]
fn selection_matches_circomlib_mux1_and_refuses_every_changed_byte() {
    let left = [3; 32];
    let right = [7; 32];
    let mut cases = Vec::new();
    for condition in [false, true] {
        let selected = if condition { left } else { right };
        let honest = Selected {
            condition,
            if_true: Bytes(left),
            if_false: Bytes(right),
            selected: fields(&selected),
        };
        for changed in std::iter::once(None).chain((0..32).map(Some)) {
            let mut selected = selected;
            if let Some(index) = changed {
                *selected.get_mut(index).expect("byte") = 8;
            }
            let mut reference = inputs(&left, &right);
            reference.push(("condition", vec![u8::from(condition).to_string()]));
            reference.push(("selected", decimals(&selected)));
            let wires = selected
                .iter()
                .enumerate()
                .map(|(i, b)| (578 + i, Fr::from(*b)))
                .collect();
            cases.push(Case {
                name: "selected",
                holds: changed.is_none(),
                fixture: Selected {
                    selected: fields(&selected),
                    ..honest
                },
                sdk_witness: SdkWitness::Tampered { honest, wires },
                circom: reference,
            });
        }
    }
    verify("select", cases, (641, 642, 1129, 1130));
}
#[test]
fn snarkjs_checks_and_proves_byte_selection() {
    let work = WorkDir::new("bytes-select-snarkjs");
    let fixture = Selected {
        condition: true,
        if_true: Bytes([3; 32]),
        if_false: Bytes([7; 32]),
        selected: [Field::from(3u64); 32],
    };
    let r1cs = work.write("select.r1cs", &Selected::<32>::export_r1cs().expect("r1cs"));
    let witness = assignment(&fixture);
    let honest = work.write("honest.wtns", &write_wtns(&witness));
    let wrong = work.write(
        "wrong.wtns",
        &write_wtns(&with_wires(witness, &[(609, Fr::from(7u64))])),
    );
    assert_eq!(
        (
            snarkjs::wtns_check(&r1cs, &honest),
            snarkjs::wtns_check(&r1cs, &wrong)
        ),
        (WtnsCheck::Accepted, WtnsCheck::Rejected)
    );
    assert_eq!(snarkjs::groth16(&work, &r1cs, &honest), (true, json!([])));
}

#[test]
fn snarkjs_accepts_assertion_witnesses_and_refuses_broken_relations() {
    fn check<F: ZkCircuit>(work: &WorkDir, name: &str, fixture: &F, wires: &[(usize, Fr)]) {
        let r1cs = work.write(&format!("{name}.r1cs"), &F::export_r1cs().expect("r1cs"));
        let witness = assignment(fixture);
        let honest = work.write(&format!("{name}.wtns"), &write_wtns(&witness));
        let wrong = work.write(
            &format!("{name}-wrong.wtns"),
            &write_wtns(&with_wires(witness, wires)),
        );
        assert_eq!(
            (
                snarkjs::wtns_check(&r1cs, &honest),
                snarkjs::wtns_check(&r1cs, &wrong)
            ),
            (WtnsCheck::Accepted, WtnsCheck::Rejected)
        );
    }
    let work = WorkDir::new("bytes-assert-snarkjs");
    let right = |byte| {
        std::iter::once((10, Fr::from(byte)))
            .chain((11..).zip(low_bits(byte)))
            .collect::<Vec<_>>()
    };
    check(
        &work,
        "equal",
        &AssertEqual {
            left: Bytes([3]),
            right: Bytes([3]),
        },
        &right(7),
    );
    check(
        &work,
        "not-equal",
        &AssertNotEqual {
            left: Bytes([3]),
            right: Bytes([7]),
        },
        &right(3),
    );
    check(
        &work,
        "equal-if",
        &AssertEqualIf {
            left: Bytes([3]),
            right: Bytes([7]),
            condition: false,
        },
        &[(19, Fr::from(1u64))],
    );
    check(
        &work,
        "is-equal",
        &IsEqual {
            left: Bytes([3]),
            right: Bytes([3]),
            claimed: true,
        },
        &[(19, Fr::from(0u64))],
    );
}
