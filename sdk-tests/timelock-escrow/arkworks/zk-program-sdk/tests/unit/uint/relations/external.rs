#![cfg(feature = "external-tools")]
use super::fixtures::*;
use crate::harness::{
    circom::Compiled,
    circomlib,
    equivalence::{assert_relation_equivalent, sizes, Case, SdkWitness},
    field::decimal,
    fixture::{assignment, export, with_wires},
    iden3::write_wtns,
    snarkjs::{self, WtnsCheck},
    WorkDir,
};
use ark_bn254::Fr;
use ark_ff::One;
use zk_program_sdk::ZkCircuit;

pub fn compiled(name: &str) -> Compiled {
    circomlib::compile(&format!("uint/relations/{name}.circom"))
}

fn compare_cases<const BITS: u32, const OP: u8>() -> Vec<Case<Compare<BITS, OP>>> {
    [(0, 0), (1, 0), (0, 1), (15, 15), (7, 8)]
        .into_iter()
        .flat_map(|(x, y)| {
            let honest = compare::<BITS, OP>(x, y);
            [false, true].map(|wrong| {
                let mut fixture = honest.clone();
                let claim = assignment(&honest).get(3).copied().expect("claim")
                    + Fr::from(u64::from(wrong));
                fixture.claimed = claim.into();
                Case {
                    name: if wrong { "false claim" } else { "honest claim" },
                    holds: !wrong,
                    fixture,
                    sdk_witness: SdkWitness::Tampered {
                        honest: honest.clone(),
                        wires: vec![(3, claim)],
                    },
                    circom: vec![
                        ("x", vec![x.to_string()]),
                        ("y", vec![y.to_string()]),
                        ("claimed", vec![decimal(claim.into())]),
                    ],
                }
            })
        })
        .collect()
}

fn comparisons<const BITS: u32, const OP: u8>() -> (usize, usize) {
    let circuit = compiled(&format!("compare_{BITS}_{OP}"));
    assert_relation_equivalent(&circuit, &compare_cases::<BITS, OP>());
    let (sdk, circom) = sizes::<Compare<BITS, OP>>(&circuit);
    (sdk.constraints, circom.constraints)
}

#[test]
fn comparisons_min_max_and_equality_match_circomlib_with_pinned_counts() {
    assert_eq!(
        [
            comparisons::<4, 0>(),
            comparisons::<4, 1>(),
            comparisons::<4, 2>(),
            comparisons::<4, 3>(),
            comparisons::<4, 4>(),
            comparisons::<4, 5>(),
            comparisons::<64, 0>(),
            comparisons::<64, 1>(),
            comparisons::<252, 0>(),
            comparisons::<252, 1>(),
        ],
        [
            (17, 23),
            (17, 26),
            (18, 23),
            (18, 26),
            (267, 19),
            (13, 19),
            (197, 203),
            (197, 206),
            (761, 767),
            (761, 770)
        ]
    );
}

#[test]
fn division_matches_the_bounded_integer_relation_in_circom() {
    let circuit = compiled("division_4");
    let cases: Vec<_> = [(0, 1), (15, 1), (15, 4), (15, 15)]
        .into_iter()
        .flat_map(|(x, d)| {
            let honest = division::<4, 4, 4>(x, d);
            [0, 1, 2].map(|tamper| {
                let mut fixture = honest.clone();
                let q = x / d + u128::from(tamper == 1);
                let r = x % d + u128::from(tamper == 2);
                fixture.quotient = q.into();
                fixture.remainder = r.into();
                Case {
                    name: "division",
                    holds: tamper == 0,
                    fixture,
                    sdk_witness: SdkWitness::Tampered {
                        honest: honest.clone(),
                        wires: vec![(3, Fr::from(q)), (4, Fr::from(r))],
                    },
                    circom: vec![
                        ("x", vec![x.to_string()]),
                        ("divisor", vec![d.to_string()]),
                        ("quotient", vec![q.to_string()]),
                        ("remainder", vec![r.to_string()]),
                    ],
                }
            })
        })
        .collect();
    assert_relation_equivalent(&circuit, &cases);
    assert_eq!(sizes::<Division<4, 4, 4>>(&circuit).0.constraints, 28);
}

#[test]
fn selection_and_zero_match_mux1_and_iszero() {
    let selection = compiled("selection_4");
    for condition in [false, true] {
        let selected = if condition { 5u64 } else { 9u64 };
        let honest = Selection::<4> {
            x: 5u64.into(),
            y: 9u64.into(),
            condition,
            claimed: selected.into(),
        };
        let cases = [false, true].map(|wrong| {
            let claim = selected + u64::from(wrong);
            let mut fixture = honest.clone();
            fixture.claimed = claim.into();
            Case {
                name: "select",
                holds: !wrong,
                fixture,
                sdk_witness: SdkWitness::Tampered {
                    honest: honest.clone(),
                    wires: vec![(4, Fr::from(claim))],
                },
                circom: vec![
                    ("x", vec!["5".into()]),
                    ("y", vec!["9".into()]),
                    ("condition", vec![u64::from(condition).to_string()]),
                    ("claimed", vec![claim.to_string()]),
                ],
            }
        });
        assert_relation_equivalent(&selection, &cases);
    }
    let zero = compiled("zero_4");
    for x in [0u64, 1, 15] {
        let honest = Zero::<4> {
            x: x.into(),
            claimed: u64::from(x == 0).into(),
        };
        let cases = [false, true].map(|wrong| {
            let claim = u64::from((x == 0) != wrong);
            let mut fixture = honest.clone();
            fixture.claimed = claim.into();
            Case {
                name: "zero",
                holds: !wrong,
                fixture,
                sdk_witness: SdkWitness::Tampered {
                    honest: honest.clone(),
                    wires: vec![(2, Fr::from(claim))],
                },
                circom: vec![
                    ("x", vec![x.to_string()]),
                    ("claimed", vec![claim.to_string()]),
                ],
            }
        });
        assert_relation_equivalent(&zero, &cases);
    }
}

pub fn snarkjs_fixture<F: ZkCircuit>(name: &str, fixture: &F, claim: usize) {
    let work = WorkDir::new(name);
    let r1cs = work.write("sdk.r1cs", &export::<F>());
    let witness = assignment(fixture);
    let wrong = *witness.get(claim).expect("claim") + Fr::one();
    let tampered = work.write(
        "wrong.wtns",
        &write_wtns(&with_wires(witness.clone(), &[(claim, wrong)])),
    );
    let honest = work.write("sdk.wtns", &write_wtns(&witness));
    assert_eq!(snarkjs::wtns_check(&r1cs, &honest), WtnsCheck::Accepted);
    assert_eq!(snarkjs::wtns_check(&r1cs, &tampered), WtnsCheck::Rejected);
    assert_eq!(
        snarkjs::groth16(&work, &r1cs, &honest),
        (true, serde_json::json!([]))
    );
}

#[test]
fn snarkjs_proves_comparison_division_selection_and_zero_and_rejects_false_claims() {
    snarkjs_fixture(
        "uint-compare-snarkjs",
        &compare::<64, 0>(u128::from(u64::MAX) - 1, u128::from(u64::MAX)),
        3,
    );
    snarkjs_fixture(
        "uint-div-snarkjs",
        &division::<64, 64, 64>(u128::from(u64::MAX), 7),
        3,
    );
    snarkjs_fixture(
        "uint-select-snarkjs",
        &Selection::<4> {
            x: 5u64.into(),
            y: 9u64.into(),
            condition: true,
            claimed: 5u64.into(),
        },
        4,
    );
    snarkjs_fixture(
        "uint-zero-snarkjs",
        &Zero::<4> {
            x: 0u64.into(),
            claimed: 1u64.into(),
        },
        2,
    );
}

fn pair_equivalence<const OP: u8>() {
    let circuit = compiled(&format!("pair_4_{OP}"));
    let cases: Vec<_> = [(0u64, 0u64), (0, 15), (15, 0), (7, 8), (15, 15)]
        .into_iter()
        .map(|(x, y)| Case {
            name: "assertion",
            holds: pair_holds(OP, x, y),
            fixture: Pair::<4, OP> {
                x: x.into(),
                y: y.into(),
            },
            sdk_witness: SdkWitness::Explicit(pair_witness(OP, x, y)),
            circom: vec![("x", vec![x.to_string()]), ("y", vec![y.to_string()])],
        })
        .collect();
    assert_relation_equivalent(&circuit, &cases);
}

#[test]
fn all_assertion_forms_match_circom_relations_for_honest_and_coordinated_false_witnesses() {
    pair_equivalence::<0>();
    pair_equivalence::<1>();
    pair_equivalence::<2>();
    pair_equivalence::<3>();
    pair_equivalence::<4>();
    pair_equivalence::<5>();
}

#[test]
fn range_and_conditional_assertions_match_circom_including_disabled_inequality() {
    use crate::uint::rows::low_bits;
    let range = compiled("range_4");
    let cases: Vec<_> = [
        (0u64, 0u64, 15u64),
        (15, 0, 15),
        (7, 8, 15),
        (7, 0, 6),
        (7, 9, 1),
    ]
    .into_iter()
    .map(|(x, low, high)| {
        let (xf, lf, hf) = (Fr::from(x), Fr::from(low), Fr::from(high));
        let witness = [
            vec![Fr::one(), xf, lf, hf],
            low_bits(xf, 4),
            low_bits(lf, 4),
            low_bits(hf, 4),
            low_bits(xf - lf, 4),
            low_bits(hf - xf, 4),
        ]
        .concat();
        Case {
            name: "range",
            holds: low <= x && x <= high,
            fixture: Range::<4> {
                x: x.into(),
                low: low.into(),
                high: high.into(),
            },
            sdk_witness: SdkWitness::Explicit(witness),
            circom: vec![
                ("x", vec![x.to_string()]),
                ("low", vec![low.to_string()]),
                ("high", vec![high.to_string()]),
            ],
        }
    })
    .collect();
    assert_relation_equivalent(&range, &cases);
    let conditional = compiled("conditional_4");
    let cases: Vec<_> = [false, true]
        .into_iter()
        .flat_map(|condition| {
            [(5u64, 5u64), (5, 9)].into_iter().map(move |(x, y)| {
                let (xf, yf) = (Fr::from(x), Fr::from(y));
                let witness = [
                    vec![Fr::one(), xf, yf, Fr::from(u64::from(condition))],
                    low_bits(xf, 4),
                    low_bits(yf, 4),
                ]
                .concat();
                Case {
                    name: "conditional equality",
                    holds: !condition || x == y,
                    fixture: Conditional::<4> {
                        x: x.into(),
                        y: y.into(),
                        condition,
                    },
                    sdk_witness: SdkWitness::Explicit(witness),
                    circom: vec![
                        ("x", vec![x.to_string()]),
                        ("y", vec![y.to_string()]),
                        ("condition", vec![u64::from(condition).to_string()]),
                    ],
                }
            })
        })
        .collect();
    assert_relation_equivalent(&conditional, &cases);
}

fn zero_assertion<const NONZERO: bool>() {
    use crate::uint::rows::low_bits;
    use ark_ff::Field as _;
    let reference = compiled(&format!("assert_zero_4_{}", u8::from(NONZERO)));
    let cases: Vec<_> = [0u64, 1, 15]
        .into_iter()
        .map(|x| {
            let xf = Fr::from(x);
            let mut witness = [vec![Fr::one(), xf], low_bits(xf, 4)].concat();
            if NONZERO {
                witness.push(xf.inverse().unwrap_or_default());
            }
            Case {
                name: "zero assertion",
                holds: (x != 0) == NONZERO,
                fixture: AssertZero::<4, NONZERO> { x: x.into() },
                sdk_witness: SdkWitness::Explicit(witness),
                circom: vec![("x", vec![x.to_string()])],
            }
        })
        .collect();
    assert_relation_equivalent(&reference, &cases);
}

#[test]
fn zero_assertions_match_circomlib_iszero() {
    zero_assertion::<false>();
    zero_assertion::<true>();
}
