use ark_bn254::Fr;
use ark_ff::{Field as _, Zero};
use zolana_program::{
    circuit::{Field, VariableRole},
    testing::PrivateVariableReport,
    ZkCircuit,
};

use super::{
    fixtures::{
        ArrayAssertEqual, ArrayAssertEqualIf, ArrayAssertNotEqual, ArrayIsEqual, AssertEqual,
        AssertEqualIf, AssertEqualIfConstant, AssertEqualIfItself, AssertNotEqual,
        ConditionInCircuit, Constant, ConstantsIf, EqualConstantsIf, IsEqual, Unasserted,
        BOOL_RULE, CLAIM_RULE, NOT_EQUAL_RULE, RULE,
    },
    vectors::{Pair, ARRAYS, DIFFERENT, EQUAL, LENGTH, X},
};
use crate::{
    harness::{
        field::{fr, MODULUS_MINUS_1},
        fixture::{
            assignment, breaks_rule, check_constraints, check_private_variables, check_tampered,
            export, exported, first_unsatisfied, no_free_variable, per_vector, size, ProverRefusal,
            Size,
        },
        iden3::R1csHeader,
    },
    ops::rows::{boolean_row, minus_one, one, r1cs},
};

const EQUALITY_SCOPE: &str = "an equality test";

fn frs(pair: &Pair) -> (Fr, Fr) {
    let (left, right) = pair.fields();
    (left.into(), right.into())
}

fn inverse_of_difference(pair: &Pair) -> Fr {
    let (left, right) = frs(pair);
    (left - right).inverse().expect("different sides")
}

fn hint_candidates(pair: &Pair) -> [Fr; 4] {
    let (left, right) = frs(pair);
    [
        Fr::zero(),
        one(),
        fr(MODULUS_MINUS_1),
        (left - right).inverse().unwrap_or(fr(X)),
    ]
}

#[test]
fn assert_equal_on_two_variables_exports_exactly_one_row_and_no_variable() {
    let (left, right) = EQUAL[4].fields();
    assert_eq!(
        (
            exported::<AssertEqual>(),
            assignment(&AssertEqual { left, right })
        ),
        (
            r1cs(
                R1csHeader::bn254(3, 0, 2, 1),
                vec![(vec![(one(), 1), (minus_one(), 2)], vec![(one(), 0)], vec![])]
            ),
            vec![one(), left.into(), right.into()]
        )
    );
}

#[test]
fn is_equal_adds_exactly_two_rows_and_two_private_variables() {
    let difference = vec![(one(), 1), (minus_one(), 2)];
    assert_eq!(
        exported::<Unasserted>(),
        r1cs(
            R1csHeader::bn254(5, 0, 4, 2),
            vec![
                (difference.clone(), vec![(one(), 4)], vec![(one(), 3)]),
                (difference, vec![(one(), 0), (minus_one(), 3)], vec![]),
            ]
        )
    );
}

#[test]
fn the_is_equal_claim_exports_exactly_the_golden_rows() {
    let difference = vec![(one(), 1), (minus_one(), 2)];
    assert_eq!(
        exported::<IsEqual>(),
        r1cs(
            R1csHeader::bn254(6, 0, 5, 3),
            vec![
                (difference.clone(), vec![(one(), 5)], vec![(one(), 4)]),
                (difference, vec![(one(), 0), (minus_one(), 4)], vec![]),
                (
                    vec![(one(), 0), (minus_one(), 3), (minus_one(), 4)],
                    vec![(one(), 0)],
                    vec![]
                ),
            ]
        )
    );
}

fn is_equal_assignment(pair: &Pair, equal: bool) -> Vec<Fr> {
    let (left, right) = pair.fields();
    assignment(&IsEqual {
        left,
        right,
        claimed: Field::from(u64::from(equal)),
    })
}

#[test]
fn the_is_equal_assignment_holds_the_inequality_bit_and_the_inverse_hint() {
    assert_eq!(
        (
            per_vector(&EQUAL, |pair| is_equal_assignment(pair, true)),
            per_vector(&DIFFERENT, |pair| is_equal_assignment(pair, false))
        ),
        (
            per_vector(&EQUAL, |pair| {
                let (left, right) = frs(pair);
                vec![one(), left, right, one(), Fr::zero(), one()]
            }),
            per_vector(&DIFFERENT, |pair| {
                let (left, right) = frs(pair);
                vec![
                    one(),
                    left,
                    right,
                    Fr::zero(),
                    one(),
                    inverse_of_difference(pair),
                ]
            })
        )
    );
}

#[test]
fn assert_equal_if_exports_the_condition_row_then_exactly_one_product_row() {
    assert_eq!(
        exported::<AssertEqualIf>(),
        r1cs(
            R1csHeader::bn254(4, 0, 3, 2),
            vec![
                boolean_row(3),
                (vec![(one(), 1), (minus_one(), 2)], vec![(one(), 3)], vec![]),
            ]
        )
    );
}

#[test]
fn a_false_constant_condition_exports_no_row_and_a_true_one_exactly_assert_equal() {
    assert_eq!(
        (
            exported::<AssertEqualIfConstant<false>>(),
            export::<AssertEqualIfConstant<true>>() == export::<AssertEqual>()
        ),
        (r1cs(R1csHeader::bn254(3, 0, 2, 0), vec![]), true)
    );
}

#[test]
fn constant_sides_export_no_row_when_equal_and_force_the_condition_false_when_different() {
    assert_eq!(
        (exported::<EqualConstantsIf>(), exported::<ConstantsIf>()),
        (
            r1cs(R1csHeader::bn254(2, 0, 1, 1), vec![boolean_row(1)]),
            r1cs(
                R1csHeader::bn254(2, 0, 1, 2),
                vec![
                    boolean_row(1),
                    (vec![(Fr::from(2u64), 1)], vec![(one(), 0)], vec![])
                ]
            )
        )
    );
}

#[test]
fn a_variable_asserted_against_itself_under_a_variable_condition_exports_an_empty_row() {
    assert_eq!(
        exported::<AssertEqualIfItself>(),
        r1cs(
            R1csHeader::bn254(3, 0, 2, 2),
            vec![boolean_row(2), (vec![], vec![(one(), 2)], vec![])]
        )
    );
}

#[test]
fn assert_not_equal_exports_exactly_one_row_and_one_inverse_variable() {
    assert_eq!(
        exported::<AssertNotEqual>(),
        r1cs(
            R1csHeader::bn254(4, 0, 3, 1),
            vec![(
                vec![(one(), 1), (minus_one(), 2)],
                vec![(one(), 3)],
                vec![(one(), 0)]
            )]
        )
    );
}

#[test]
fn the_assert_not_equal_hint_is_exactly_the_inverse_of_the_difference() {
    assert_eq!(
        per_vector(&DIFFERENT, |pair| {
            let (left, right) = pair.fields();
            assignment(&AssertNotEqual { left, right })
        }),
        per_vector(&DIFFERENT, |pair| {
            let (left, right) = frs(pair);
            vec![one(), left, right, inverse_of_difference(pair)]
        })
    );
}

#[test]
fn array_assert_equal_exports_exactly_one_row_per_element() {
    let row = |index: usize| {
        (
            vec![(one(), 1 + index), (minus_one(), 1 + LENGTH + index)],
            vec![(one(), 0)],
            vec![],
        )
    };
    assert_eq!(
        (
            exported::<ArrayAssertEqual<0>>(),
            exported::<ArrayAssertEqual<LENGTH>>()
        ),
        (
            r1cs(R1csHeader::bn254(1, 0, 0, 0), vec![]),
            r1cs(
                R1csHeader::bn254(7, 0, 6, 3),
                (0..LENGTH).map(row).collect()
            )
        )
    );
}

#[test]
fn array_assert_equal_if_exports_the_condition_row_then_one_product_row_per_element() {
    let condition = 1 + 2 * LENGTH;
    let row = |index: usize| {
        (
            vec![(one(), 1 + index), (minus_one(), 1 + LENGTH + index)],
            vec![(one(), condition)],
            vec![],
        )
    };
    assert_eq!(
        exported::<ArrayAssertEqualIf<LENGTH>>(),
        r1cs(
            R1csHeader::bn254(8, 0, 7, 4),
            std::iter::once(boolean_row(condition))
                .chain((0..LENGTH).map(row))
                .collect()
        )
    );
}

#[test]
fn array_is_equal_of_two_elements_tests_each_pair_then_their_sum() {
    let difference = |index: usize| vec![(one(), 1 + index), (minus_one(), 3 + index)];
    let bits = vec![(one(), 6), (one(), 8)];
    assert_eq!(
        exported::<ArrayIsEqual<2>>(),
        r1cs(
            R1csHeader::bn254(12, 0, 11, 7),
            vec![
                (difference(0), vec![(one(), 7)], vec![(one(), 6)]),
                (difference(0), vec![(one(), 0), (minus_one(), 6)], vec![]),
                (difference(1), vec![(one(), 9)], vec![(one(), 8)]),
                (difference(1), vec![(one(), 0), (minus_one(), 8)], vec![]),
                (bits.clone(), vec![(one(), 11)], vec![(one(), 10)]),
                (bits, vec![(one(), 0), (minus_one(), 10)], vec![]),
                (
                    vec![(one(), 0), (minus_one(), 5), (minus_one(), 10)],
                    vec![(one(), 0)],
                    vec![]
                ),
            ]
        )
    );
}

fn sizes(constraints: usize, variables: usize) -> Size {
    Size {
        constraints,
        variables,
    }
}

#[test]
fn array_equality_costs_two_rows_per_element_plus_two_for_the_conjunction() {
    assert_eq!(
        (
            [
                size::<ArrayIsEqual<0>>(),
                size::<ArrayIsEqual<1>>(),
                size::<ArrayIsEqual<2>>(),
                size::<ArrayIsEqual<3>>(),
            ],
            [
                size::<ArrayAssertNotEqual<1>>(),
                size::<ArrayAssertNotEqual<2>>(),
                size::<ArrayAssertNotEqual<3>>(),
            ],
        ),
        (
            [sizes(1, 2), sizes(3, 6), sizes(7, 12), sizes(9, 16)],
            [sizes(3, 5), sizes(7, 11), sizes(9, 15)],
        )
    );
}

#[test]
fn empty_arrays_can_never_be_asserted_different() {
    let empty = ArrayAssertNotEqual::<0> {
        left: [],
        right: [],
    };
    assert_eq!(
        (
            ArrayAssertNotEqual::<0>::export_r1cs()
                .map(|_| ())
                .map_err(|error| (error.name(), error.broken_rule())),
            check_constraints(&empty),
        ),
        (
            Err(("CircuitError.RuleBroken", Some(NOT_EQUAL_RULE))),
            Err(("CircuitError.RuleBroken", None, None)),
        )
    );
}

type Honest = (Option<usize>, Result<usize, ProverRefusal>);

fn honest<F: ZkCircuit>(fixture: F) -> Honest {
    (
        first_unsatisfied::<F>(&assignment(&fixture)),
        check_constraints(&fixture),
    )
}

#[test]
fn every_honest_pair_satisfies_every_exported_row_and_checks_every_proving_row() {
    let equal = |pair: &Pair| {
        let (left, right) = pair.fields();
        [
            honest(AssertEqual { left, right }),
            honest(IsEqual {
                left,
                right,
                claimed: Field::from(1u64),
            }),
            honest(AssertEqualIf {
                left,
                right,
                condition: false,
            }),
            honest(AssertEqualIf {
                left,
                right,
                condition: true,
            }),
            honest(AssertEqualIfConstant::<true> { left, right }),
        ]
    };
    let different = |pair: &Pair| {
        let (left, right) = pair.fields();
        [
            honest(IsEqual {
                left,
                right,
                claimed: Field::from(0u64),
            }),
            honest(AssertEqualIf {
                left,
                right,
                condition: false,
            }),
            honest(AssertEqualIfConstant::<false> { left, right }),
            honest(AssertNotEqual { left, right }),
        ]
    };
    assert_eq!(
        (per_vector(&EQUAL, equal), per_vector(&DIFFERENT, different)),
        (
            per_vector(&EQUAL, |_| [
                (None, Ok(1)),
                (None, Ok(3)),
                (None, Ok(2)),
                (None, Ok(2)),
                (None, Ok(1)),
            ]),
            per_vector(&DIFFERENT, |_| [
                (None, Ok(3)),
                (None, Ok(2)),
                (None, Ok(0)),
                (None, Ok(1)),
            ])
        )
    );
}

#[test]
fn every_honest_array_pair_satisfies_every_exported_row_and_checks_every_proving_row() {
    let checked = per_vector(&ARRAYS, |vector| {
        let (left, right) = vector.fields();
        let mut checks = vec![
            honest(ArrayIsEqual::<LENGTH> {
                left,
                right,
                claimed: Field::from(u64::from(vector.equal)),
            }),
            honest(ArrayAssertEqualIf::<LENGTH> {
                left,
                right,
                condition: false,
            }),
        ];
        if vector.equal {
            checks.push(honest(ArrayAssertEqual::<LENGTH> { left, right }));
            checks.push(honest(ArrayAssertEqualIf::<LENGTH> {
                left,
                right,
                condition: true,
            }));
        } else {
            checks.push(honest(ArrayAssertNotEqual::<LENGTH> { left, right }));
        }
        checks
    });
    assert_eq!(
        checked,
        per_vector(&ARRAYS, |vector| if vector.equal {
            vec![(None, Ok(9)), (None, Ok(4)), (None, Ok(3)), (None, Ok(4))]
        } else {
            vec![(None, Ok(9)), (None, Ok(4)), (None, Ok(9))]
        })
    );
}

#[test]
fn every_different_right_side_breaks_exactly_row_0_of_assert_equal() {
    let r1cs = exported::<AssertEqual>();
    let (left, right) = EQUAL[4].fields();
    let fixture = AssertEqual { left, right };
    let constant_true = AssertEqualIfConstant::<true> { left, right };
    assert_eq!(
        per_vector(&DIFFERENT, |pair| {
            let (left, right) = frs(pair);
            (
                r1cs.first_unsatisfied(&[one(), left, right]),
                check_tampered(&fixture, 2, Field::from(right)),
                check_tampered(&constant_true, 2, Field::from(right)),
            )
        }),
        per_vector(&DIFFERENT, |_| (
            Some(0),
            Err(breaks_rule(0, RULE)),
            Err(breaks_rule(0, RULE))
        ))
    );
}

#[test]
fn no_inverse_proves_equal_sides_different() {
    let r1cs = exported::<AssertNotEqual>();
    let refused = per_vector(&EQUAL, |pair| {
        let (left, right) = frs(pair);
        hint_candidates(pair).map(|hint| r1cs.first_unsatisfied(&[one(), left, right, hint]))
    });
    let tampered = per_vector(&DIFFERENT, |pair| {
        let (left, right) = pair.fields();
        let fixture = AssertNotEqual { left, right };
        let hint = inverse_of_difference(pair);
        (
            check_tampered(&fixture, 2, left),
            check_tampered(&fixture, 3, Field::from(hint + one())),
        )
    });
    assert_eq!(
        (refused, tampered),
        (
            per_vector(&EQUAL, |_| [Some(0); 4]),
            per_vector(&DIFFERENT, |_| (
                Err(breaks_rule(0, NOT_EQUAL_RULE)),
                Err(breaks_rule(0, NOT_EQUAL_RULE))
            ))
        )
    );
}

#[test]
fn no_witness_flips_an_equality_claim() {
    let r1cs = exported::<IsEqual>();
    let flipped = |pair: &Pair, claimed: u64, bit: u64| {
        let (left, right) = frs(pair);
        hint_candidates(pair).map(|hint| {
            r1cs.first_unsatisfied(&[one(), left, right, Fr::from(claimed), Fr::from(bit), hint])
        })
    };
    let wrong_claims = |pair: &Pair, equal: bool| {
        let honest = is_equal_assignment(pair, equal);
        [Fr::from(u64::from(!equal)), Fr::from(2u64)].map(|claimed| {
            let mut witness = honest.clone();
            witness[3] = claimed;
            r1cs.first_unsatisfied(&witness)
        })
    };
    assert_eq!(
        (
            per_vector(&EQUAL, |pair| flipped(pair, 0, 1)),
            per_vector(&DIFFERENT, |pair| flipped(pair, 1, 0)),
            per_vector(&EQUAL, |pair| wrong_claims(pair, true)),
            per_vector(&DIFFERENT, |pair| wrong_claims(pair, false)),
        ),
        (
            per_vector(&EQUAL, |_| [Some(0); 4]),
            per_vector(&DIFFERENT, |_| [Some(1), Some(0), Some(0), Some(0)]),
            per_vector(&EQUAL, |_| [Some(2); 2]),
            per_vector(&DIFFERENT, |_| [Some(2); 2]),
        )
    );
}

type Free = Vec<(usize, VariableRole, Option<&'static str>)>;

fn free(report: PrivateVariableReport) -> (usize, usize, Free, Free) {
    let summary = |variables: Vec<zolana_program::testing::FreeVariable>| {
        variables
            .into_iter()
            .map(|free| {
                (
                    free.variable,
                    free.role,
                    free.allocation.map(|label| label.text),
                )
            })
            .collect()
    };
    (
        report.constraints,
        report.private_variables,
        summary(report.free),
        summary(report.tolerated),
    )
}

const FIELD_INPUT: Option<&str> = Some("a field proof input");

#[test]
fn a_false_condition_binds_neither_side_and_a_true_one_binds_both() {
    let unbound = |pair: &Pair| {
        let (left, right) = pair.fields();
        let variable = AssertEqualIf {
            left,
            right,
            condition: false,
        };
        let constant = AssertEqualIfConstant::<false> { left, right };
        (
            free(check_private_variables(&variable)),
            free(check_private_variables(&constant)),
            check_tampered(&variable, 2, left),
            check_tampered(&constant, 2, left),
        )
    };
    let bound = |pair: &Pair| {
        let (left, right) = pair.fields();
        let (_, other) = DIFFERENT[5].fields();
        let variable = AssertEqualIf {
            left,
            right,
            condition: true,
        };
        (
            check_private_variables(&variable),
            check_tampered(&variable, 2, other),
        )
    };
    let both_free = vec![
        (0, VariableRole::Constrained, FIELD_INPUT),
        (1, VariableRole::Constrained, FIELD_INPUT),
    ];
    assert_eq!(
        (per_vector(&DIFFERENT, unbound), per_vector(&EQUAL, bound)),
        (
            per_vector(&DIFFERENT, |_| (
                (2, 3, both_free.clone(), vec![]),
                (0, 2, both_free.clone(), vec![]),
                Ok(()),
                Ok(())
            )),
            per_vector(&EQUAL, |_| (
                no_free_variable(2, 3),
                Err(breaks_rule(1, RULE))
            ))
        )
    );
}

#[test]
fn a_true_condition_on_different_sides_breaks_the_product_row() {
    let tampered = per_vector(&DIFFERENT, |pair| {
        let (left, right) = pair.fields();
        let fixture = AssertEqualIf {
            left,
            right,
            condition: false,
        };
        (
            check_tampered(&fixture, 3, Field::from(1u64)),
            check_tampered(&fixture, 3, Field::from(2u64)),
        )
    });
    assert_eq!(
        (
            tampered,
            check_tampered(&ConstantsIf { condition: false }, 1, Field::from(1u64)),
        ),
        (
            per_vector(&DIFFERENT, |_| (
                Err(breaks_rule(1, RULE)),
                Err(breaks_rule(0, BOOL_RULE))
            )),
            Err(breaks_rule(1, RULE)),
        )
    );
}

#[test]
fn no_private_variable_is_free_when_the_assertion_binds() {
    let equal = |pair: &Pair| {
        let (left, right) = pair.fields();
        (
            check_private_variables(&AssertEqual { left, right }),
            free(check_private_variables(&IsEqual {
                left,
                right,
                claimed: Field::from(1u64),
            })),
        )
    };
    let different = |pair: &Pair| {
        let (left, right) = pair.fields();
        (
            check_private_variables(&AssertNotEqual { left, right }),
            check_private_variables(&IsEqual {
                left,
                right,
                claimed: Field::from(0u64),
            }),
        )
    };
    assert_eq!(
        (per_vector(&EQUAL, equal), per_vector(&DIFFERENT, different)),
        (
            per_vector(&EQUAL, |_| (
                no_free_variable(1, 2),
                (
                    3,
                    5,
                    vec![],
                    vec![(
                        4,
                        VariableRole::Multiplier,
                        Some("the inverse hint of an equality test")
                    )]
                )
            )),
            per_vector(&DIFFERENT, |_| (
                no_free_variable(1, 3),
                no_free_variable(3, 5)
            ))
        )
    );
}

#[test]
fn a_tampered_array_element_breaks_exactly_its_own_row() {
    let (left, right) = ARRAYS[0].fields();
    let other = Field::from(5u64);
    let first_right = 1 + LENGTH;
    let condition = 1 + 2 * LENGTH;
    let equal = ArrayAssertEqual::<LENGTH> { left, right };
    let conditional = ArrayAssertEqualIf::<LENGTH> {
        left,
        right,
        condition: true,
    };
    let claim = ArrayIsEqual::<LENGTH> {
        left,
        right,
        claimed: Field::from(1u64),
    };
    let (differing_left, differing_right) = ARRAYS[1].fields();
    let different = ArrayAssertNotEqual::<LENGTH> {
        left: differing_left,
        right: differing_right,
    };
    assert_eq!(
        (
            (0..LENGTH)
                .map(|index| check_tampered(&equal, first_right + index, other))
                .collect::<Vec<_>>(),
            (0..LENGTH)
                .map(|index| check_tampered(&conditional, first_right + index, other))
                .collect::<Vec<_>>(),
            check_tampered(&conditional, condition, Field::from(0u64)),
            check_tampered(&claim, condition, Field::from(0u64)),
            check_tampered(&different, first_right, differing_left[0]),
        ),
        (
            (0..LENGTH)
                .map(|index| Err(breaks_rule(index, RULE)))
                .collect::<Vec<_>>(),
            (0..LENGTH)
                .map(|index| Err(breaks_rule(1 + index, RULE)))
                .collect::<Vec<_>>(),
            Ok(()),
            Err(breaks_rule(8, CLAIM_RULE)),
            Err(breaks_rule(0, EQUALITY_SCOPE)),
        )
    );
}

#[test]
fn a_constant_condition_other_than_the_placeholders_changes_the_shape() {
    let shape = |pair: &Pair| {
        let (left, right) = pair.fields();
        [false, true].map(|condition| {
            check_constraints(&ConditionInCircuit {
                left,
                right,
                condition: Constant(condition),
            })
        })
    };
    assert_eq!(
        per_vector(&EQUAL, shape),
        per_vector(&EQUAL, |_| [
            Ok(0),
            Err(("ProverError.ShapeDiffers", None, None))
        ])
    );
}

#[test]
fn check_constraints_refuses_equal_sides_asserted_different_before_synthesis() {
    assert_eq!(
        per_vector(&EQUAL, |pair| {
            let (left, right) = pair.fields();
            AssertNotEqual { left, right }
                .check_constraints()
                .map_err(|error| (error.name(), error.broken_rule(), error.location().file()))
        }),
        per_vector(&EQUAL, |_| Err((
            "CircuitError.RuleBroken",
            Some(NOT_EQUAL_RULE),
            super::fixtures::FILE
        )))
    );
}
