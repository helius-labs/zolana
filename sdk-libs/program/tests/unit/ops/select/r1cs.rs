use ark_bn254::Fr;
use zolana_program::{
    circuit::{Field, VariableRole},
    testing::PrivateVariableReport,
};

use super::{
    fixtures::{
        every_form, form_names, ArraySelected, SelectConstantBranches, SelectConstantCondition,
        Selected, Unasserted, FALSE_CONSTANT, RULE, TRUE_CONSTANT,
    },
    vectors::{arrays, Branches, BRANCHES, CONDITIONS, LENGTH},
};
use crate::{
    harness::{
        fixture::{
            assignment, breaks_rule, check_constraints, check_tampered, each, export, exported,
            first_unsatisfied, per_vector, Assignment, CheckConstraints, Export, Fixture,
            FreeVariables, ProverRefusal, Visit,
        },
        iden3::R1csHeader,
    },
    ops::rows::{boolean_row, minus_one, one, r1cs, Constraint},
};

const BOOL_RULE: &str = "a bool proof input is neither 0 nor 1";
const SELECTED_WIRE: usize = 4;
const PRODUCT_WIRE: usize = 5;

fn product_row(condition: usize, if_true: usize, if_false: usize, product: usize) -> Constraint {
    (
        vec![(one(), condition)],
        vec![(one(), if_true), (minus_one(), if_false)],
        vec![(one(), product)],
    )
}

fn claim_row(if_false: usize, selected: usize, product: usize) -> Constraint {
    (
        vec![(one(), if_false), (minus_one(), selected), (one(), product)],
        vec![(one(), 0)],
        vec![],
    )
}

fn per_claim<T>(visit: impl Fn(&Branches, bool) -> T) -> Vec<(&'static str, [T; 2])> {
    per_vector(&BRANCHES, |branches| {
        CONDITIONS.map(|condition| visit(branches, condition))
    })
}

#[test]
fn select_exports_the_condition_row_one_product_row_and_the_claim_row() {
    assert_eq!(
        exported::<Selected<0>>(),
        r1cs(
            R1csHeader::bn254(6, 0, 5, 3),
            vec![boolean_row(1), product_row(1, 2, 3, 5), claim_row(3, 4, 5)]
        )
    );
}

#[test]
fn every_form_exports_byte_identical_r1cs() {
    assert_eq!(
        every_form(&Export, BRANCHES[0].claim(false)),
        each(&form_names(), export::<Selected<0>>())
    );
}

#[test]
fn select_on_variables_adds_exactly_one_row_and_one_variable() {
    assert_eq!(
        exported::<Unasserted>(),
        r1cs(
            R1csHeader::bn254(5, 0, 4, 2),
            vec![boolean_row(1), product_row(1, 2, 3, 4)]
        )
    );
}

#[test]
fn the_product_variable_is_exactly_the_condition_times_the_branch_difference() {
    assert_eq!(
        per_claim(|branches, condition| every_form(&Assignment, branches.claim(condition))),
        per_claim(|branches, condition| {
            let (_, if_true, if_false, chosen) = branches.claim(condition);
            let (if_true, if_false) = (Fr::from(if_true), Fr::from(if_false));
            let bit = Fr::from(u64::from(condition));
            each(
                &form_names(),
                vec![
                    one(),
                    bit,
                    if_true,
                    if_false,
                    chosen.into(),
                    bit * (if_true - if_false),
                ],
            )
        })
    );
}

#[test]
fn a_constant_condition_selects_a_branch_with_no_row_and_no_variable() {
    assert_eq!(
        (
            exported::<SelectConstantCondition<true>>(),
            exported::<SelectConstantCondition<false>>()
        ),
        (
            r1cs(
                R1csHeader::bn254(4, 0, 3, 1),
                vec![(vec![(one(), 1), (minus_one(), 3)], vec![(one(), 0)], vec![])]
            ),
            r1cs(
                R1csHeader::bn254(4, 0, 3, 1),
                vec![(vec![(one(), 2), (minus_one(), 3)], vec![(one(), 0)], vec![])]
            )
        )
    );
}

#[test]
fn constant_branches_select_with_no_product_row() {
    assert_eq!(
        exported::<SelectConstantBranches>(),
        r1cs(
            R1csHeader::bn254(3, 0, 2, 2),
            vec![
                boolean_row(1),
                (
                    vec![
                        (Fr::from(FALSE_CONSTANT), 0),
                        (Fr::from(TRUE_CONSTANT - FALSE_CONSTANT), 1),
                        (minus_one(), 2)
                    ],
                    vec![(one(), 0)],
                    vec![]
                ),
            ]
        )
    );
}

#[test]
fn array_select_exports_one_product_row_and_one_claim_row_per_element() {
    let condition = 1;
    let if_true = |index: usize| 2 + index;
    let if_false = |index: usize| 2 + LENGTH + index;
    let selected = |index: usize| 2 + 2 * LENGTH + index;
    let product = |index: usize| 2 + 3 * LENGTH + index;
    let rows = std::iter::once(boolean_row(condition))
        .chain(
            (0..LENGTH).map(|index| {
                product_row(condition, if_true(index), if_false(index), product(index))
            }),
        )
        .chain((0..LENGTH).map(|index| claim_row(if_false(index), selected(index), product(index))))
        .collect();
    assert_eq!(
        (
            exported::<ArraySelected<0>>(),
            exported::<ArraySelected<LENGTH>>()
        ),
        (
            r1cs(R1csHeader::bn254(2, 0, 1, 1), vec![boolean_row(condition)]),
            r1cs(R1csHeader::bn254(14, 0, 13, 7), rows)
        )
    );
}

struct Honest;

fn honest<F: Fixture>(fixture: &F) -> <Honest as Visit>::Output {
    Honest.visit(fixture)
}

impl<C> Visit<C> for Honest {
    type Output = (Option<usize>, Result<usize, ProverRefusal>);

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        (
            first_unsatisfied::<F>(&assignment(fixture)),
            check_constraints(fixture),
        )
    }
}

#[test]
fn every_honest_selection_satisfies_every_exported_row_and_checks_every_proving_row() {
    let (seven, three) = (Field::from(TRUE_CONSTANT), Field::from(FALSE_CONSTANT));
    let (if_true, if_false) = arrays();
    assert_eq!(
        (
            per_claim(|branches, condition| every_form(&Honest, branches.claim(condition))),
            per_vector(&BRANCHES, |branches| {
                let (if_true, if_false) = branches.fields();
                (
                    honest(&SelectConstantCondition::<true> {
                        if_true,
                        if_false,
                        selected: if_true,
                    }),
                    honest(&SelectConstantCondition::<false> {
                        if_true,
                        if_false,
                        selected: if_false,
                    }),
                )
            }),
            [(true, seven), (false, three)].map(|(condition, selected)| {
                honest(&SelectConstantBranches {
                    condition,
                    selected,
                })
            }),
            CONDITIONS.map(|condition| {
                honest(&ArraySelected::<LENGTH> {
                    condition,
                    if_true,
                    if_false,
                    selected: if condition { if_true } else { if_false },
                })
            }),
        ),
        (
            per_claim(|_, _| each(&form_names(), (None, Ok(3)))),
            per_vector(&BRANCHES, |_| ((None, Ok(1)), (None, Ok(1)))),
            [(None, Ok(2)), (None, Ok(2))],
            [(None, Ok(7)), (None, Ok(7))],
        )
    );
}

struct WrongSelection;

impl<C> Visit<C> for WrongSelection {
    type Output = [Result<(), ProverRefusal>; 2];

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture);
        let selected = honest[SELECTED_WIRE];
        [selected + one(), selected - one()]
            .map(|value| check_tampered(fixture, SELECTED_WIRE, Field::from(value)))
    }
}

#[test]
fn every_value_but_the_chosen_branch_breaks_the_claim_row() {
    let r1cs = exported::<Selected<0>>();
    let other_branch = per_claim(|branches, condition| {
        let mut witness = assignment(&Selected::<0> {
            condition,
            if_true: branches.fields().0,
            if_false: branches.fields().1,
            selected: branches.chosen(condition),
        });
        witness[SELECTED_WIRE] = branches.chosen(!condition).into();
        (
            branches.if_true == branches.if_false,
            r1cs.first_unsatisfied(&witness),
        )
    });
    assert_eq!(
        (
            per_claim(|branches, condition| every_form(&WrongSelection, branches.claim(condition))),
            other_branch,
        ),
        (
            per_claim(|_, _| each(
                &form_names(),
                [Err(breaks_rule(2, RULE)), Err(breaks_rule(2, RULE))]
            )),
            per_claim(|branches, _| {
                let same = branches.if_true == branches.if_false;
                (same, if same { None } else { Some(2) })
            }),
        )
    );
}

#[test]
fn a_tampered_product_breaks_its_unlabelled_row() {
    assert_eq!(
        per_claim(|branches, condition| {
            let fixture = Selected::<0> {
                condition,
                if_true: branches.fields().0,
                if_false: branches.fields().1,
                selected: branches.chosen(condition),
            };
            let product = assignment(&fixture)[PRODUCT_WIRE];
            check_tampered(&fixture, PRODUCT_WIRE, Field::from(product + one()))
        }),
        per_claim(|_, _| Err(("ProverError.ProofInputsBreakRule", Some(1), None)))
    );
}

#[test]
fn only_the_condition_row_refuses_a_condition_of_two() {
    let r1cs = exported::<Selected<0>>();
    let two = Fr::from(2u64);
    assert_eq!(
        per_vector(&BRANCHES, |branches| {
            let (if_true, if_false) = branches.fields();
            let (if_true, if_false) = (Fr::from(if_true), Fr::from(if_false));
            let product = two * (if_true - if_false);
            let witness = [one(), two, if_true, if_false, if_false + product, product];
            let fixture = Selected::<0> {
                condition: false,
                if_true: if_true.into(),
                if_false: if_false.into(),
                selected: if_false.into(),
            };
            (
                r1cs.first_unsatisfied(&witness),
                check_tampered(&fixture, 1, Field::from(two)),
            )
        }),
        per_vector(&BRANCHES, |_| (Some(0), Err(breaks_rule(0, BOOL_RULE))))
    );
}

type Free = (
    usize,
    usize,
    Vec<(usize, VariableRole, Option<&'static str>)>,
    usize,
);

fn summary(report: PrivateVariableReport) -> Free {
    (
        report.constraints,
        report.private_variables,
        report
            .free
            .into_iter()
            .map(|free| {
                (
                    free.variable,
                    free.role,
                    free.allocation.map(|label| label.text),
                )
            })
            .collect(),
        report.tolerated.len(),
    )
}

#[test]
fn under_a_false_condition_exactly_the_unchosen_branch_is_free() {
    assert_eq!(
        per_claim(|branches, condition| {
            every_form(&FreeVariables, branches.claim(condition))
                .into_iter()
                .map(|(form, report)| (form, summary(report)))
                .collect::<Vec<_>>()
        }),
        per_claim(|_, condition| {
            let free = if condition {
                vec![]
            } else {
                vec![(1, VariableRole::Constrained, Some("a field proof input"))]
            };
            each(&form_names(), (3, 5, free, 0))
        })
    );
}

#[test]
fn a_tampered_array_element_breaks_exactly_its_own_claim_row() {
    let (if_true, if_false) = arrays();
    let fixture = ArraySelected::<LENGTH> {
        condition: true,
        if_true,
        if_false,
        selected: if_true,
    };
    let first_selected = 2 + 2 * LENGTH;
    assert_eq!(
        (0..LENGTH)
            .map(|index| {
                check_tampered(
                    &fixture,
                    first_selected + index,
                    if_false[index] + Field::from(1u64),
                )
            })
            .collect::<Vec<_>>(),
        (0..LENGTH)
            .map(|index| Err(breaks_rule(1 + LENGTH + index, RULE)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_selection_checks_the_same_shape_as_the_placeholder() {
    assert_eq!(
        per_claim(|branches, condition| every_form(&CheckConstraints, branches.claim(condition))),
        per_claim(|_, _| each(&form_names(), Ok(3)))
    );
}
