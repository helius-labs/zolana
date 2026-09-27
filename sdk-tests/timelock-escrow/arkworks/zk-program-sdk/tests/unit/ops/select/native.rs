use zk_program_sdk::circuit::{value, CircuitVar, Field};

use super::{
    fixtures::{
        every_form, form_names, ArraySelected, SelectConstantBranches, SelectConstantCondition,
        FALSE_CONSTANT, RULE_BROKEN, TRUE_CONSTANT,
    },
    vectors::{arrays, Branches, BRANCHES, CONDITIONS, LENGTH},
};
use crate::harness::fixture::{
    each, native, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit, Visited,
};

type Selection = (String, Result<Field, Refusal>);

struct NativeSelected;

impl Visit<CircuitVar> for NativeSelected {
    type Output = Selection;

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Selection {
        let selected = F::computed(&native_circuit(fixture).expect("native instantiation"));
        (format!("{selected:?}"), outcome(value(&selected)))
    }
}

fn constant(value: Field) -> Selection {
    (
        format!("CircuitVar::constant({})", ark_bn254::Fr::from(value)),
        Ok(value),
    )
}

fn per_condition<T>(visit: impl Fn(bool) -> T) -> [(bool, T); 2] {
    CONDITIONS.map(|condition| (condition, visit(condition)))
}

#[test]
fn the_native_select_is_exactly_the_chosen_branch_in_every_form() {
    assert_eq!(
        per_vector(&BRANCHES, |branches| per_condition(|condition| {
            every_form(&NativeSelected, branches.claim(condition))
        })),
        per_vector(&BRANCHES, |branches| per_condition(|condition| {
            each(&form_names(), constant(branches.chosen(condition)))
        }))
    );
}

fn claims(branches: &Branches, condition: bool) -> Visited<[Result<(), Refusal>; 2]> {
    let (_, if_true, if_false, chosen) = branches.claim(condition);
    let honest = every_form(&Native, (condition, if_true, if_false, chosen));
    let wrong = every_form(
        &Native,
        (condition, if_true, if_false, chosen + Field::from(1u64)),
    );
    honest
        .into_iter()
        .zip(wrong)
        .map(|((form, honest), (_, wrong))| (form, [honest, wrong]))
        .collect()
}

#[test]
fn every_chosen_branch_holds_natively_and_every_other_value_breaks_the_rule() {
    let other_branch = |branches: &Branches| {
        let (if_true, if_false) = branches.fields();
        CONDITIONS.map(|condition| {
            let other = branches.chosen(!condition);
            (
                other == branches.chosen(condition),
                every_form(&Native, (condition, if_true, if_false, other)),
            )
        })
    };
    assert_eq!(
        (
            per_vector(&BRANCHES, |branches| per_condition(|condition| {
                claims(branches, condition)
            })),
            per_vector(&BRANCHES, other_branch),
        ),
        (
            per_vector(&BRANCHES, |_| per_condition(|_| {
                each(&form_names(), [Ok(()), Err(RULE_BROKEN)])
            })),
            per_vector(&BRANCHES, |branches| {
                let same = branches.if_true == branches.if_false;
                let outcome = if same { Ok(()) } else { Err(RULE_BROKEN) };
                [
                    (same, each(&form_names(), outcome)),
                    (same, each(&form_names(), outcome)),
                ]
            }),
        )
    );
}

#[test]
fn a_constant_condition_or_constant_branches_select_natively_the_chosen_value() {
    let (seven, three) = (Field::from(TRUE_CONSTANT), Field::from(FALSE_CONSTANT));
    let constant_condition = per_vector(&BRANCHES, |branches| {
        let (if_true, if_false) = branches.fields();
        [
            native(&SelectConstantCondition::<true> {
                if_true,
                if_false,
                selected: if_true,
            }),
            native(&SelectConstantCondition::<false> {
                if_true,
                if_false,
                selected: if_false,
            }),
        ]
    });
    assert_eq!(
        (
            constant_condition,
            [
                native(&SelectConstantBranches {
                    condition: true,
                    selected: seven,
                }),
                native(&SelectConstantBranches {
                    condition: false,
                    selected: three,
                }),
                native(&SelectConstantBranches {
                    condition: true,
                    selected: three,
                }),
                native(&SelectConstantBranches {
                    condition: false,
                    selected: seven,
                }),
            ],
        ),
        (
            per_vector(&BRANCHES, |_| [Ok(()), Ok(())]),
            [Ok(()), Ok(()), Err(RULE_BROKEN), Err(RULE_BROKEN)],
        )
    );
}

fn array_values<const N: usize>(fixture: &ArraySelected<N>) -> Vec<Result<Field, Refusal>> {
    let circuit = native_circuit(fixture).expect("native instantiation");
    <ArraySelected<N> as Fixture<[CircuitVar; N]>>::computed(&circuit)
        .iter()
        .map(|selected| outcome(value(selected)))
        .collect()
}

#[test]
fn the_native_array_select_is_exactly_the_chosen_array_element_by_element() {
    let (if_true, if_false) = arrays();
    let selected = CONDITIONS.map(|condition| {
        let chosen = if condition { if_true } else { if_false };
        let fixture = ArraySelected::<LENGTH> {
            condition,
            if_true,
            if_false,
            selected: chosen,
        };
        (array_values(&fixture), native(&fixture))
    });
    let empty = ArraySelected::<0> {
        condition: true,
        if_true: [],
        if_false: [],
        selected: [],
    };
    assert_eq!(
        (selected, array_values(&empty), native(&empty)),
        (
            [
                (if_false.map(Ok).to_vec(), Ok(())),
                (if_true.map(Ok).to_vec(), Ok(()))
            ],
            vec![],
            Ok(())
        )
    );
}

#[test]
fn a_wrong_array_element_breaks_the_rule_natively() {
    let (if_true, if_false) = arrays();
    let wrong = (0..LENGTH)
        .map(|index| {
            let mut selected = if_true;
            selected[index] = if_false[index] + Field::from(1u64);
            native(&ArraySelected::<LENGTH> {
                condition: true,
                if_true,
                if_false,
                selected,
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(wrong, vec![Err(RULE_BROKEN); LENGTH]);
}
