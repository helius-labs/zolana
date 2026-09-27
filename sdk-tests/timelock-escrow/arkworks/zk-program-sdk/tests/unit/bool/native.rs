use zk_program_sdk::{
    circuit::{constant, value, Assert, Bool, CircuitVar, Field, Uint},
    CircuitError,
};

use super::{
    fixtures::{
        assert_true_if_form_names, assert_true_if_forms, binary_assert_names, binary_asserts,
        broken, constant_form_names, convert_form_names, convert_forms, every_constant_form,
        every_fold, every_gate, select_form_names, select_forms, unary_assert_names, unary_asserts,
        AssertEqualIf, Fold, Gate, Not, ALL, ANY, ASSERT_EQUAL_IF_RULE, ASSERT_TRUE_IF_FORMS,
        ASSERT_TRUE_IF_RULE, BINARY_ASSERTS, CONSTANT_FORMS, CONVERT_RULE, FOLDS, GATES, NOT_RULE,
        NOT_ZERO_OR_ONE, SELECT_FORMS, SELECT_RULE, UNARY_ASSERTS,
    },
    vectors::{
        per_flags, Pair, Triple, BITS, BOOLEAN_PAIRS, DECEPTIVE_ALL, DECEPTIVE_ANY, FLAGS,
        NON_BOOLEAN, NON_BOOLEAN_PAIRS, TRIPLES, WRONG_CLAIMS,
    },
};
use crate::harness::{
    field::field,
    fixture::{
        each, native, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit, Visited,
    },
};

const FILE: &str = file!();

type Output = Result<(String, Field), Refusal>;

struct NativeOutput;

impl Visit<Result<CircuitVar, Refusal>> for NativeOutput {
    type Output = Output;

    fn visit<F: Fixture<Result<CircuitVar, Refusal>>>(&self, fixture: &F) -> Output {
        native(fixture)?;
        let output = F::computed(&native_circuit(fixture)?)?;
        Ok((format!("{output:?}"), outcome(value(&output))?))
    }
}

fn constant_output(value: bool) -> Output {
    Ok((
        format!("CircuitVar::constant({})", u8::from(value)),
        Field::from(value),
    ))
}

fn read(var: impl Into<CircuitVar>) -> Output {
    let var = var.into();
    Ok((format!("{var:?}"), outcome(value(&var))?))
}

fn rule(rule: &'static str, holds: bool) -> Result<(), Refusal> {
    if holds {
        Ok(())
    } else {
        Err(("CircuitError.RuleBroken", Some(rule), FILE))
    }
}

fn fixture_rule(rule: &'static str, holds: bool) -> Result<(), Refusal> {
    if holds {
        Ok(())
    } else {
        Err(broken(rule))
    }
}

/// Every boolean combination of `N` operands, the first operand outermost.
fn combinations<const N: usize>() -> Vec<[bool; N]> {
    (0..1usize << N)
        .map(|index| std::array::from_fn(|operand| (index >> (N - 1 - operand)) & 1 == 1))
        .collect()
}

fn per_gate<T>(value: impl Fn(&Gate) -> T) -> Visited<T> {
    GATES.iter().map(|gate| (gate.name, value(gate))).collect()
}

fn per_pair<T>(pairs: &[Pair], value: impl Fn(&Gate, &Pair) -> T) -> Visited<Visited<T>> {
    per_gate(|gate| per_vector(pairs, |pair| value(gate, pair)))
}

fn honest(gate: &Gate, pair: &Pair) -> (Field, Field, Field) {
    let (a, b) = pair.fields();
    let (x, y) = pair.bits();
    (a, b, Field::from(gate.output(x, y)))
}

#[test]
fn a_bool_constant_is_exactly_zero_or_one_and_a_constant() {
    assert_eq!(
        [read(Bool::constant(false)), read(Bool::constant(true))],
        [constant_output(false), constant_output(true)]
    );
}

#[test]
fn try_from_accepts_exactly_the_constants_zero_and_one_in_both_forms() {
    let convert = |x: Field| {
        let var = constant(x);
        (
            outcome(Bool::try_from(var.clone())).and_then(read),
            outcome(Bool::try_from(&var)).and_then(read),
        )
    };
    let refused: Refusal = ("CircuitError.NotZeroOrOne", None, FILE);
    assert_eq!(
        (
            per_vector(&BITS, |bit| convert(bit.field())),
            per_vector(&NON_BOOLEAN, |x| convert(x.field())),
        ),
        (
            per_vector(&BITS, |bit| (
                constant_output(bit.bit()),
                constant_output(bit.bit())
            )),
            per_vector(&NON_BOOLEAN, |_| (Err(refused), Err(refused))),
        )
    );
}

#[test]
fn from_bool_keeps_the_value_in_a_circuit_var_and_in_every_uint_width() {
    let into = |bit: bool| {
        let bit = Bool::constant(bit);
        [
            read(bit.clone()),
            read(Uint::<1>::from(bit.clone())),
            read(Uint::<64>::from(bit.clone())),
            read(Uint::<253>::from(bit)),
        ]
    };
    assert_eq!(
        [into(false), into(true)],
        [
            [(); 4].map(|_| constant_output(false)),
            [(); 4].map(|_| constant_output(true))
        ]
    );
}

#[test]
fn every_gate_on_constants_is_its_truth_table_and_stays_a_constant() {
    let not = |[a]: [bool; 1]| read(Bool::constant(a).not());
    let not_not = |[a]: [bool; 1]| read(Bool::constant(a).not().not());
    assert_eq!(
        (
            per_gate(|gate| {
                combinations::<2>()
                    .into_iter()
                    .map(|[a, b]| {
                        outcome((gate.apply)(&Bool::constant(a), &Bool::constant(b))).and_then(read)
                    })
                    .collect::<Vec<_>>()
            }),
            combinations::<1>().into_iter().map(not).collect::<Vec<_>>(),
            combinations::<1>()
                .into_iter()
                .map(not_not)
                .collect::<Vec<_>>(),
        ),
        (
            per_gate(|gate| gate.truth.map(constant_output).to_vec()),
            vec![constant_output(true), constant_output(false)],
            vec![constant_output(false), constant_output(true)],
        )
    );
}

#[test]
fn all_and_any_on_constants_are_iterator_all_and_any_with_empty_slices_included() {
    let fold = |apply: fn(&[Bool]) -> Result<Bool, CircuitError>, flags: &[bool]| {
        let flags: Vec<Bool> = flags.iter().map(|flag| Bool::constant(*flag)).collect();
        outcome(apply(&flags)).and_then(read)
    };
    assert_eq!(
        FOLDS
            .iter()
            .map(|op| (op.name, per_flags(|flags| fold(op.apply, flags))))
            .collect::<Visited<_>>(),
        FOLDS
            .iter()
            .map(|op| (
                op.name,
                per_flags(|flags| constant_output((op.truth)(flags)))
            ))
            .collect::<Visited<_>>()
    );
}

#[test]
fn select_on_constants_picks_the_branch_the_condition_names_in_both_forms() {
    let select = |triple: &Triple| {
        let (c, t, f) = (
            Bool::constant(triple.condition),
            Bool::constant(triple.if_true),
            Bool::constant(triple.if_false),
        );
        SELECT_FORMS
            .iter()
            .map(|(name, form)| (*name, read(form(&c, &t, &f))))
            .collect::<Visited<_>>()
    };
    assert_eq!(
        per_vector(&TRIPLES, select),
        per_vector(&TRIPLES, |triple| each(
            &select_form_names(),
            constant_output(triple.selected())
        ))
    );
}

#[test]
fn every_assertion_on_constants_holds_exactly_as_its_truth_table_says() {
    let bit = Bool::constant;
    assert_eq!(
        (
            UNARY_ASSERTS
                .iter()
                .map(|(op, _)| {
                    let results = combinations::<1>()
                        .into_iter()
                        .map(|[a]| outcome((op.apply)(&bit(a), op.rule)))
                        .collect::<Vec<_>>();
                    (op.name, results)
                })
                .collect::<Visited<_>>(),
            BINARY_ASSERTS
                .iter()
                .map(|(op, _)| {
                    let results = combinations::<2>()
                        .into_iter()
                        .map(|[a, b]| outcome((op.apply)(&bit(a), &bit(b), op.rule)))
                        .collect::<Vec<_>>();
                    (op.name, results)
                })
                .collect::<Visited<_>>(),
            combinations::<3>()
                .into_iter()
                .map(|[a, b, c]| {
                    outcome(bit(a).assert_equal_if(&bit(b), &bit(c), ASSERT_EQUAL_IF_RULE))
                })
                .collect::<Vec<_>>(),
        ),
        (
            UNARY_ASSERTS
                .iter()
                .map(|(op, holds)| {
                    (
                        op.name,
                        holds.map(|holds| fixture_rule(op.rule, holds)).to_vec(),
                    )
                })
                .collect::<Visited<_>>(),
            BINARY_ASSERTS
                .iter()
                .map(|(op, holds)| {
                    (
                        op.name,
                        holds.map(|holds| fixture_rule(op.rule, holds)).to_vec(),
                    )
                })
                .collect::<Visited<_>>(),
            [true, true, true, false, true, false, true, true]
                .map(|holds| rule(ASSERT_EQUAL_IF_RULE, holds))
                .to_vec(),
        )
    );
}

#[test]
fn every_boolean_vector_holds_natively_in_every_output_fixture() {
    assert_eq!(
        (
            per_vector(&BITS, |bit| {
                let x = bit.field();
                (
                    convert_forms(&NativeOutput, (x, x)),
                    NativeOutput.visit(&Not {
                        a: x,
                        out: Field::from(!bit.bit()),
                    }),
                    every_constant_form(&NativeOutput, x, |gate, form| {
                        Field::from(form.output(gate, bit.bit()))
                    }),
                )
            }),
            every_gate(&NativeOutput, &BOOLEAN_PAIRS, honest),
            every_fold(&NativeOutput, &FLAGS, |op, flags| {
                Field::from((op.truth)(flags))
            }),
            per_vector(&TRIPLES, |triple| {
                let (c, t, f) = triple.fields();
                select_forms(&NativeOutput, (c, t, f, Field::from(triple.selected())))
            }),
        ),
        (
            per_vector(&BITS, |bit| (
                each(&convert_form_names(), constant_output(bit.bit())),
                constant_output(!bit.bit()),
                per_gate(|gate| {
                    CONSTANT_FORMS
                        .iter()
                        .map(|form| (form.name, constant_output(form.output(gate, bit.bit()))))
                        .collect()
                }),
            )),
            per_pair(&BOOLEAN_PAIRS, |gate, pair| {
                let (a, b) = pair.bits();
                constant_output(gate.output(a, b))
            }),
            FOLDS
                .iter()
                .map(|op| (
                    op.name,
                    per_flags(|flags| constant_output((op.truth)(flags)))
                ))
                .collect::<Visited<_>>(),
            per_vector(&TRIPLES, |triple| each(
                &select_form_names(),
                constant_output(triple.selected())
            )),
        )
    );
}

#[test]
fn every_assertion_fixture_holds_natively_exactly_as_its_truth_table_says() {
    let equal_if = |triple: &Triple| {
        let Triple {
            condition: a,
            if_true: b,
            if_false: condition,
            ..
        } = *triple;
        (
            native(&AssertEqualIf {
                a: Field::from(a),
                b: Field::from(b),
                condition: Field::from(condition),
            }),
            fixture_rule(ASSERT_EQUAL_IF_RULE, !condition || a == b),
        )
    };
    assert_eq!(
        (
            per_vector(&BITS, |bit| unary_asserts(&Native, bit.field())),
            per_vector(&BOOLEAN_PAIRS, |pair| binary_asserts(
                &Native,
                pair.fields()
            )),
            per_vector(&TRIPLES, |triple| equal_if(triple).0),
            per_vector(&BITS, |bit| assert_true_if_forms(&Native, bit.field())),
        ),
        (
            per_vector(&BITS, |bit| {
                unary_assert_names()
                    .into_iter()
                    .zip(&UNARY_ASSERTS)
                    .map(|(name, (op, holds))| {
                        (name, fixture_rule(op.rule, holds[usize::from(bit.bit())]))
                    })
                    .collect()
            }),
            per_vector(&BOOLEAN_PAIRS, |pair| {
                binary_assert_names()
                    .into_iter()
                    .zip(&BINARY_ASSERTS)
                    .map(|(name, (op, holds))| (name, fixture_rule(op.rule, holds[pair.row()])))
                    .collect()
            }),
            per_vector(&TRIPLES, |triple| equal_if(triple).1),
            per_vector(&BITS, |bit| {
                assert_true_if_form_names()
                    .into_iter()
                    .zip(&ASSERT_TRUE_IF_FORMS)
                    .map(|(name, form)| {
                        (
                            name,
                            fixture_rule(ASSERT_TRUE_IF_RULE, form.holds(bit.bit())),
                        )
                    })
                    .collect()
            }),
        )
    );
}

/// The wrong claims for an output whose truth is t: the negation of t, then
/// every value of `WRONG_CLAIMS`.
fn wrong_claims() -> Vec<(&'static str, Option<Field>)> {
    let mut claims = vec![("the negation", None)];
    claims.extend(
        WRONG_CLAIMS
            .iter()
            .map(|claim| (claim.name, Some(claim.field()))),
    );
    claims
}

fn claim(wrong: Option<Field>, truth: bool) -> Field {
    wrong.unwrap_or(Field::from(!truth))
}

#[test]
fn every_wrong_claim_breaks_exactly_the_fixture_rule_natively() {
    let computed: Visited<_> = wrong_claims()
        .into_iter()
        .map(|(name, wrong)| {
            let refusals = (
                every_gate(&Native, &BOOLEAN_PAIRS, |gate, pair| {
                    let (a, b) = pair.fields();
                    let (x, y) = pair.bits();
                    (a, b, claim(wrong, gate.output(x, y)))
                }),
                per_vector(&BITS, |bit| {
                    let (x, a) = (bit.field(), bit.bit());
                    (
                        native(&Not {
                            a: x,
                            out: claim(wrong, !a),
                        }),
                        convert_forms(&Native, (x, claim(wrong, a))),
                        every_constant_form(&Native, x, |gate, form| {
                            claim(wrong, form.output(gate, a))
                        }),
                    )
                }),
                every_fold(&Native, &FLAGS, |op, flags| claim(wrong, (op.truth)(flags))),
                per_vector(&TRIPLES, |triple| {
                    let (c, t, f) = triple.fields();
                    select_forms(&Native, (c, t, f, claim(wrong, triple.selected())))
                }),
            );
            (name, refusals)
        })
        .collect();
    let expected: Visited<_> = wrong_claims()
        .into_iter()
        .map(|(name, _)| {
            let refusals = (
                per_pair(&BOOLEAN_PAIRS, |gate, _| Err(broken(gate.rule))),
                per_vector(&BITS, |_| {
                    (
                        Err(broken(NOT_RULE)),
                        each(&convert_form_names(), Err(broken(CONVERT_RULE))),
                        per_gate(|gate| each(&constant_form_names(), Err(broken(gate.rule)))),
                    )
                }),
                FOLDS
                    .iter()
                    .map(|op| (op.name, per_flags(|_| Err(broken(op.rule)))))
                    .collect::<Visited<_>>(),
                per_vector(&TRIPLES, |_| {
                    each(&select_form_names(), Err(broken(SELECT_RULE)))
                }),
            );
            (name, refusals)
        })
        .collect();
    assert_eq!(computed, expected);
}

#[test]
fn every_non_boolean_operand_is_refused_natively_with_not_zero_or_one() {
    let zero = Field::from(0u64);
    let flags = |values: [&str; 3]| values.map(field);
    assert_eq!(
        (
            per_vector(&NON_BOOLEAN, |x| {
                let x = x.field();
                (
                    convert_forms(&Native, (x, x)),
                    native(&Not { a: x, out: zero }),
                    every_constant_form(&Native, x, |_, _| zero),
                    unary_asserts(&Native, x),
                    assert_true_if_forms(&Native, x),
                    select_forms(&Native, (x, zero, zero, zero)),
                    select_forms(&Native, (zero, zero, x, x)),
                )
            }),
            every_gate(&Native, &NON_BOOLEAN_PAIRS, |gate, pair| {
                let (a, b) = pair.fields();
                (a, b, gate.polynomial(a.into(), b.into()).into())
            }),
            per_vector(&NON_BOOLEAN_PAIRS, |pair| {
                let (a, b) = pair.fields();
                (
                    binary_asserts(&Native, (a, b)),
                    native(&AssertEqualIf {
                        a,
                        b,
                        condition: zero,
                    }),
                )
            }),
            (
                native(&Fold::<ALL, 3> {
                    flags: flags(DECEPTIVE_ALL.1),
                    out: Field::from(1u64),
                }),
                native(&Fold::<ANY, 3> {
                    flags: flags(DECEPTIVE_ANY.1),
                    out: zero,
                }),
            ),
        ),
        (
            per_vector(&NON_BOOLEAN, |_| (
                each(&convert_form_names(), Err(NOT_ZERO_OR_ONE)),
                Err(NOT_ZERO_OR_ONE),
                per_gate(|_| each(&constant_form_names(), Err(NOT_ZERO_OR_ONE))),
                each(&unary_assert_names(), Err(NOT_ZERO_OR_ONE)),
                each(&assert_true_if_form_names(), Err(NOT_ZERO_OR_ONE)),
                each(&select_form_names(), Err(NOT_ZERO_OR_ONE)),
                each(&select_form_names(), Err(NOT_ZERO_OR_ONE)),
            )),
            per_pair(&NON_BOOLEAN_PAIRS, |_, _| Err(NOT_ZERO_OR_ONE)),
            per_vector(&NON_BOOLEAN_PAIRS, |_| (
                each(&binary_assert_names(), Err(NOT_ZERO_OR_ONE)),
                Err(NOT_ZERO_OR_ONE),
            )),
            (Err(NOT_ZERO_OR_ONE), Err(NOT_ZERO_OR_ONE)),
        )
    );
}
