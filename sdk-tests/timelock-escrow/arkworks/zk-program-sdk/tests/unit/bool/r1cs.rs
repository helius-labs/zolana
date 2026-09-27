use ark_bn254::Fr;
use ark_ff::{One, Zero};
use zk_program_sdk::{
    circuit::{CircuitVar, Field, VariableRole},
    testing::PrivateVariableReport,
    ProverError, ZkCircuit,
};

use super::{
    fixtures::{
        assert_true_if_forms, constant_form_names, convert_form_names, convert_forms,
        every_constant_form, every_fold, every_gate, fold, select_form_names, select_forms,
        unary_asserts, AssertEqualIf, AssertTrueIfConstant, AssertedBinary, AssertedUnary, Choose,
        ChooseConstantBranches, ChooseConstantCondition, ConstantClaim, ConstantForm, Constants,
        Converted, Fold, Gate, Linear, Not, Variables, ALL, ANY, ASSERT_EQUAL_IF_RULE,
        ASSERT_NOT_EQUAL, ASSERT_TRUE_IF_FORMS, BINARY_ASSERTS, CONSTANT_FORMS, CONVERT_RULE,
        FOLDS, GATES, NOT_BOOLEAN, NOT_RULE, SELECT_RULE, UNARY_ASSERTS,
    },
    vectors::{
        per_flags, Pair, Triple, BITS, BOOLEAN_PAIRS, DECEPTIVE_ALL, DECEPTIVE_ANY, FLAGS,
        NON_BOOLEAN, NON_BOOLEAN_PAIRS, TRIPLES,
    },
};
use crate::harness::{
    field::{field, MODULUS_MINUS_1},
    fixture::{
        assignment, breaks_rule, check_constraints, check_private_variables, check_tampered, each,
        export, exported, per_vector, size, Export, Fixture, ProverRefusal, Refusal, Size, Visit,
        Visited,
    },
    iden3::{R1cs, R1csHeader, Row},
};

fn terms(terms: &[(i64, usize)]) -> Row {
    terms
        .iter()
        .map(|(coefficient, wire)| (Fr::from(*coefficient), *wire))
        .collect()
}

/// The booleanity row w * (w - 1) = 0 of the input at `wire`.
fn boolean(wire: usize) -> (Row, Row, Row) {
    (terms(&[(1, wire)]), terms(&[(-1, 0), (1, wire)]), vec![])
}

/// The row `terms * 1 = 0` of an assertion, its terms sorted by wire with
/// every zero coefficient dropped.
fn linear(terms: &[(Fr, usize)]) -> (Row, Row, Row) {
    let mut row: Row = terms
        .iter()
        .filter(|(coefficient, _)| !coefficient.is_zero())
        .copied()
        .collect();
    row.sort_by_key(|(_, wire)| *wire);
    (row, vec![(Fr::one(), 0)], vec![])
}

fn r1cs(variables: usize, rows: Vec<(Row, Row, Row)>) -> R1cs {
    let (mut a, mut b, mut c) = (vec![], vec![], vec![]);
    for (row_a, row_b, row_c) in rows {
        a.push(row_a);
        b.push(row_b);
        c.push(row_c);
    }
    R1cs {
        header: R1csHeader::bn254(variables, 0, variables - 1, a.len()),
        a,
        b,
        c,
        wire_labels: (0..u64::try_from(variables).expect("variables")).collect(),
    }
}

fn rows(r1cs: &R1cs) -> Vec<(Row, Row, Row)> {
    r1cs.rows()
        .map(|(a, b, c)| {
            let mut a = a.clone();
            a.sort_by_key(|(_, wire)| *wire);
            (a, b.clone(), c.clone())
        })
        .collect()
}

pub fn unsatisfied_rows(r1cs: &R1cs, witness: &[Fr]) -> Vec<usize> {
    let evaluate = |row: &Row| {
        row.iter().fold(Fr::zero(), |sum, (coefficient, wire)| {
            sum + *coefficient * witness[*wire]
        })
    };
    r1cs.rows()
        .enumerate()
        .filter(|(_, (a, b, c))| evaluate(a) * evaluate(b) != evaluate(c))
        .map(|(row, _)| row)
        .collect()
}

fn fr(value: bool) -> Fr {
    Fr::from(value)
}

fn per_gate<T>(value: impl Fn(&Gate) -> T) -> Visited<T> {
    GATES.iter().map(|gate| (gate.name, value(gate))).collect()
}

fn honest(gate: &Gate, pair: &Pair) -> (Field, Field, Field) {
    let (a, b) = pair.fields();
    let (x, y) = pair.bits();
    (a, b, Field::from(gate.output(x, y)))
}

#[test]
fn a_conversion_exports_exactly_the_booleanity_row_then_the_claim_row_in_every_form() {
    let one = Fr::one();
    assert_eq!(
        (
            exported::<Converted<1>>(),
            convert_forms(&Export, (Field::from(0u64), Field::from(0u64))),
        ),
        (
            r1cs(3, vec![boolean(1), linear(&[(one, 1), (-one, 2)])]),
            each(&convert_form_names(), export::<Converted<0>>()),
        )
    );
}

#[test]
fn a_bool_constant_allocates_nothing_and_puts_its_value_on_variable_zero() {
    let one = Fr::one();
    assert_eq!(
        (
            exported::<ConstantClaim<false>>(),
            exported::<ConstantClaim<true>>(),
        ),
        (
            r1cs(2, vec![linear(&[(-one, 1)])]),
            r1cs(2, vec![linear(&[(one, 0), (-one, 1)])]),
        )
    );
}

#[test]
fn every_operation_on_constants_adds_no_constraint_and_no_variable() {
    assert_eq!(
        (
            exported::<Constants>(),
            assignment(&Constants),
            check_constraints(&Constants)
        ),
        (r1cs(1, vec![]), vec![Fr::one()], Ok(0))
    );
}

#[test]
fn not_and_every_operation_with_a_constant_operand_add_no_constraint() {
    let fixture = Linear {
        a: Field::from(1u64),
    };
    assert_eq!(
        (
            exported::<Linear>(),
            assignment(&fixture),
            check_constraints(&fixture)
        ),
        (r1cs(2, vec![boolean(1)]), vec![Fr::one(); 2], Ok(1))
    );
}

#[test]
fn not_exports_exactly_the_booleanity_row_and_the_negated_claim_row() {
    let one = Fr::one();
    assert_eq!(
        exported::<Not>(),
        r1cs(
            3,
            vec![boolean(1), linear(&[(one, 0), (-one, 1), (-one, 2)])]
        )
    );
}

#[test]
fn and_exports_exactly_the_golden_rows_and_header() {
    let one = Fr::one();
    assert_eq!(
        exported::<Variables<0>>(),
        R1cs {
            header: R1csHeader::bn254(5, 0, 4, 4),
            a: vec![
                vec![(one, 1)],
                vec![(one, 2)],
                vec![(one, 1)],
                vec![(one, 4), (-one, 3)]
            ],
            b: vec![
                vec![(-one, 0), (one, 1)],
                vec![(-one, 0), (one, 2)],
                vec![(one, 2)],
                vec![(one, 0)]
            ],
            c: vec![vec![], vec![], vec![(one, 4)], vec![]],
            wire_labels: vec![0, 1, 2, 3, 4],
        }
    );
}

struct Shape;

impl<C> Visit<C> for Shape {
    type Output = (Size, Vec<(Row, Row, Row)>);

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> Self::Output {
        (size::<F>(), rows(&exported::<F>()))
    }
}

fn gate_row(gate: &Gate) -> (Row, Row, Row) {
    let [one, a, b, product] = gate.coefficients();
    linear(&[(one, 0), (a, 1), (b, 2), (-Fr::one(), 3), (product, 4)])
}

#[test]
fn every_two_variable_gate_costs_one_product_row_and_inlines_its_truth_table() {
    let one = Fr::one();
    let product = (vec![(one, 1)], vec![(one, 2)], vec![(one, 4)]);
    assert_eq!(
        every_gate(&Shape, &BOOLEAN_PAIRS[..1], honest),
        per_gate(|gate| vec![(
            BOOLEAN_PAIRS[0].name,
            (
                Size {
                    constraints: 4,
                    variables: 5
                },
                vec![boolean(1), boolean(2), product.clone(), gate_row(gate)]
            )
        )])
    );
}

#[test]
fn every_constant_operand_form_inlines_to_the_affine_form_of_its_truth_table() {
    let affine = |gate: &Gate, form: &ConstantForm| {
        let (at_zero, at_one) = (fr(form.output(gate, false)), fr(form.output(gate, true)));
        linear(&[(at_zero, 0), (at_one - at_zero, 1), (-Fr::one(), 2)])
    };
    assert_eq!(
        every_constant_form(&Shape, Field::from(0u64), |_, _| Field::from(0u64)),
        per_gate(|gate| {
            CONSTANT_FORMS
                .iter()
                .map(|form| {
                    (
                        form.name,
                        (
                            Size {
                                constraints: 2,
                                variables: 3,
                            },
                            vec![boolean(1), affine(gate, form)],
                        ),
                    )
                })
                .collect()
        })
    );
}

#[test]
fn all_and_any_of_two_flags_export_exactly_the_equality_test_rows() {
    let one = Fr::one();
    let two = Fr::from(2u64);
    let equality = |a: Row| {
        vec![
            (a.clone(), vec![(one, 5)], vec![(one, 4)]),
            (a, vec![(one, 0), (-one, 4)], vec![]),
        ]
    };
    let with = |rows: Vec<(Row, Row, Row)>, claim| {
        let mut all = vec![boolean(1), boolean(2)];
        all.extend(rows);
        all.push(claim);
        r1cs(6, all)
    };
    assert_eq!(
        (exported::<Fold<ALL, 2>>(), exported::<Fold<ANY, 2>>()),
        (
            with(
                equality(vec![(two, 0), (-one, 1), (-one, 2)]),
                linear(&[(one, 0), (-one, 3), (-one, 4)])
            ),
            with(
                equality(vec![(-one, 1), (-one, 2)]),
                linear(&[(-one, 3), (one, 4)])
            ),
        )
    );
}

#[test]
fn a_fold_of_at_most_one_flag_adds_no_constraint_beyond_the_claim() {
    let one = Fr::one();
    assert_eq!(
        (
            exported::<Fold<ALL, 0>>(),
            exported::<Fold<ANY, 0>>(),
            exported::<Fold<ALL, 1>>(),
            exported::<Fold<ANY, 1>>(),
        ),
        (
            r1cs(2, vec![linear(&[(one, 0), (-one, 1)])]),
            r1cs(2, vec![linear(&[(-one, 1)])]),
            r1cs(3, vec![boolean(1), linear(&[(one, 1), (-one, 2)])]),
            r1cs(3, vec![boolean(1), linear(&[(one, 1), (-one, 2)])]),
        )
    );
}

#[test]
fn a_fold_of_n_flags_costs_n_booleanity_rows_two_equality_rows_and_the_claim() {
    let fold_size = |constraints, variables| Size {
        constraints,
        variables,
    };
    assert_eq!(
        [
            size::<Fold<ALL, 2>>(),
            size::<Fold<ANY, 2>>(),
            size::<Fold<ALL, 3>>(),
            size::<Fold<ANY, 3>>(),
        ],
        [
            fold_size(5, 6),
            fold_size(5, 6),
            fold_size(6, 7),
            fold_size(6, 7)
        ]
    );
}

#[test]
fn select_exports_exactly_the_golden_rows_in_both_forms() {
    let one = Fr::one();
    let zero = Field::from(0u64);
    assert_eq!(
        (
            exported::<Choose<0>>(),
            select_forms(&Export, (zero, zero, zero, zero)),
        ),
        (
            r1cs(
                6,
                vec![
                    boolean(1),
                    boolean(2),
                    boolean(3),
                    (vec![(one, 1)], vec![(one, 2), (-one, 3)], vec![(one, 5)]),
                    linear(&[(one, 3), (-one, 4), (one, 5)]),
                ]
            ),
            each(&select_form_names(), export::<Choose<0>>()),
        )
    );
}

#[test]
fn a_constant_condition_or_constant_branches_make_select_linear() {
    let one = Fr::one();
    let branches = |at_false: i64, slope: i64| {
        r1cs(
            3,
            vec![
                boolean(1),
                linear(&[(Fr::from(at_false), 0), (Fr::from(slope), 1), (-one, 2)]),
            ],
        )
    };
    assert_eq!(
        (
            exported::<ChooseConstantCondition<true>>(),
            exported::<ChooseConstantCondition<false>>(),
            [
                exported::<ChooseConstantBranches<false, false>>(),
                exported::<ChooseConstantBranches<false, true>>(),
                exported::<ChooseConstantBranches<true, false>>(),
                exported::<ChooseConstantBranches<true, true>>(),
            ],
        ),
        (
            r1cs(
                4,
                vec![boolean(1), boolean(2), linear(&[(one, 1), (-one, 3)])]
            ),
            r1cs(
                4,
                vec![boolean(1), boolean(2), linear(&[(one, 2), (-one, 3)])]
            ),
            [
                branches(0, 0),
                branches(1, -1),
                branches(0, 1),
                branches(1, 0)
            ],
        )
    );
}

#[test]
fn every_assertion_exports_exactly_its_golden_rows() {
    let one = Fr::one();
    let two = Fr::from(2u64);
    assert_eq!(
        (
            [
                exported::<AssertedUnary<0>>(),
                exported::<AssertedUnary<1>>(),
            ],
            [
                exported::<AssertedBinary<0>>(),
                exported::<AssertedBinary<1>>(),
                exported::<AssertedBinary<2>>(),
            ],
            exported::<AssertEqualIf>(),
        ),
        (
            [
                r1cs(2, vec![boolean(1), linear(&[(one, 0), (-one, 1)])]),
                r1cs(2, vec![boolean(1), linear(&[(-one, 1)])]),
            ],
            [
                r1cs(
                    3,
                    vec![
                        boolean(1),
                        boolean(2),
                        (vec![(-one, 0), (one, 1)], vec![(one, 2)], vec![])
                    ]
                ),
                r1cs(
                    3,
                    vec![boolean(1), boolean(2), linear(&[(one, 1), (-one, 2)])]
                ),
                r1cs(
                    4,
                    vec![
                        boolean(1),
                        boolean(2),
                        (vec![(one, 1)], vec![(one, 2)], vec![(one, 3)]),
                        linear(&[(-one, 0), (one, 1), (one, 2), (-two, 3)]),
                    ]
                ),
            ],
            r1cs(
                4,
                vec![
                    boolean(1),
                    boolean(2),
                    boolean(3),
                    (vec![(one, 1), (-one, 2)], vec![(one, 3)], vec![])
                ]
            ),
        )
    );
}

#[test]
fn a_constant_operand_of_assert_true_if_leaves_at_most_one_linear_row() {
    let one = Fr::one();
    assert_eq!(
        [
            exported::<AssertTrueIfConstant<0>>(),
            exported::<AssertTrueIfConstant<1>>(),
            exported::<AssertTrueIfConstant<2>>(),
            exported::<AssertTrueIfConstant<3>>(),
        ],
        [
            r1cs(2, vec![boolean(1)]),
            r1cs(2, vec![boolean(1), linear(&[(one, 0), (-one, 1)])]),
            r1cs(2, vec![boolean(1), linear(&[(one, 1)])]),
            r1cs(2, vec![boolean(1)]),
        ]
    );
}

/// Visits a fixture as a `Fixture<()>`, for fixtures that also expose a
/// computed value.
fn direct<V: Visit, F: Fixture>(visitor: &V, fixture: &F) -> V::Output {
    visitor.visit(fixture)
}

struct Completes;

impl<C> Visit<C> for Completes {
    type Output = (Result<usize, ProverRefusal>, Option<usize>);

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        (
            check_constraints(fixture),
            exported::<F>().first_unsatisfied(&assignment(fixture)),
        )
    }
}

fn completes(constraints: usize) -> (Result<usize, ProverRefusal>, Option<usize>) {
    (Ok(constraints), None)
}

fn fold_constraints(flags: usize) -> usize {
    match flags {
        0 => 1,
        1 => 2,
        n => n + 3,
    }
}

#[test]
fn every_boolean_vector_satisfies_every_exported_row_and_every_proving_row() {
    let zero = Field::from(0u64);
    assert_eq!(
        (
            per_vector(&BITS, |bit| {
                let x = bit.field();
                (
                    convert_forms(&Completes, (x, x)),
                    direct(
                        &Completes,
                        &Not {
                            a: x,
                            out: Field::from(!bit.bit()),
                        },
                    ),
                    every_constant_form(&Completes, x, |gate, form| {
                        Field::from(form.output(gate, bit.bit()))
                    }),
                )
            }),
            every_gate(&Completes, &BOOLEAN_PAIRS, honest),
            every_fold(&Completes, &FLAGS, |op, flags| {
                Field::from((op.truth)(flags))
            }),
            per_vector(&TRIPLES, |triple| {
                let (c, t, f) = triple.fields();
                select_forms(&Completes, (c, t, f, Field::from(triple.selected())))
            }),
            (
                direct(
                    &Completes,
                    &ChooseConstantCondition::<true> {
                        if_true: Field::from(1u64),
                        if_false: zero,
                        out: Field::from(1u64),
                    }
                ),
                direct(
                    &Completes,
                    &ChooseConstantBranches::<false, true> {
                        condition: zero,
                        out: Field::from(1u64),
                    }
                ),
            ),
        ),
        (
            per_vector(&BITS, |_| (
                each(&convert_form_names(), completes(2)),
                completes(2),
                per_gate(|_| each(&constant_form_names(), completes(2))),
            )),
            per_gate(|_| per_vector(&BOOLEAN_PAIRS, |_| completes(4))),
            FOLDS
                .iter()
                .map(|op| (
                    op.name,
                    per_flags(|flags| completes(fold_constraints(flags.len())))
                ))
                .collect::<Visited<_>>(),
            per_vector(&TRIPLES, |_| each(&select_form_names(), completes(5))),
            (completes(3), completes(2)),
        )
    );
}

fn holding_binary<const OP: usize, V: Visit>(visitor: &V) -> Visited<V::Output> {
    let (_, holds) = &BINARY_ASSERTS[OP];
    BOOLEAN_PAIRS
        .iter()
        .filter(|pair| holds[pair.row()])
        .map(|pair| {
            let (a, b) = pair.fields();
            (pair.name, visitor.visit(&AssertedBinary::<OP> { a, b }))
        })
        .collect()
}

fn holding_form<const FORM: usize, V: Visit>(visitor: &V) -> Visited<V::Output> {
    BITS.iter()
        .filter(|bit| ASSERT_TRUE_IF_FORMS[FORM].holds(bit.bit()))
        .map(|bit| {
            (
                bit.name,
                visitor.visit(&AssertTrueIfConstant::<FORM> { x: bit.field() }),
            )
        })
        .collect()
}

fn equal_if_holds(triple: &Triple) -> bool {
    !triple.if_false || triple.condition == triple.if_true
}

fn holding_equal_if<V: Visit>(visitor: &V) -> Visited<V::Output> {
    TRIPLES
        .iter()
        .filter(|triple| equal_if_holds(triple))
        .map(|triple| {
            let (a, b, condition) = triple.fields();
            (
                triple.name,
                visitor.visit(&AssertEqualIf { a, b, condition }),
            )
        })
        .collect()
}

#[test]
fn every_holding_assertion_satisfies_every_exported_row_and_every_proving_row() {
    let (zero, one) = (Field::from(0u64), Field::from(1u64));
    let binary = |op: usize, constraints: usize| {
        let (_, holds) = &BINARY_ASSERTS[op];
        BOOLEAN_PAIRS
            .iter()
            .filter(|pair| holds[pair.row()])
            .map(|pair| (pair.name, completes(constraints)))
            .collect::<Visited<_>>()
    };
    let form = |form: usize, constraints: usize| {
        BITS.iter()
            .filter(|bit| ASSERT_TRUE_IF_FORMS[form].holds(bit.bit()))
            .map(|bit| (bit.name, completes(constraints)))
            .collect::<Visited<_>>()
    };
    assert_eq!(
        (
            [
                direct(&Completes, &AssertedUnary::<0> { a: one }),
                direct(&Completes, &AssertedUnary::<1> { a: zero }),
            ],
            [
                holding_binary::<0, _>(&Completes),
                holding_binary::<1, _>(&Completes),
                holding_binary::<2, _>(&Completes),
            ],
            holding_equal_if(&Completes),
            [
                holding_form::<0, _>(&Completes),
                holding_form::<1, _>(&Completes),
                holding_form::<2, _>(&Completes),
                holding_form::<3, _>(&Completes),
            ],
        ),
        (
            [completes(2), completes(2)],
            [binary(0, 3), binary(1, 3), binary(2, 4)],
            TRIPLES
                .iter()
                .filter(|triple| equal_if_holds(triple))
                .map(|triple| (triple.name, completes(4)))
                .collect::<Visited<_>>(),
            [form(0, 1), form(1, 2), form(2, 2), form(3, 1)],
        )
    );
}

struct Shifted {
    wire: usize,
    by: i64,
}

impl<C> Visit<C> for Shifted {
    type Output = Result<(), ProverRefusal>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        let honest = assignment(fixture)[self.wire];
        check_tampered(fixture, self.wire, Field::from(honest + Fr::from(self.by)))
    }
}

fn shifted<C, F: Fixture<C>>(wire: usize, fixture: &F) -> [Result<(), ProverRefusal>; 2] {
    [
        Shifted { wire, by: 1 }.visit(fixture),
        Shifted { wire, by: -1 }.visit(fixture),
    ]
}

struct ShiftedOutput(usize);

impl<C> Visit<C> for ShiftedOutput {
    type Output = [Result<(), ProverRefusal>; 2];

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        shifted::<C, F>(self.0, fixture)
    }
}

/// Visits the honest `Fold` of every op and flag combination with the
/// visitor `visitor(flags)` builds.
fn per_fold<V: Visit<Result<CircuitVar, Refusal>>>(
    visitor: impl Fn(usize) -> V,
) -> Visited<Visited<V::Output>> {
    FOLDS
        .iter()
        .enumerate()
        .map(|(op, fold_op)| {
            let visited = per_flags(|flags| {
                let fields: Vec<Field> = flags.iter().map(|flag| Field::from(*flag)).collect();
                let out = Field::from((fold_op.truth)(flags));
                let visitor = visitor(flags.len());
                match op {
                    ALL => fold::<ALL, V>(&visitor, &fields, out),
                    _ => fold::<ANY, V>(&visitor, &fields, out),
                }
            });
            (fold_op.name, visited)
        })
        .collect()
}

#[test]
fn a_claim_off_by_one_breaks_exactly_the_claim_row_with_the_fixture_rule() {
    let refused = |row, rule| [Err(breaks_rule(row, rule)), Err(breaks_rule(row, rule))];
    assert_eq!(
        (
            per_vector(&BITS, |bit| {
                let x = bit.field();
                (
                    convert_forms(&ShiftedOutput(2), (x, x)),
                    shifted::<(), _>(
                        2,
                        &Not {
                            a: x,
                            out: Field::from(!bit.bit()),
                        },
                    ),
                    every_constant_form(&ShiftedOutput(2), x, |gate, form| {
                        Field::from(form.output(gate, bit.bit()))
                    }),
                )
            }),
            every_gate(&ShiftedOutput(3), &BOOLEAN_PAIRS, honest),
            per_fold(|flags| ShiftedOutput(flags + 1)),
            per_vector(&TRIPLES, |triple| {
                let (c, t, f) = triple.fields();
                select_forms(&ShiftedOutput(4), (c, t, f, Field::from(triple.selected())))
            }),
        ),
        (
            per_vector(&BITS, |_| (
                each(&convert_form_names(), refused(1, CONVERT_RULE)),
                refused(1, NOT_RULE),
                per_gate(|gate| each(&constant_form_names(), refused(1, gate.rule))),
            )),
            per_gate(|gate| per_vector(&BOOLEAN_PAIRS, |_| refused(3, gate.rule))),
            FOLDS
                .iter()
                .map(|op| (
                    op.name,
                    per_flags(|flags| refused(fold_constraints(flags.len()) - 1, op.rule))
                ))
                .collect::<Visited<_>>(),
            per_vector(&TRIPLES, |_| each(
                &select_form_names(),
                refused(4, SELECT_RULE)
            )),
        )
    );
}

fn gate_rows<const GATE: usize>() -> (&'static str, Visited<Vec<usize>>) {
    let gate = &GATES[GATE];
    let r1cs = exported::<Variables<GATE>>();
    let rows = per_vector(&NON_BOOLEAN_PAIRS, |pair| {
        let (a, b) = pair.fields();
        let (a, b) = (Fr::from(a), Fr::from(b));
        unsatisfied_rows(&r1cs, &[Fr::one(), a, b, gate.polynomial(a, b), a * b])
    });
    (gate.name, rows)
}

fn non_boolean_rows(pair: &Pair) -> Vec<usize> {
    [pair.a, pair.b]
        .iter()
        .enumerate()
        .filter(|(_, x)| !["0", "1"].contains(x))
        .map(|(row, _)| row)
        .collect()
}

#[test]
fn a_non_boolean_operand_breaks_exactly_its_booleanity_rows_with_every_other_row_satisfied() {
    let (one, zero) = (Fr::one(), Fr::zero());
    let flags = |values: [&str; 3]| values.map(|decimal| Fr::from(field(decimal)));
    let [a0, a1, a2] = flags(DECEPTIVE_ALL.1);
    let [n0, n1, n2] = flags(DECEPTIVE_ANY.1);
    let per_x = per_vector(&NON_BOOLEAN, |x| {
        let x = Fr::from(x.field());
        (
            unsatisfied_rows(&exported::<Converted<0>>(), &[one, x, x]),
            unsatisfied_rows(&exported::<Not>(), &[one, x, one - x]),
            [
                unsatisfied_rows(&exported::<Choose<0>>(), &[one, x, one, zero, x, x]),
                unsatisfied_rows(&exported::<Choose<0>>(), &[one, one, x, zero, x, x]),
                unsatisfied_rows(&exported::<Choose<0>>(), &[one, zero, zero, x, x, zero]),
            ],
            [
                unsatisfied_rows(&exported::<AssertedBinary<0>>(), &[one, x, zero]),
                unsatisfied_rows(&exported::<AssertedBinary<0>>(), &[one, one, x]),
            ],
            [
                unsatisfied_rows(&exported::<AssertEqualIf>(), &[one, x, zero, zero]),
                unsatisfied_rows(&exported::<AssertEqualIf>(), &[one, one, one, x]),
            ],
        )
    });
    assert_eq!(
        (
            [
                gate_rows::<0>(),
                gate_rows::<1>(),
                gate_rows::<2>(),
                gate_rows::<3>(),
                gate_rows::<4>(),
                gate_rows::<5>(),
            ],
            per_x,
            unsatisfied_rows(
                &exported::<Fold<ALL, 3>>(),
                &[one, a0, a1, a2, one, zero, one]
            ),
            unsatisfied_rows(
                &exported::<Fold<ANY, 3>>(),
                &[one, n0, n1, n2, zero, zero, one]
            ),
        ),
        (
            GATES.map(|gate| (gate.name, per_vector(&NON_BOOLEAN_PAIRS, non_boolean_rows))),
            per_vector(&NON_BOOLEAN, |_| (
                vec![0],
                vec![0],
                [vec![0], vec![1], vec![2]],
                [vec![0], vec![1]],
                [vec![0], vec![2]],
            )),
            vec![0],
            vec![1],
        )
    );
}

struct NonBooleanInput(usize);

impl<C> Visit<C> for NonBooleanInput {
    type Output = [Result<(), ProverRefusal>; 2];

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        [field("2"), field(MODULUS_MINUS_1)].map(|value| check_tampered(fixture, self.0, value))
    }
}

#[test]
fn a_non_boolean_input_breaks_its_booleanity_row_in_the_proving_rows_with_the_sdk_rule() {
    let refused = |wire: usize| {
        let row = wire - 1;
        [
            Err(breaks_rule(row, NOT_BOOLEAN)),
            Err(breaks_rule(row, NOT_BOOLEAN)),
        ]
    };
    let (zero, one) = (Field::from(0u64), Field::from(1u64));
    let inputs = |wires: std::ops::RangeInclusive<usize>,
                  visit: &dyn Fn(usize) -> [Result<(), ProverRefusal>; 2]| {
        wires.map(visit).collect::<Vec<_>>()
    };
    let expected = |wires: std::ops::RangeInclusive<usize>| wires.map(refused).collect::<Vec<_>>();
    assert_eq!(
        (
            per_vector(&BITS, |bit| {
                let x = bit.field();
                (
                    convert_forms(&NonBooleanInput(1), (x, x)),
                    direct(
                        &NonBooleanInput(1),
                        &Not {
                            a: x,
                            out: Field::from(!bit.bit()),
                        },
                    ),
                    every_constant_form(&NonBooleanInput(1), x, |gate, form| {
                        Field::from(form.output(gate, bit.bit()))
                    }),
                )
            }),
            [1, 2].map(|wire| every_gate(&NonBooleanInput(wire), &BOOLEAN_PAIRS[2..3], honest)),
            inputs(1..=3, &|wire| {
                direct(
                    &NonBooleanInput(wire),
                    &Fold::<ALL, 3> {
                        flags: [one, zero, one],
                        out: zero,
                    },
                )
            }),
            inputs(1..=3, &|wire| {
                direct(
                    &NonBooleanInput(wire),
                    &Choose::<0> {
                        condition: one,
                        if_true: zero,
                        if_false: one,
                        out: zero,
                    },
                )
            }),
            (
                unary_asserts(&NonBooleanInput(1), one).remove(0).1,
                inputs(1..=2, &|wire| {
                    direct(
                        &NonBooleanInput(wire),
                        &AssertedBinary::<1> { a: one, b: one },
                    )
                }),
                inputs(1..=3, &|wire| {
                    direct(
                        &NonBooleanInput(wire),
                        &AssertEqualIf {
                            a: one,
                            b: zero,
                            condition: zero,
                        },
                    )
                }),
                assert_true_if_forms(&NonBooleanInput(1), one).remove(3).1,
            ),
        ),
        (
            per_vector(&BITS, |_| (
                each(&convert_form_names(), refused(1)),
                refused(1),
                per_gate(|_| each(&constant_form_names(), refused(1))),
            )),
            [1, 2].map(|wire| per_gate(|_| per_vector(&BOOLEAN_PAIRS[2..3], |_| refused(wire)))),
            expected(1..=3),
            expected(1..=3),
            (refused(1), expected(1..=2), expected(1..=3), refused(1)),
        )
    );
}

#[test]
fn a_tampered_intermediate_witness_breaks_its_own_row() {
    let (zero, one) = (Field::from(0u64), Field::from(1u64));
    let unlabelled = |row| Err(("ProverError.ProofInputsBreakRule", Some(row), None));
    let equality = |row| {
        Err((
            "ProverError.ProofInputsBreakRule",
            Some(row),
            Some("an equality test"),
        ))
    };
    assert_eq!(
        (
            every_gate(&Shifted { wire: 4, by: 1 }, &BOOLEAN_PAIRS, honest),
            [
                direct(
                    &Shifted { wire: 4, by: 1 },
                    &Fold::<ALL, 2> {
                        flags: [one, zero],
                        out: zero,
                    }
                ),
                direct(
                    &Shifted { wire: 5, by: 1 },
                    &Fold::<ALL, 2> {
                        flags: [one, zero],
                        out: zero,
                    }
                ),
                direct(
                    &Shifted { wire: 5, by: 1 },
                    &Fold::<ANY, 3> {
                        flags: [one, zero, one],
                        out: one,
                    }
                ),
                direct(
                    &Shifted { wire: 6, by: 1 },
                    &Fold::<ANY, 3> {
                        flags: [one, zero, one],
                        out: one,
                    }
                ),
            ],
            direct(
                &Shifted { wire: 5, by: 1 },
                &Choose::<0> {
                    condition: one,
                    if_true: one,
                    if_false: zero,
                    out: one,
                }
            ),
            direct(
                &Shifted { wire: 3, by: 1 },
                &AssertedBinary::<2> { a: one, b: zero }
            ),
        ),
        (
            per_gate(|_| per_vector(&BOOLEAN_PAIRS, |_| unlabelled(2))),
            [equality(2), equality(2), equality(3), equality(3)],
            unlabelled(3),
            unlabelled(2),
        )
    );
}

type Freedom = (usize, usize, Vec<usize>, Vec<(usize, VariableRole)>);

fn freedom(report: PrivateVariableReport) -> Freedom {
    (
        report.constraints,
        report.private_variables,
        report.free.iter().map(|free| free.variable).collect(),
        report
            .tolerated
            .iter()
            .map(|free| (free.variable, free.role))
            .collect(),
    )
}

struct Freedoms;

impl<C> Visit<C> for Freedoms {
    type Output = Freedom;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Freedom {
        freedom(check_private_variables(fixture))
    }
}

fn bound(constraints: usize, private_variables: usize) -> Freedom {
    (constraints, private_variables, vec![], vec![])
}

#[test]
fn no_private_variable_is_free_and_only_an_equal_sided_inverse_hint_is_tolerated() {
    let fold_freedom = |op: usize, flags: &[bool]| {
        let n = flags.len();
        let constraints = fold_constraints(n);
        let sides_equal = match op {
            ALL => flags.iter().all(|flag| *flag),
            _ => !flags.iter().any(|flag| *flag),
        };
        match n {
            0 | 1 => bound(constraints, n + 1),
            _ if sides_equal => (
                constraints,
                n + 3,
                vec![],
                vec![(n + 2, VariableRole::Multiplier)],
            ),
            _ => bound(constraints, n + 3),
        }
    };
    assert_eq!(
        (
            per_vector(&BITS, |bit| {
                let x = bit.field();
                (
                    convert_forms(&Freedoms, (x, x)),
                    direct(
                        &Freedoms,
                        &Not {
                            a: x,
                            out: Field::from(!bit.bit()),
                        },
                    ),
                    every_constant_form(&Freedoms, x, |gate, form| {
                        Field::from(form.output(gate, bit.bit()))
                    }),
                )
            }),
            every_gate(&Freedoms, &BOOLEAN_PAIRS, honest),
            per_fold(|_| Freedoms),
            per_vector(&TRIPLES, |triple| {
                let (c, t, f) = triple.fields();
                select_forms(&Freedoms, (c, t, f, Field::from(triple.selected())))
            }),
            (
                [
                    direct(
                        &Freedoms,
                        &AssertedUnary::<0> {
                            a: Field::from(1u64)
                        }
                    ),
                    direct(
                        &Freedoms,
                        &AssertedUnary::<1> {
                            a: Field::from(0u64)
                        }
                    ),
                ],
                [
                    holding_binary::<0, _>(&Freedoms),
                    holding_binary::<1, _>(&Freedoms),
                    holding_binary::<2, _>(&Freedoms),
                ],
                holding_equal_if(&Freedoms),
            ),
        ),
        (
            per_vector(&BITS, |_| (
                each(&convert_form_names(), bound(2, 2)),
                bound(2, 2),
                per_gate(|_| each(&constant_form_names(), bound(2, 2))),
            )),
            per_gate(|_| per_vector(&BOOLEAN_PAIRS, |_| bound(4, 4))),
            FOLDS
                .iter()
                .enumerate()
                .map(|(op, fold_op)| (fold_op.name, per_flags(|flags| fold_freedom(op, flags))))
                .collect::<Visited<_>>(),
            per_vector(&TRIPLES, |_| each(&select_form_names(), bound(5, 5))),
            (
                [bound(2, 1), bound(2, 1)],
                [
                    BOOLEAN_PAIRS
                        .iter()
                        .filter(|pair| BINARY_ASSERTS[0].1[pair.row()])
                        .map(|pair| (pair.name, bound(3, 2)))
                        .collect::<Visited<_>>(),
                    BOOLEAN_PAIRS
                        .iter()
                        .filter(|pair| BINARY_ASSERTS[1].1[pair.row()])
                        .map(|pair| (pair.name, bound(3, 2)))
                        .collect::<Visited<_>>(),
                    BOOLEAN_PAIRS
                        .iter()
                        .filter(|pair| BINARY_ASSERTS[2].1[pair.row()])
                        .map(|pair| (pair.name, bound(4, 3)))
                        .collect::<Visited<_>>(),
                ],
                TRIPLES
                    .iter()
                    .filter(|triple| equal_if_holds(triple))
                    .map(|triple| (triple.name, bound(4, 3)))
                    .collect::<Visited<_>>(),
            ),
        )
    );
}

#[test]
fn the_prover_refuses_a_non_boolean_operand_or_a_broken_assertion_before_synthesis() {
    let (zero, one, two) = (Field::from(0u64), Field::from(1u64), Field::from(2u64));
    let refusal = |error: ProverError| error.name();
    assert_eq!(
        (
            check_constraints(&Not { a: two, out: zero }),
            Not { a: two, out: zero }
                .export_assignment()
                .map_err(refusal),
            check_constraints(&AssertedUnary::<0> { a: zero }),
            AssertedBinary::<ASSERT_NOT_EQUAL> { a: one, b: one }
                .export_assignment()
                .map_err(refusal),
        ),
        (
            Err(("CircuitError.NotZeroOrOne", None, None)),
            Err("CircuitError.NotZeroOrOne"),
            Err(("CircuitError.RuleBroken", None, None)),
            Err("CircuitError.RuleBroken"),
        )
    );
}

#[test]
fn a_failing_assertion_breaks_exactly_its_assertion_row_with_the_fixture_rule() {
    let (zero, one) = (Field::from(0u64), Field::from(1u64));
    let (fr_zero, fr_one) = (Fr::zero(), Fr::one());
    let rule_of = |op: usize| BINARY_ASSERTS[op].0.rule;
    assert_eq!(
        (
            [
                check_tampered(&AssertedUnary::<0> { a: one }, 1, zero),
                check_tampered(&AssertedUnary::<1> { a: zero }, 1, one),
            ],
            [
                check_tampered(&AssertedBinary::<0> { a: one, b: one }, 1, zero),
                check_tampered(&AssertedBinary::<1> { a: one, b: one }, 2, zero),
                check_tampered(
                    &AssertEqualIf {
                        a: one,
                        b: zero,
                        condition: zero,
                    },
                    3,
                    one,
                ),
            ],
            [
                unsatisfied_rows(
                    &exported::<AssertedBinary<ASSERT_NOT_EQUAL>>(),
                    &[fr_one, fr_one, fr_one, fr_one]
                ),
                unsatisfied_rows(
                    &exported::<AssertedBinary<ASSERT_NOT_EQUAL>>(),
                    &[fr_one, fr_zero, fr_zero, fr_zero]
                ),
            ],
        ),
        (
            [
                Err(breaks_rule(1, UNARY_ASSERTS[0].0.rule)),
                Err(breaks_rule(1, UNARY_ASSERTS[1].0.rule)),
            ],
            [
                Err(breaks_rule(2, rule_of(0))),
                Err(breaks_rule(2, rule_of(1))),
                Err(breaks_rule(3, ASSERT_EQUAL_IF_RULE)),
            ],
            [vec![3], vec![3]],
        )
    );
}
