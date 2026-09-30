use ark_bn254::Fr;
use ark_ff::{One, Zero};
use proptest::prelude::*;
use zolana_program::circuit::{CircuitVar, Field};

use super::{
    fixtures::{
        binary_assert_names, binary_asserts, broken, fold, select_form_names, select_forms,
        unary_assert_names, unary_asserts, AssertEqualIf, Gate, Variables, ALL, ANY,
        ASSERT_EQUAL_IF_RULE, BINARY_ASSERTS, FOLDS, GATES, NOT_BOOLEAN, NOT_ZERO_OR_ONE,
        SELECT_RULE, UNARY_ASSERTS,
    },
    r1cs::unsatisfied_rows,
};
use crate::harness::{
    field::random,
    fixture::{
        breaks_rule, check_tampered, each, exported, native, Fixture, Native, ProverRefusal,
        Refusal, Visit, Visited,
    },
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

/// A field element that is 0 or 1 half of the time.
fn operand() -> impl Strategy<Value = Field> {
    prop_oneof![
        Just(Field::from(0u64)),
        Just(Field::from(1u64)),
        arbitrary_field()
    ]
}

fn bit_of(value: Field) -> Option<bool> {
    match Fr::from(value) {
        value if value.is_zero() => Some(false),
        value if value.is_one() => Some(true),
        _ => None,
    }
}

fn every_gate_at<V: Visit<Result<CircuitVar, Refusal>>>(
    visitor: &V,
    (a, b): (Field, Field),
    claimed: impl Fn(&Gate) -> Field,
) -> Visited<V::Output> {
    fn one<const GATE: usize, V: Visit<Result<CircuitVar, Refusal>>>(
        visitor: &V,
        (a, b): (Field, Field),
        claimed: &impl Fn(&Gate) -> Field,
    ) -> (&'static str, V::Output) {
        let gate = &GATES[GATE];
        let out = claimed(gate);
        (gate.name, visitor.visit(&Variables::<GATE> { a, b, out }))
    }
    vec![
        one::<0, _>(visitor, (a, b), &claimed),
        one::<1, _>(visitor, (a, b), &claimed),
        one::<2, _>(visitor, (a, b), &claimed),
        one::<3, _>(visitor, (a, b), &claimed),
        one::<4, _>(visitor, (a, b), &claimed),
        one::<5, _>(visitor, (a, b), &claimed),
    ]
}

fn gate_rows<const GATE: usize>(a: Fr, b: Fr) -> (&'static str, Vec<usize>) {
    let gate = &GATES[GATE];
    let witness = [Fr::one(), a, b, gate.polynomial(a, b), a * b];
    (
        gate.name,
        unsatisfied_rows(&exported::<Variables<GATE>>(), &witness),
    )
}

/// The native outcome of an assertion over boolean operands whose table says
/// `holds`, or of one with a non-boolean operand (`None`).
fn judged(rule: &'static str, holds: Option<bool>) -> Result<(), Refusal> {
    match holds {
        Some(true) => Ok(()),
        Some(false) => Err(broken(rule)),
        None => Err(NOT_ZERO_OR_ONE),
    }
}

struct Tampered {
    wire: usize,
    value: Field,
}

impl Visit<Result<CircuitVar, Refusal>> for Tampered {
    type Output = Result<(), ProverRefusal>;

    fn visit<F: Fixture<Result<CircuitVar, Refusal>>>(&self, fixture: &F) -> Self::Output {
        check_tampered(fixture, self.wire, self.value)
    }
}

proptest! {
    #[test]
    fn natively_every_gate_refuses_exactly_the_non_boolean_operands_and_holds_exactly_on_its_truth_table(
        a in operand(),
        b in operand(),
        claimed in operand(),
    ) {
        let expected = |gate: &Gate| match (bit_of(a), bit_of(b)) {
            (Some(x), Some(y)) if Field::from(gate.output(x, y)) == claimed => Ok(()),
            (Some(_), Some(_)) => Err(broken(gate.rule)),
            _ => Err(NOT_ZERO_OR_ONE),
        };
        prop_assert_eq!(
            every_gate_at(&Native, (a, b), |_| claimed),
            GATES.iter().map(|gate| (gate.name, expected(gate))).collect::<Visited<_>>()
        );
    }

    #[test]
    fn a_non_boolean_operand_breaks_exactly_its_booleanity_rows_in_every_gate(
        a in arbitrary_field(),
        b in operand(),
    ) {
        let (a, b) = (Fr::from(a), Fr::from(b));
        let rows = if bit_of(b.into()).is_some() { vec![0] } else { vec![0, 1] };
        let rows = if bit_of(a.into()).is_some() {
            rows.into_iter().filter(|row| *row == 1).collect()
        } else {
            rows
        };
        prop_assert_eq!(
            [
                gate_rows::<0>(a, b),
                gate_rows::<1>(a, b),
                gate_rows::<2>(a, b),
                gate_rows::<3>(a, b),
                gate_rows::<4>(a, b),
                gate_rows::<5>(a, b),
            ],
            GATES.map(|gate| (gate.name, rows.clone()))
        );
    }

    #[test]
    fn every_wrong_claim_of_a_gate_breaks_its_claim_row_in_the_proving_rows(
        a in any::<bool>(),
        b in any::<bool>(),
        claimed in arbitrary_field(),
    ) {
        let expected = |gate: &Gate| {
            if Field::from(gate.output(a, b)) == claimed {
                Ok(())
            } else {
                Err(breaks_rule(3, gate.rule))
            }
        };
        let tampered = Tampered { wire: 3, value: claimed };
        prop_assert_eq!(
            every_gate_at(&tampered, (Field::from(a), Field::from(b)), |gate| {
                Field::from(gate.output(a, b))
            }),
            GATES.iter().map(|gate| (gate.name, expected(gate))).collect::<Visited<_>>()
        );
    }

    #[test]
    fn natively_a_fold_holds_exactly_on_iterator_all_and_any_and_refuses_a_non_boolean_flag(
        flags in prop::collection::vec(operand(), 0..=3),
        claimed in operand(),
    ) {
        let bits: Option<Vec<bool>> = flags.iter().map(|flag| bit_of(*flag)).collect();
        let expected = |op: usize| match &bits {
            Some(bits) if Field::from((FOLDS[op].truth)(bits)) == claimed => Ok(()),
            Some(_) => Err(broken(FOLDS[op].rule)),
            None => Err(NOT_ZERO_OR_ONE),
        };
        prop_assert_eq!(
            (
                fold::<ALL, _>(&Native, &flags, claimed),
                fold::<ANY, _>(&Native, &flags, claimed),
            ),
            (expected(ALL), expected(ANY))
        );
    }

    #[test]
    fn natively_select_refuses_a_non_boolean_operand_and_holds_exactly_on_the_named_branch(
        condition in operand(),
        if_true in operand(),
        if_false in operand(),
        claimed in operand(),
    ) {
        let expected = match (bit_of(condition), bit_of(if_true), bit_of(if_false)) {
            (Some(c), Some(t), Some(f)) if Field::from(if c { t } else { f }) == claimed => Ok(()),
            (Some(_), Some(_), Some(_)) => Err(broken(SELECT_RULE)),
            _ => Err(NOT_ZERO_OR_ONE),
        };
        prop_assert_eq!(
            select_forms(&Native, (condition, if_true, if_false, claimed)),
            each(&select_form_names(), expected)
        );
    }

    #[test]
    fn natively_every_assertion_refuses_a_non_boolean_operand_and_holds_exactly_as_its_table_says(
        a in operand(),
        b in operand(),
        condition in operand(),
    ) {
        let (x, y, c) = (bit_of(a), bit_of(b), bit_of(condition));
        let pair = x.zip(y).map(|(x, y)| 2 * usize::from(x) + usize::from(y));
        prop_assert_eq!(
            (
                unary_asserts(&Native, a),
                binary_asserts(&Native, (a, b)),
                native(&AssertEqualIf { a, b, condition }),
            ),
            (
                unary_assert_names()
                    .into_iter()
                    .zip(&UNARY_ASSERTS)
                    .map(|(name, (op, holds))| {
                        (name, judged(op.rule, x.map(|x| holds[usize::from(x)])))
                    })
                    .collect::<Visited<_>>(),
                binary_assert_names()
                    .into_iter()
                    .zip(&BINARY_ASSERTS)
                    .map(|(name, (op, holds))| (name, judged(op.rule, pair.map(|row| holds[row]))))
                    .collect::<Visited<_>>(),
                judged(
                    ASSERT_EQUAL_IF_RULE,
                    x.zip(y).zip(c).map(|((x, y), c)| !c || x == y)
                ),
            )
        );
    }

    #[test]
    fn a_non_boolean_input_of_every_gate_breaks_its_booleanity_row_in_the_proving_rows(
        a in any::<bool>(),
        b in any::<bool>(),
        value in arbitrary_field().prop_filter("a non-boolean value", |value| bit_of(*value).is_none()),
        wire in 1usize..=2,
    ) {
        prop_assert_eq!(
            every_gate_at(&Tampered { wire, value }, (Field::from(a), Field::from(b)), |gate| {
                Field::from(gate.output(a, b))
            }),
            GATES.map(|gate| (gate.name, Err(breaks_rule(wire - 1, NOT_BOOLEAN)))).to_vec()
        );
    }
}
