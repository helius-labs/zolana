use ark_bn254::Fr;
use zolana_program::{
    circuit::{constant, value, zero, CircuitVar, Field},
    conversion::{self, Allocator, ProofInput},
    CircuitError,
};

use super::{
    fixtures::{every_form, every_form_name, RULE_BROKEN},
    vectors::{INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    field::{be_bytes, canonical, field, integer, modulus},
    fixture::{expected, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit},
};

struct NativeDifference;

impl Visit<CircuitVar> for NativeDifference {
    type Output = (String, Result<Field, Refusal>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let difference = F::computed(&native_circuit(fixture).expect("native instantiation"));
        (format!("{difference:?}"), outcome(value(&difference)))
    }
}

#[test]
fn every_valid_vector_holds_natively_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Native, vector.fields())),
        expected(&VALID, &every_form_name(), |_, _| Ok(()))
    );
}

#[test]
fn every_invalid_vector_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| every_form(&Native, vector.fields())),
        expected(&INVALID, &every_form_name(), |_, _| Err(RULE_BROKEN))
    );
}

#[test]
fn the_native_difference_is_field_subtraction_modulo_p_in_every_form() {
    let field_differences: Vec<_> = VALID
        .iter()
        .map(|vector| {
            let (left, right, _) = vector.fields();
            left - right
        })
        .collect();
    assert_eq!(
        (
            field_differences,
            per_vector(&VALID, |vector| every_form(
                &NativeDifference,
                vector.fields()
            ))
        ),
        (
            VALID
                .iter()
                .map(|vector| field(vector.difference))
                .collect(),
            expected(&VALID, &every_form_name(), |vector, _| {
                let difference = field(vector.difference);
                (
                    format!("CircuitVar::constant({})", Fr::from(difference)),
                    Ok(difference),
                )
            })
        )
    );
}

#[test]
fn constant_subtraction_adds_the_negation_undoes_addition_and_anticommutes() {
    let operands: Vec<CircuitVar> = VALID
        .iter()
        .flat_map(|vector| [vector.left, vector.right])
        .map(|decimal| constant(field(decimal)))
        .collect();
    let values = |vars: Vec<CircuitVar>| -> Vec<Field> {
        vars.iter()
            .map(|var| value(var).expect("constant"))
            .collect()
    };
    let pairs = || {
        operands
            .iter()
            .flat_map(|a| operands.iter().map(move |b| (a, b)))
    };
    assert_eq!(
        (
            values(pairs().map(|(a, b)| a - b).collect()),
            values(pairs().map(|(a, b)| (a - b) + b).collect()),
            values(pairs().map(|(a, b)| b - a).collect()),
            values(operands.iter().map(|a| a - a).collect()),
            values(operands.iter().map(|a| a - zero()).collect()),
        ),
        (
            values(pairs().map(|(a, b)| a + -b).collect()),
            values(pairs().map(|(a, _)| a.clone()).collect()),
            values(pairs().map(|(a, b)| -(a - b)).collect()),
            vec![Field::from(0u64); operands.len()],
            values(operands.clone()),
        )
    );
}

#[test]
fn a_difference_of_p_is_refused_before_it_reaches_the_circuit() {
    let (left, right) = (field(NON_CANONICAL.left), field(NON_CANONICAL.right));
    let bytes = be_bytes(NON_CANONICAL.difference);
    let refusal = |error: CircuitError| (error.name(), error.to_string());
    assert_eq!(
        (
            integer(NON_CANONICAL.difference) == modulus(),
            canonical(NON_CANONICAL.difference),
            left - right,
            conversion::field(&bytes, "difference").map_err(refusal),
            bytes
                .instantiate(&Allocator::native())
                .map(|_| ())
                .map_err(refusal),
        ),
        (
            true,
            None,
            Field::from(0u64),
            Err((
                "CircuitError.BytesTooLarge",
                "difference is too large for a circuit value".to_string()
            )),
            Err((
                "CircuitError.BytesTooLarge",
                "32-byte input is too large for a circuit value".to_string()
            )),
        )
    );
}
