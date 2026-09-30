use ark_bn254::Fr;
use zolana_program::{
    circuit::{constant, value, zero, CircuitVar, Field},
    conversion::{self, Allocator, ProofInput},
    CircuitError,
};

use super::{
    fixtures::{every_form, form_names, RULE_BROKEN},
    vectors::{INVALID, NON_CANONICAL, VALID},
};
use crate::harness::{
    field::{be_bytes, canonical, field, integer, modulus},
    fixture::{expected, native_circuit, outcome, per_vector, Fixture, Native, Refusal, Visit},
};

struct NativeNegation;

impl Visit<CircuitVar> for NativeNegation {
    type Output = (String, Result<Field, Refusal>);

    fn visit<F: Fixture<CircuitVar>>(&self, fixture: &F) -> Self::Output {
        let negation = F::computed(&native_circuit(fixture).expect("native instantiation"));
        (format!("{negation:?}"), outcome(value(&negation)))
    }
}

#[test]
fn every_valid_vector_holds_natively_in_every_form() {
    assert_eq!(
        per_vector(&VALID, |vector| every_form(&Native, vector.fields())),
        expected(&VALID, &form_names(), |_, _| Ok(()))
    );
}

#[test]
fn every_invalid_vector_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| every_form(&Native, vector.fields())),
        expected(&INVALID, &form_names(), |_, _| Err(RULE_BROKEN))
    );
}

#[test]
fn the_native_negation_is_the_additive_inverse_modulo_p_in_every_form() {
    let field_negations: Vec<_> = VALID.iter().map(|vector| -vector.fields().0).collect();
    assert_eq!(
        (
            field_negations,
            per_vector(&VALID, |vector| every_form(
                &NativeNegation,
                vector.fields()
            ))
        ),
        (
            VALID.iter().map(|vector| field(vector.negation)).collect(),
            expected(&VALID, &form_names(), |vector, _| {
                let negation = field(vector.negation);
                (
                    format!("CircuitVar::constant({})", Fr::from(negation)),
                    Ok(negation),
                )
            })
        )
    );
}

#[test]
fn constant_negation_is_an_involution_that_cancels_and_subtracts_from_zero() {
    let operands: Vec<CircuitVar> = VALID
        .iter()
        .map(|vector| constant(field(vector.value)))
        .collect();
    let values = |vars: Vec<CircuitVar>| -> Vec<Field> {
        vars.iter()
            .map(|var| value(var).expect("constant"))
            .collect()
    };
    assert_eq!(
        (
            values(operands.iter().map(|a| -(-a)).collect()),
            values(operands.iter().map(|a| a + -a).collect()),
            values(operands.iter().map(|a| -a).collect()),
        ),
        (
            values(operands.clone()),
            vec![Field::from(0u64); operands.len()],
            values(operands.iter().map(|a| zero() - a).collect()),
        )
    );
}

#[test]
fn a_negation_of_p_is_refused_before_it_reaches_the_circuit() {
    let bytes = be_bytes(NON_CANONICAL.negation);
    let refusal = |error: CircuitError| (error.name(), error.to_string());
    assert_eq!(
        (
            integer(NON_CANONICAL.negation) == modulus(),
            canonical(NON_CANONICAL.negation),
            -field(NON_CANONICAL.value),
            conversion::field(&bytes, "negation").map_err(refusal),
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
                "negation is too large for a circuit value".to_string()
            )),
            Err((
                "CircuitError.BytesTooLarge",
                "32-byte input is too large for a circuit value".to_string()
            )),
        )
    );
}
