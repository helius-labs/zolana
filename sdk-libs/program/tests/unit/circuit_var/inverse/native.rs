use ark_bn254::Fr;
use zolana_program::circuit::{constant, value, zero, CircuitVar, Field};

use super::{
    fixtures::{Inverse, InverseOfFour, InverseOfZero, DIVISION_BY_ZERO, RULE_BROKEN},
    vectors::{INVALID, VALID, ZERO},
};
use crate::harness::{
    field::{field, HALF_ABOVE},
    fixture::{native, outcome, per_vector, Refusal},
};

fn inverse(var: &CircuitVar) -> Field {
    value(&var.inverse().expect("a nonzero constant")).expect("a constant inverse")
}

#[test]
fn every_valid_vector_holds_natively() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, inverse) = vector.fields();
            native(&Inverse { x, inverse })
        }),
        per_vector(&VALID, |_| Ok(()))
    );
}

#[test]
fn every_wrong_inverse_of_a_nonzero_x_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (x, inverse) = vector.fields();
            native(&Inverse { x, inverse })
        }),
        per_vector(&INVALID, |_| Err(RULE_BROKEN))
    );
}

#[test]
fn a_zero_x_fails_natively_with_division_by_zero_whatever_the_claim() {
    assert_eq!(
        per_vector(&ZERO, |vector| {
            let (x, inverse) = vector.fields();
            native(&Inverse { x, inverse })
        }),
        per_vector(&ZERO, |_| Err(DIVISION_BY_ZERO))
    );
}

#[test]
fn the_native_inverse_of_a_constant_is_its_field_inverse_and_stays_a_constant() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, _) = vector.fields();
            let inverted = constant(x).inverse().expect("a nonzero constant");
            (
                format!("{inverted:?}"),
                outcome(value(&inverted)),
                x * inverse(&constant(x)),
            )
        }),
        per_vector(&VALID, |vector| {
            let expected = field(vector.inverse);
            (
                format!("CircuitVar::constant({})", Fr::from(expected)),
                Ok(expected),
                Field::from(1u64),
            )
        })
    );
}

#[test]
fn the_constant_zero_has_no_inverse_at_the_line_that_asks() {
    let refused: Result<CircuitVar, Refusal> = outcome(zero().inverse());
    assert_eq!(
        (
            refused.map(|_| ()),
            native(&InverseOfZero {
                inverse: Field::from(0u64)
            }),
            native(&InverseOfFour {
                inverse: field(HALF_ABOVE) * field(HALF_ABOVE),
            }),
        ),
        (
            Err(("CircuitError.DivisionByZero", None, file!())),
            Err(DIVISION_BY_ZERO),
            Ok(()),
        )
    );
}

#[test]
fn constant_inversion_is_an_involution_that_distributes_over_products() {
    let operands: Vec<CircuitVar> = VALID
        .iter()
        .map(|vector| constant(field(vector.x)))
        .collect();
    let pairs = || {
        operands
            .iter()
            .flat_map(|a| operands.iter().map(move |b| (a, b)))
    };
    assert_eq!(
        (
            operands
                .iter()
                .map(|a| inverse(&constant(inverse(a))))
                .collect::<Vec<_>>(),
            pairs().map(|(a, b)| inverse(&(a * b))).collect::<Vec<_>>(),
        ),
        (
            operands
                .iter()
                .map(|a| value(a).expect("constant"))
                .collect::<Vec<_>>(),
            pairs()
                .map(|(a, b)| inverse(a) * inverse(b))
                .collect::<Vec<_>>(),
        )
    );
}
