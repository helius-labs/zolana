use ark_bn254::Fr;
use zolana_program::circuit::{constant, value, CircuitVar, Field};

use super::{
    fixtures::{ByFour, ByZero, Div, FourOver, DIVISION_BY_ZERO, RULE_BROKEN},
    vectors::{INVALID, VALID, ZERO},
};
use crate::harness::{
    field::{field, HALF_ABOVE},
    fixture::{native, outcome, per_vector},
};

fn quotient(dividend: &CircuitVar, divisor: &CircuitVar) -> Field {
    value(&dividend.div(divisor).expect("a nonzero divisor")).expect("a constant quotient")
}

#[test]
fn every_valid_vector_holds_natively() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            native(&Div {
                dividend,
                divisor,
                quotient,
            })
        }),
        per_vector(&VALID, |_| Ok(()))
    );
}

#[test]
fn every_wrong_quotient_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            native(&Div {
                dividend,
                divisor,
                quotient,
            })
        }),
        per_vector(&INVALID, |_| Err(RULE_BROKEN))
    );
}

#[test]
fn a_zero_divisor_fails_natively_with_division_by_zero_whatever_the_dividend_and_claim() {
    assert_eq!(
        per_vector(&ZERO, |vector| {
            let (dividend, divisor, quotient) = vector.fields();
            native(&Div {
                dividend,
                divisor,
                quotient,
            })
        }),
        per_vector(&ZERO, |_| Err(DIVISION_BY_ZERO))
    );
}

#[test]
fn the_native_quotient_is_the_dividend_times_the_divisors_inverse_and_stays_a_constant() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (dividend, divisor, _) = vector.fields();
            let divided = constant(dividend)
                .div(&constant(divisor))
                .expect("a nonzero divisor");
            let quotient = value(&divided).expect("a constant quotient");
            (format!("{divided:?}"), quotient, quotient * divisor)
        }),
        per_vector(&VALID, |vector| {
            let (dividend, _, quotient) = vector.fields();
            (
                format!("CircuitVar::constant({})", Fr::from(quotient)),
                quotient,
                dividend,
            )
        })
    );
}

#[test]
fn a_constant_divisor_of_zero_fails_at_the_line_that_divides() {
    let quarter = field(HALF_ABOVE) * field(HALF_ABOVE);
    assert_eq!(
        (
            outcome(constant(1u64).div(&constant(0u64))).map(|_| ()),
            native(&ByZero {
                dividend: field("1"),
                quotient: field("0"),
            }),
            native(&ByFour {
                dividend: field("1"),
                quotient: quarter,
            }),
            native(&FourOver {
                divisor: field("2"),
                quotient: field("2"),
            }),
        ),
        (
            Err(("CircuitError.DivisionByZero", None, file!())),
            Err(DIVISION_BY_ZERO),
            Ok(()),
            Ok(()),
        )
    );
}

#[test]
fn constant_division_undoes_multiplication_and_divides_by_one_and_itself_as_expected() {
    let operands: Vec<CircuitVar> = VALID
        .iter()
        .map(|vector| constant(field(vector.divisor)))
        .collect();
    let pairs = || {
        operands
            .iter()
            .flat_map(|a| operands.iter().map(move |b| (a, b)))
    };
    let values = |vars: Vec<CircuitVar>| -> Vec<Field> {
        vars.iter()
            .map(|var| value(var).expect("constant"))
            .collect()
    };
    assert_eq!(
        (
            pairs()
                .map(|(a, b)| quotient(&(a * b), b))
                .collect::<Vec<_>>(),
            operands.iter().map(|a| quotient(a, a)).collect::<Vec<_>>(),
            operands
                .iter()
                .map(|a| quotient(a, &constant(1u64)))
                .collect::<Vec<_>>(),
        ),
        (
            values(pairs().map(|(a, _)| a.clone()).collect()),
            vec![Field::from(1u64); operands.len()],
            values(operands.clone()),
        )
    );
}
