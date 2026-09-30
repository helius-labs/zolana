use ark_bn254::Fr;
use ark_ff::Field as _;
use zolana_program::circuit::{constant, value, zero, CircuitVar, Field};

use super::{
    fixtures::{Pow, Pow5, RULE_BROKEN},
    vectors::{BASES, EXPONENTS, INVALID, VALID},
};
use crate::harness::{
    field::field,
    fixture::{native, outcome, per_vector, Refusal},
};

fn power(var: &CircuitVar, exponent: u64) -> Field {
    value(&var.pow(exponent).expect("a constant power")).expect("a constant")
}

#[test]
fn every_valid_vector_holds_natively() {
    assert_eq!(
        per_vector(&VALID, |vector| {
            let (x, power) = vector.fields();
            native(&Pow5 { x, power })
        }),
        per_vector(&VALID, |_| Ok(()))
    );
}

#[test]
fn every_invalid_vector_breaks_exactly_the_fixture_rule_natively() {
    assert_eq!(
        per_vector(&INVALID, |vector| {
            let (x, power) = vector.fields();
            native(&Pow5 { x, power })
        }),
        per_vector(&INVALID, |_| Err(RULE_BROKEN))
    );
}

#[test]
fn the_native_power_is_field_exponentiation_for_every_base_and_exponent() {
    let pairs = || {
        BASES
            .iter()
            .flat_map(|base| EXPONENTS.iter().map(move |exponent| (*base, *exponent)))
    };
    assert_eq!(
        pairs()
            .map(|(base, exponent)| {
                let raised = constant(field(base))
                    .pow(exponent)
                    .expect("a constant power");
                (
                    base,
                    exponent,
                    format!("{raised:?}"),
                    outcome(value(&raised)),
                )
            })
            .collect::<Vec<_>>(),
        pairs()
            .map(|(base, exponent)| {
                let expected = Fr::from(field(base)).pow([exponent]);
                (
                    base,
                    exponent,
                    format!("CircuitVar::constant({expected})"),
                    Ok::<_, Refusal>(Field::from(expected)),
                )
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn zero_to_the_zero_is_one_and_every_base_to_the_zero_holds_natively() {
    assert_eq!(
        (
            power(&zero(), 0),
            BASES
                .map(|base| native(&Pow::<0> {
                    x: field(base),
                    power: field("1"),
                }))
                .to_vec(),
        ),
        (Field::from(1u64), vec![Ok(()); BASES.len()])
    );
}

#[test]
fn constant_powers_add_their_exponents_and_raise_to_one_exactly_the_base() {
    const SMALL: [u64; 5] = [0, 1, 2, 3, 5];
    let bases: Vec<CircuitVar> = BASES.iter().map(|base| constant(field(base))).collect();
    let triples = || {
        bases.iter().flat_map(|base| {
            SMALL
                .iter()
                .flat_map(move |a| SMALL.iter().map(move |b| (base, *a, *b)))
        })
    };
    assert_eq!(
        (
            triples()
                .map(|(base, a, b)| power(base, a) * power(base, b))
                .collect::<Vec<_>>(),
            bases.iter().map(|base| power(base, 1)).collect::<Vec<_>>(),
        ),
        (
            triples()
                .map(|(base, a, b)| power(base, a + b))
                .collect::<Vec<_>>(),
            bases
                .iter()
                .map(|base| value(base).expect("constant"))
                .collect::<Vec<_>>(),
        )
    );
}
