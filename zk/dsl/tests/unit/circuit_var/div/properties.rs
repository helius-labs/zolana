use ark_bn254::Fr;
use ark_ff::One;
use proptest::prelude::*;
use zolana_program::circuit::Field;

use super::fixtures::{honest, Div, DIVISION_BY_ZERO, QUOTIENT_WIRE, RULE, RULE_BROKEN};
use crate::harness::{
    field::random,
    fixture::{breaks_rule, check_constraints, check_tampered, exported, native},
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn nonzero_field() -> impl Strategy<Value = Field> {
    arbitrary_field().prop_filter("a nonzero divisor", |x| *x != Field::from(0u64))
}

proptest! {
    #[test]
    fn natively_div_holds_exactly_when_the_quotient_times_the_divisor_is_the_dividend(
        dividend in arbitrary_field(),
        divisor in nonzero_field(),
        claimed in arbitrary_field(),
        honest_claim in any::<bool>(),
    ) {
        let quotient = if honest_claim { honest(dividend, divisor).quotient } else { claimed };
        let expected = if quotient * divisor == dividend { Ok(()) } else { Err(RULE_BROKEN) };
        prop_assert_eq!(native(&Div { dividend, divisor, quotient }), expected);
    }

    #[test]
    fn every_honest_quotient_checks_three_constraints_and_a_wrong_one_names_the_rule(
        dividend in arbitrary_field(),
        divisor in nonzero_field(),
        offset in nonzero_field(),
    ) {
        let fixture = honest(dividend, divisor);
        prop_assert_eq!(
            (
                check_constraints(&fixture),
                check_tampered(&fixture, QUOTIENT_WIRE, fixture.quotient + offset),
            ),
            (Ok(3), Err(breaks_rule(2, RULE)))
        );
    }

    #[test]
    fn a_zero_divisor_is_refused_natively_and_by_every_witness(
        dividend in arbitrary_field(),
        quotient in arbitrary_field(),
        inverse in arbitrary_field(),
        product in arbitrary_field(),
    ) {
        let zero = Field::from(0u64);
        prop_assert_eq!(
            (
                native(&Div { dividend, divisor: zero, quotient }),
                exported::<Div>().first_unsatisfied(&[
                    Fr::one(),
                    dividend.into(),
                    zero.into(),
                    quotient.into(),
                    inverse.into(),
                    product.into(),
                ]),
            ),
            (Err(DIVISION_BY_ZERO), Some(0))
        );
    }
}
