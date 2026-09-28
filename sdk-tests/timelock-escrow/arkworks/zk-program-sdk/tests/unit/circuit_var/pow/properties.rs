use ark_bn254::Fr;
use ark_ff::Field as _;
use proptest::prelude::*;
use zk_program_sdk::circuit::{constant, value, Field};

use super::fixtures::{Pow5, POWER_WIRE, RULE, RULE_BROKEN};
use crate::harness::{
    field::random,
    fixture::{breaks_rule, check_constraints, check_tampered, native},
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn fifth(x: Field) -> Field {
    Fr::from(x).pow([5u64]).into()
}

proptest! {
    #[test]
    fn natively_x_to_the_5_holds_exactly_when_the_claim_is_the_fifth_power(
        x in arbitrary_field(),
        claimed in arbitrary_field(),
        honest in any::<bool>(),
    ) {
        let power = if honest { fifth(x) } else { claimed };
        let expected = if power == fifth(x) { Ok(()) } else { Err(RULE_BROKEN) };
        prop_assert_eq!(native(&Pow5 { x, power }), expected);
    }

    #[test]
    fn every_honest_power_checks_four_constraints_and_a_wrong_one_names_the_rule(
        x in arbitrary_field(),
        offset in arbitrary_field().prop_filter("a wrong power", |offset| *offset != Field::from(0u64)),
    ) {
        let fixture = Pow5 { x, power: fifth(x) };
        prop_assert_eq!(
            (
                check_constraints(&fixture),
                check_tampered(&fixture, POWER_WIRE, fixture.power + offset),
            ),
            (Ok(4), Err(breaks_rule(3, RULE)))
        );
    }

    #[test]
    fn a_constant_power_is_field_exponentiation_for_every_exponent(
        x in arbitrary_field(),
        exponent in any::<u64>(),
    ) {
        prop_assert_eq!(
            value(&constant(x).pow(exponent).expect("a constant power")).ok(),
            Some(Field::from(Fr::from(x).pow([exponent])))
        );
    }
}
