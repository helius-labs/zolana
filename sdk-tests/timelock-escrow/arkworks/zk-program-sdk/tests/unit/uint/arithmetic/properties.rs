use ark_bn254::Fr;
use proptest::prelude::*;
use zk_program_sdk::circuit::{constant, value, CircuitVar, Field, Uint};

use super::fixtures::{
    CheckedAdd, CheckedMul, CheckedSub, ADD_RULE, CLAIMED_WIRE, FILE, MUL_RULE, RULE, SUB_RULE,
};
use crate::{
    harness::fixture::{breaks_rule, check_constraints, check_tampered},
    uint::rows::{broken, native},
};

fn uint(x: u64) -> Uint<64> {
    Uint::try_from(constant(x)).expect("a u64 fits in 64 bits")
}

fn value_of<const BITS: u32>(uint: Uint<BITS>) -> Field {
    value(&CircuitVar::from(uint)).expect("a constant result")
}

fn outcome(result: Option<u64>, rule: &'static str) -> Result<(), crate::uint::rows::Refused> {
    result.map(drop).ok_or_else(|| broken(rule, FILE))
}

proptest! {
    #[test]
    fn natively_every_64_bit_checked_operation_holds_exactly_when_u64_arithmetic_does(
        x in any::<u64>(),
        y in any::<u64>(),
    ) {
        let (xf, yf) = (Field::from(x), Field::from(y));
        let claim = |result: Option<u64>, wide: u128| {
            Field::from(result.map_or(Fr::from(wide), Fr::from))
        };
        let sum = claim(x.checked_add(y), u128::from(x) + u128::from(y));
        let product = claim(x.checked_mul(y), u128::from(x) * u128::from(y));
        let difference = Field::from(Fr::from(x) - Fr::from(y));
        prop_assert_eq!(
            (
                native(&CheckedAdd::<64> { x: xf, y: yf, claimed: sum }),
                native(&CheckedMul::<64> { x: xf, y: yf, claimed: product }),
                native(&CheckedSub::<64> { x: xf, y: yf, claimed: difference }),
            ),
            (
                outcome(x.checked_add(y), ADD_RULE),
                outcome(x.checked_mul(y), MUL_RULE),
                outcome(x.checked_sub(y), SUB_RULE),
            )
        );
    }

    #[test]
    fn natively_add_and_mul_at_64_bits_give_the_u128_result(x in any::<u64>(), y in any::<u64>()) {
        prop_assert_eq!(
            (
                value_of(uint(x).add::<65>(&uint(y))),
                value_of(uint(x).mul::<128>(&uint(y))),
            ),
            (
                Field::from(u128::from(x) + u128::from(y)),
                Field::from(u128::from(x) * u128::from(y)),
            )
        );
    }

    #[test]
    fn every_fitting_64_bit_checked_sum_satisfies_the_rows_and_a_wrong_claim_breaks_the_claim_rule(
        x in any::<u64>(),
        y in any::<u64>(),
    ) {
        let (low, high) = (x.min(y), x.max(y));
        let (half_x, half_y) = (x >> 1, y >> 1);
        let add = CheckedAdd::<64> {
            x: Field::from(half_x),
            y: Field::from(half_y),
            claimed: Field::from(half_x + half_y),
        };
        let sub = CheckedSub::<64> {
            x: Field::from(high),
            y: Field::from(low),
            claimed: Field::from(high - low),
        };
        let (small_x, small_y) = (x >> 32, y >> 32);
        let mul = CheckedMul::<64> {
            x: Field::from(small_x),
            y: Field::from(small_y),
            claimed: Field::from(small_x * small_y),
        };
        let wrong = Field::from(u128::from(u64::MAX) + 1);
        prop_assert_eq!(
            (
                check_constraints(&add),
                check_constraints(&mul),
                check_constraints(&sub),
                check_tampered(&add, CLAIMED_WIRE, wrong),
                check_tampered(&mul, CLAIMED_WIRE, wrong),
                check_tampered(&sub, CLAIMED_WIRE, wrong),
            ),
            (
                Ok(196),
                Ok(197),
                Ok(196),
                Err(breaks_rule(195, RULE)),
                Err(breaks_rule(196, RULE)),
                Err(breaks_rule(195, RULE)),
            )
        );
    }
}

proptest! {
    #[test]
    fn random_sums_match_three_independent_u64_operands(values in any::<[u64;3]>()) {
        let total: u128 = values.iter().copied().map(u128::from).sum();
        let fixture = super::fixtures::Sum::<64,66> { values: values.map(Field::from), claimed: total.into() };
        prop_assert_eq!(check_constraints(&fixture), Ok(196));
        prop_assert_eq!(native(&fixture), Ok(()));
        prop_assert!(check_tampered(&fixture, 4, (total+1).into()).is_err());
    }
}
