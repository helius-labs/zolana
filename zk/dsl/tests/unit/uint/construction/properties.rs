use ark_bn254::Fr;
use num_bigint::BigUint;
use proptest::prelude::*;
use zolana_program::circuit::Field;

use super::fixtures::{Borrowed, FILE, WIDTH_RULE, X_WIRE};
use crate::{
    harness::{
        field::random,
        fixture::{assignment, breaks_rule, check_constraints, check_tampered, first_unsatisfied},
    },
    uint::rows::{integer, native, too_large},
};

proptest! {
    #[test]
    fn natively_a_64_bit_try_from_holds_exactly_below_2_to_the_64(x in any::<u128>()) {
        let expected = if x >> 64 == 0 { Ok(()) } else { Err(too_large(64, FILE)) };
        prop_assert_eq!(native(&Borrowed::<64> { x: Field::from(x) }), expected);
    }

    #[test]
    fn natively_a_252_bit_try_from_holds_exactly_below_2_to_the_252(bytes in any::<[u8; 32]>()) {
        let x = random(bytes);
        let fits = integer(Fr::from(x)) < BigUint::from(1u8) << 252u32;
        let expected = if fits { Ok(()) } else { Err(too_large(252, FILE)) };
        prop_assert_eq!(native(&Borrowed::<252> { x }), expected);
    }

    #[test]
    fn every_u64_satisfies_the_64_bit_rows_and_a_tampered_value_breaks_the_width_rule(
        x in any::<u64>(),
        offset in 1u64..,
    ) {
        let fixture = Borrowed::<64> { x: Field::from(x) };
        let tampered = Fr::from(x) + Fr::from(offset);
        prop_assert_eq!(
            (
                check_constraints(&fixture),
                first_unsatisfied::<Borrowed<64>>(&assignment(&fixture)),
                check_tampered(&fixture, X_WIRE, Field::from(tampered)),
            ),
            (Ok(65), None, Err(breaks_rule(64, WIDTH_RULE)))
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn random_constants_and_bool_conversions_keep_integer_values_and_bind_claims(x in any::<u64>(), offset in 1u64..) {
        use zolana_program::circuit::{value, CircuitVar, Uint};
        use super::fixtures::{Constants, FromBool, RULE};
        use crate::harness::fixture::{native as native_result, rule_broken};
        let as_field = |x: Uint<64>| value(&CircuitVar::from(x)).expect("constant integer");
        prop_assert_eq!(as_field(Uint::<64>::constant(x).expect("u64 fits")), Field::from(x));
        prop_assert_eq!(as_field(Uint::<64>::zero()), Field::from(0u64));
        let byte = x & 255;
        prop_assert_eq!(value(&CircuitVar::from(Uint::<8>::constant(byte).expect("byte fits"))).expect("constant byte"), Field::from(byte));
        let error = Uint::<8>::constant(byte + 256).expect_err("byte overflow");
        prop_assert_eq!((error.name(), error.to_string()), ("CircuitError.ValueTooLarge", "a value does not fit in 8 bits".to_owned()));
        let constant_fixture = Constants { x:15u64.into() };
        let wrong_constant = Field::from(Fr::from(15u64) + Fr::from(offset));
        prop_assert_eq!(check_constraints(&constant_fixture), Ok(2));
        prop_assert_eq!(native_result(&Constants { x:wrong_constant }), Err(rule_broken(RULE,FILE)));
        prop_assert_eq!(check_tampered(&constant_fixture,1,wrong_constant), Err(breaks_rule(0,RULE)));
        for bit in [false,true] {
            let fixture = FromBool::<64> { bit, claimed:u64::from(bit).into() };
            let wrong_claim = Field::from(Fr::from(u64::from(bit)) + Fr::from(offset));
            prop_assert_eq!(native_result(&fixture), Ok(()));
            prop_assert_eq!(check_constraints(&fixture), Ok(2));
            prop_assert_eq!(first_unsatisfied::<FromBool<64>>(&assignment(&fixture)), None);
            prop_assert_eq!(native_result(&FromBool::<64> { bit, claimed:wrong_claim }), Err(rule_broken(RULE,FILE)));
            prop_assert_eq!(check_tampered(&fixture,2,wrong_claim), Err(breaks_rule(1,RULE)));
        }
    }
}
