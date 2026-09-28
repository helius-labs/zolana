use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use proptest::prelude::*;
use zk_program_sdk::circuit::{constant, from_bits_le, value, Bits, Field};

use super::fixtures::{low_bits, CheckBits, FromBits, ToBits, VALUE_TOO_LARGE};
use crate::harness::{
    field::random,
    fixture::{check_constraints, native},
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn bit_length(x: Field) -> usize {
    Fr::from(x).into_bigint().num_bits() as usize
}

proptest! {
    #[test]
    fn check_bits_holds_natively_exactly_when_the_value_fits_the_width(
        x in arbitrary_field(),
        small in any::<u64>(),
    ) {
        let small = Field::from(small);
        let expected = |x: Field, width: usize| {
            if bit_length(x) <= width { Ok(()) } else { Err(VALUE_TOO_LARGE) }
        };
        prop_assert_eq!(
            (
                native(&CheckBits::<253> { x }),
                native(&CheckBits::<64> { x: small }),
                native(&CheckBits::<63> { x: small }),
                check_constraints(&CheckBits::<64> { x: small }),
            ),
            (expected(x, 253), Ok(()), expected(small, 63), Ok(65))
        );
    }

    #[test]
    fn to_bits_le_and_from_bits_le_round_trip_every_u64(integer in any::<u64>()) {
        let x = Field::from(integer);
        let bits = constant(x).to_bits_le::<64>().expect("a u64 fits 64 bits");
        prop_assert_eq!(
            (
                value(&from_bits_le(&bits)).ok(),
                native(&ToBits::<64> { x, bits: low_bits(integer) }),
                native(&FromBits::<64> { bits: low_bits(integer), value: x }),
            ),
            (Some(x), Ok(()), Ok(()))
        );
    }
}
