use zolana_program::{
    circuit::{constant, from_bits_le, value, Bits, Bool, CircuitVar, Field},
    CircuitError,
};

use super::{
    fixtures::{
        low_bits, CheckBits, CheckIsBool, ConstantCheckBits, ConstantIsBool, FromBits, ToBits,
        BIT_WIDTH_TOO_LARGE, FROM_BITS_RULE, NOT_ZERO_OR_ONE, TO_BITS_RULE, VALUE_TOO_LARGE,
    },
    vectors::{
        Vector, BITS_4, BOOL, TWO_POW_252, TWO_POW_253_MINUS_1, WIDTH_1, WIDTH_253, WIDTH_4,
    },
};
use crate::harness::{
    field::{field, TWO_POW_253},
    fixture::{native, native_circuit, per_vector, rule_broken, Refusal},
};

fn fits(vector: &Vector) -> Result<(), Refusal> {
    if vector.holds {
        Ok(())
    } else {
        Err(VALUE_TOO_LARGE)
    }
}

fn values(bits: &[Bool]) -> Vec<Field> {
    bits.iter()
        .map(|bit| value(&CircuitVar::from(bit.clone())).expect("a constant bit"))
        .collect()
}

fn message(result: Result<(), CircuitError>) -> Result<(), String> {
    result.map_err(|error| error.to_string())
}

#[test]
fn check_bits_holds_natively_exactly_below_two_to_the_width() {
    assert_eq!(
        (
            per_vector(&WIDTH_1, |vector| native(&CheckBits::<1> {
                x: vector.field()
            })),
            per_vector(&WIDTH_4, |vector| native(&CheckBits::<4> {
                x: vector.field()
            })),
            per_vector(&WIDTH_253, |vector| native(&CheckBits::<253> {
                x: vector.field()
            })),
        ),
        (
            per_vector(&WIDTH_1, fits),
            per_vector(&WIDTH_4, fits),
            per_vector(&WIDTH_253, fits),
        )
    );
}

#[test]
fn a_width_of_0_admits_exactly_zero() {
    assert_eq!(
        [
            native(&CheckBits::<0> { x: field("0") }),
            native(&CheckBits::<0> { x: field("1") }),
        ],
        [Ok(()), Err(VALUE_TOO_LARGE)]
    );
}

#[test]
fn a_width_of_254_or_more_is_refused_for_every_value() {
    assert_eq!(
        [
            native(&CheckBits::<254> { x: field("0") }),
            native(&CheckBits::<254> { x: field("1") }),
            native(&CheckBits::<255> { x: field("0") }),
            native(&CheckBits::<256> { x: field("0") }),
            native(&ToBits::<254> {
                x: field("0"),
                bits: [Field::from(0u64); 254],
            }),
        ],
        [Err(BIT_WIDTH_TOO_LARGE); 5]
    );
}

#[test]
fn each_width_refusal_names_the_width() {
    assert_eq!(
        (
            message(constant(16u64).check_bits(4)),
            message(constant(0u64).check_bits(254)),
            message(constant(2u64).check_is_bool()),
        ),
        (
            Err("a value does not fit in 4 bits".to_string()),
            Err(
                "a check over 254 bits is too wide; a circuit value holds at most 253 bits"
                    .to_string()
            ),
            Err("a value is neither 0 nor 1".to_string()),
        )
    );
}

#[test]
fn check_is_bool_holds_natively_exactly_for_0_and_1() {
    assert_eq!(
        per_vector(&BOOL, |vector| native(&CheckIsBool { x: vector.field() })),
        per_vector(&BOOL, |vector| if vector.holds {
            Ok(())
        } else {
            Err(NOT_ZERO_OR_ONE)
        })
    );
}

#[test]
fn a_constant_is_checked_when_the_circuit_is_built() {
    assert_eq!(
        (
            native(&ConstantCheckBits::<7, 3> { unused: field("0") }),
            native(&ConstantCheckBits::<8, 3> { unused: field("0") }),
            native(&ConstantIsBool::<1> { unused: field("0") }),
            native(&ConstantIsBool::<2> { unused: field("0") }),
        ),
        (Ok(()), Err(VALUE_TOO_LARGE), Ok(()), Err(NOT_ZERO_OR_ONE))
    );
}

#[test]
fn to_bits_le_holds_natively_exactly_for_the_little_endian_bits_of_a_fitting_value() {
    assert_eq!(
        per_vector(&BITS_4, |vector| native(&ToBits::<4> {
            x: vector.value(),
            bits: vector.bits(),
        })),
        per_vector(&BITS_4, |vector| match (vector.holds, vector.value < 16) {
            (true, _) => Ok(()),
            (false, true) => Err(rule_broken(TO_BITS_RULE, super::fixtures::FILE)),
            (false, false) => Err(VALUE_TOO_LARGE),
        })
    );
}

#[test]
fn the_native_bits_of_a_constant_are_its_little_endian_binary_digits() {
    let bits_of = |decimal: &str| -> Vec<Field> {
        values(
            &constant(field(decimal))
                .to_bits_le::<253>()
                .expect("a value below 2^253"),
        )
    };
    let only =
        |bit: usize| -> Vec<Field> { (0..253).map(|index| Field::from(index == bit)).collect() };
    assert_eq!(
        (
            values(&constant(5u64).to_bits_le::<4>().expect("5 fits 4 bits")),
            values(&constant(1u64).to_bits_le::<1>().expect("1 fits 1 bit")),
            bits_of(TWO_POW_253_MINUS_1),
            bits_of(TWO_POW_252),
            values(
                &native_circuit(&ToBits::<4> {
                    x: field("5"),
                    bits: low_bits(5)
                })
                .expect("native instantiation")
                .x
                .to_bits_le::<4>()
                .expect("5 fits 4 bits")
            ),
        ),
        (
            low_bits::<4>(5).to_vec(),
            vec![Field::from(1u64)],
            vec![Field::from(1u64); 253],
            only(252),
            low_bits::<4>(5).to_vec(),
        )
    );
}

#[test]
fn from_bits_le_is_the_weighted_sum_and_wraps_past_253_bits() {
    let ones = |count: usize| vec![Bool::constant(true); count];
    let sum = |bits: &[Bool]| value(&from_bits_le(bits)).expect("constant bits");
    let two_pow_254_minus_1 = field(TWO_POW_253) + field(TWO_POW_253) - Field::from(1u64);
    assert_eq!(
        (
            sum(&[]),
            sum(&[
                Bool::constant(true),
                Bool::constant(false),
                Bool::constant(true)
            ]),
            sum(&ones(253)),
            sum(&ones(254)),
        ),
        (
            Field::from(0u64),
            Field::from(5u64),
            field(TWO_POW_253_MINUS_1),
            two_pow_254_minus_1,
        )
    );
}

#[test]
fn from_bits_le_undoes_to_bits_le_at_every_width_edge() {
    let round_trip = |decimal: &str| {
        let x = constant(field(decimal));
        value(&from_bits_le(&x.to_bits_le::<253>().expect("fits"))).expect("constant")
    };
    let fitting = WIDTH_253.into_iter().filter(|vector| vector.holds);
    assert_eq!(
        fitting
            .clone()
            .map(|vector| round_trip(vector.x))
            .collect::<Vec<_>>(),
        fitting.map(|vector| vector.field()).collect::<Vec<_>>()
    );
}

#[test]
fn from_bits_holds_natively_exactly_for_boolean_bits_and_their_sum() {
    assert_eq!(
        per_vector(&BITS_4, |vector| native(&FromBits::<4> {
            bits: vector.bits(),
            value: vector.value(),
        })),
        per_vector(&BITS_4, |vector| {
            match (vector.holds, vector.bits.iter().all(|bit| *bit <= 1)) {
                (true, _) => Ok(()),
                (false, true) => Err(rule_broken(FROM_BITS_RULE, super::fixtures::FILE)),
                (false, false) => Err(NOT_ZERO_OR_ONE),
            }
        })
    );
}
