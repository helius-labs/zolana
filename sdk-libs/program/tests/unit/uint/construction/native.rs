use ark_bn254::Fr;
use zolana_program::circuit::{constant, value, Bool, CircuitVar, Field, Uint};

use super::{
    fixtures::{Borrowed, Owned, FILE},
    vectors::{invalid, valid, Vector},
};
use crate::uint::{
    at_widths,
    rows::{field, native, refused, too_large, Refused},
    Widths,
};

const UINT_FILE: &str = "sdk-libs/program/src/circuit/builtins/types/uint.rs";

type Forms = (Result<(), Refused>, Result<(), Refused>);

struct Instantiated;

impl Widths for Instantiated {
    type Output = Vec<(&'static str, Forms)>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        valid(BITS)
            .into_iter()
            .chain(invalid(BITS))
            .map(|Vector { name, x }| {
                let x = field(x);
                (
                    name,
                    (
                        native(&Borrowed::<BITS> { x }),
                        native(&Owned::<BITS> { x }),
                    ),
                )
            })
            .collect()
    }
}

#[test]
fn try_from_accepts_exactly_the_values_below_two_to_the_width_natively() {
    assert_eq!(
        at_widths!(&Instantiated, [1, 4, 64, 252, 253]),
        [1, 4, 64, 252, 253]
            .into_iter()
            .map(|bits| {
                let accepted = valid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, (Ok(()), Ok(()))));
                let refusal = || Err(too_large(bits as usize, FILE));
                let refused = invalid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, (refusal(), refusal())));
                (bits, accepted.chain(refused).collect())
            })
            .collect::<Vec<_>>()
    );
}

struct Values;

impl Widths for Values {
    type Output = Vec<(
        &'static str,
        (Result<Field, Refused>, Result<Field, Refused>),
    )>;

    fn at<const BITS: u32>(&self) -> Self::Output {
        valid(BITS)
            .into_iter()
            .map(|Vector { name, x }| {
                let var = constant(field(x));
                let owned = Uint::<BITS>::try_from(var.clone());
                let borrowed = Uint::<BITS>::try_from(&var);
                let value_of = |uint: Result<Uint<BITS>, _>| {
                    refused(uint.and_then(|uint| value(&CircuitVar::from(uint))))
                };
                (name, (value_of(owned), value_of(borrowed)))
            })
            .collect()
    }
}

#[test]
fn try_from_keeps_the_value_of_every_accepted_constant() {
    assert_eq!(
        at_widths!(&Values, [1, 4, 64, 252, 253]),
        [1, 4, 64, 252, 253]
            .into_iter()
            .map(|bits| {
                let kept = valid(bits)
                    .into_iter()
                    .map(|vector| (vector.name, (Ok(field(vector.x)), Ok(field(vector.x)))));
                (bits, kept.collect())
            })
            .collect::<Vec<_>>()
    );
}

fn constant_value<const BITS: u32>(value_of: u64) -> Result<Field, Refused> {
    refused(Uint::<BITS>::constant(value_of).and_then(|uint| value(&CircuitVar::from(uint))))
}

#[test]
fn constant_accepts_exactly_the_u64_values_below_two_to_the_width() {
    assert_eq!(
        [
            constant_value::<1>(0),
            constant_value::<1>(1),
            constant_value::<1>(2),
            constant_value::<4>(15),
            constant_value::<4>(16),
            constant_value::<8>(255),
            constant_value::<8>(256),
            constant_value::<63>((1 << 63) - 1),
            constant_value::<63>(1 << 63),
            constant_value::<64>(u64::MAX),
            constant_value::<128>(u64::MAX),
            constant_value::<253>(u64::MAX),
        ],
        [
            Ok(Field::from(0u64)),
            Ok(Field::from(1u64)),
            Err(too_large(1, UINT_FILE)),
            Ok(Field::from(15u64)),
            Err(too_large(4, UINT_FILE)),
            Ok(Field::from(255u64)),
            Err(too_large(8, UINT_FILE)),
            Ok(Field::from((1u64 << 63) - 1)),
            Err(too_large(63, UINT_FILE)),
            Ok(Field::from(u64::MAX)),
            Ok(Field::from(u64::MAX)),
            Ok(Field::from(u64::MAX)),
        ]
    );
}

#[test]
fn zero_is_the_constant_zero_at_every_width() {
    let zero = |uint: CircuitVar| (format!("{uint:?}"), refused(value(&uint)));
    let expected = || ("CircuitVar::constant(0)".to_string(), Ok(Field::from(0u64)));
    assert_eq!(
        [
            zero(Uint::<1>::zero().into()),
            zero(Uint::<64>::zero().into()),
            zero(Uint::<253>::zero().into()),
        ],
        [expected(), expected(), expected()]
    );
}

#[test]
fn a_bool_converts_to_exactly_zero_or_one_at_every_width() {
    let of = |bit: bool| {
        [
            value(&CircuitVar::from(Uint::<1>::from(Bool::constant(bit)))),
            value(&CircuitVar::from(Uint::<64>::from(Bool::constant(bit)))),
            value(&CircuitVar::from(Uint::<253>::from(Bool::constant(bit)))),
        ]
        .map(refused)
    };
    assert_eq!(
        (of(false), of(true)),
        (
            [0u64; 3].map(|v| Ok(Field::from(v))),
            [1u64; 3].map(|v| Ok(Field::from(v)))
        )
    );
}

#[test]
fn into_circuit_var_is_the_same_constant() {
    let x = Fr::from(13u64);
    let uint = Uint::<4>::try_from(constant(field(x))).expect("13 fits in 4 bits");
    let var = CircuitVar::from(uint);
    assert_eq!(
        (format!("{var:?}"), refused(value(&var))),
        ("CircuitVar::constant(13)".to_string(), Ok(field(x)))
    );
}
