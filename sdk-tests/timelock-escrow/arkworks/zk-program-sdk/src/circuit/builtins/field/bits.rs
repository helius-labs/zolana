use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, One, PrimeField, Zero};

use super::var::{collect_array, constant, zero, CircuitVar};
use crate::{
    circuit::{labels, Bool},
    CircuitError, CircuitErrorKind,
};

pub trait Bits {
    #[track_caller]
    fn check_bits(&self, bits: usize) -> Result<(), CircuitError>;

    #[track_caller]
    fn check_is_bool(&self) -> Result<(), CircuitError>;

    #[track_caller]
    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], CircuitError>;
}

impl Bits for CircuitVar {
    #[track_caller]
    fn check_bits(&self, bits: usize) -> Result<(), CircuitError> {
        range_check(self, bits, "a value does not fit in its bit width")
    }

    #[track_caller]
    fn check_is_bool(&self) -> Result<(), CircuitError> {
        assert_bool(self, "a value is neither 0 nor 1")
    }

    #[track_caller]
    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], CircuitError> {
        let bits = labels::check(&self.cs(), "a value does not fit in its bit width", || {
            bits_le(self, N)
        })?;
        collect_array(bits.into_iter().map(Bool::from_checked))
    }
}

pub fn from_bits_le(bits: &[Bool]) -> CircuitVar {
    let mut weight = Fr::one();
    bits.iter().fold(zero(), |sum, bit| {
        let sum = sum.plus(&bit.var().scaled(weight));
        weight.double_in_place();
        sum
    })
}

#[track_caller]
pub(crate) fn assert_bool(var: &CircuitVar, rule: &'static str) -> Result<(), CircuitError> {
    if let Some(value) = var.constant_value() {
        return if value.is_zero() || value.is_one() {
            Ok(())
        } else {
            Err(CircuitErrorKind::NotZeroOrOne.into())
        };
    }
    labels::check(&var.cs(), rule, || {
        var.enforce_product(&var.offset(-Fr::one()), &zero())
    })
}

#[track_caller]
pub(crate) fn range_check(
    var: &CircuitVar,
    bits: usize,
    rule: &'static str,
) -> Result<(), CircuitError> {
    labels::check(&var.cs(), rule, || bits_le(var, bits).map(|_| ()))
}

pub(crate) fn bits_le(var: &CircuitVar, bits: usize) -> Result<Vec<CircuitVar>, CircuitError> {
    if bits >= Fr::MODULUS_BIT_SIZE as usize {
        return Err(CircuitErrorKind::BitWidthTooLarge { bits }.into());
    }
    if let Some(value) = var.constant_value() {
        let value = value.into_bigint();
        if value.num_bits() as usize > bits {
            return Err(CircuitErrorKind::ValueTooLarge { bits }.into());
        }
        return Ok((0..bits)
            .map(|index| constant(u64::from(value.get_bit(index))))
            .collect());
    }
    let (decomposed, _) = var.0.to_bits_le_with_top_bits_zero(bits)?;
    Ok(decomposed
        .into_iter()
        .map(CircuitVar::from_boolean)
        .collect())
}
