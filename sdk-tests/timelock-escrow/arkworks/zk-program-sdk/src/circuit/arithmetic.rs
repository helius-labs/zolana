use ark_ff::{BigInteger, Field as _, PrimeField, Zero};
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, R1CSVar};
use ark_relations::r1cs::SynthesisError;

use super::{constant, var::fits_or, Assert, Bits, CircuitVar, Compare, Field};
use crate::RelationError;

pub trait Arithmetic: Sized {
    fn checked_add(&self, other: &Self, bits: usize) -> Result<Self, RelationError>;

    fn checked_sub(&self, other: &Self, bits: usize) -> Result<Self, RelationError>;

    fn checked_mul(&self, other: &Self, bits: usize) -> Result<Self, RelationError>;

    fn div_rem(&self, divisor: &Self, bits: usize) -> Result<(Self, Self), RelationError>;

    fn inverse(&self) -> Result<Self, RelationError>;

    fn div(&self, divisor: &Self) -> Result<Self, RelationError>;

    fn pow(&self, exponent: u64) -> Result<Self, RelationError>;
}

impl Arithmetic for CircuitVar {
    fn checked_add(&self, other: &Self, bits: usize) -> Result<Self, RelationError> {
        self.check_bits(bits)?;
        other.check_bits(bits)?;
        let sum = self.clone() + other;
        fits_or(&sum, bits, RelationError::Overflow(bits))?;
        Ok(sum)
    }

    fn checked_sub(&self, other: &Self, bits: usize) -> Result<Self, RelationError> {
        other.check_bits(bits)?;
        let difference = self.clone() - other;
        fits_or(&difference, bits, RelationError::Underflow(bits))?;
        Ok(difference)
    }

    fn checked_mul(&self, other: &Self, bits: usize) -> Result<Self, RelationError> {
        if 2 * bits >= Field::MODULUS_BIT_SIZE as usize {
            return Err(RelationError::RangeTooWide(bits));
        }
        self.check_bits(bits)?;
        other.check_bits(bits)?;
        let product = self.clone() * other;
        fits_or(&product, bits, RelationError::Overflow(bits))?;
        Ok(product)
    }

    fn div_rem(&self, divisor: &Self, bits: usize) -> Result<(Self, Self), RelationError> {
        if 2 * bits >= Field::MODULUS_BIT_SIZE as usize {
            return Err(RelationError::RangeTooWide(bits));
        }
        self.check_bits(bits)?;
        divisor.check_bits(bits)?;
        let dividend = self.value().ok().and_then(integer);
        let known_divisor = divisor.value().ok().and_then(integer);
        if known_divisor == Some(0) {
            return Err(RelationError::DivisionByZero);
        }
        let division = dividend.zip(known_divisor).and_then(|(dividend, divisor)| {
            Some((
                dividend.checked_div(divisor)?,
                dividend.checked_rem(divisor)?,
            ))
        });
        let (quotient, remainder) = match (self, divisor) {
            (CircuitVar::Constant(_), CircuitVar::Constant(_)) => {
                let (quotient, remainder) = division.ok_or(RelationError::DivisionByZero)?;
                (constant(quotient), constant(remainder))
            }
            _ => {
                let cs = self.cs().or(divisor.cs());
                let quotient = CircuitVar::new_witness(cs.clone(), || {
                    division
                        .map(|(quotient, _)| Field::from(quotient))
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;
                let remainder = CircuitVar::new_witness(cs, || {
                    division
                        .map(|(_, remainder)| Field::from(remainder))
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;
                (quotient, remainder)
            }
        };
        quotient.check_bits(bits)?;
        remainder.assert_less_than(divisor, bits, "the remainder is below the divisor")?;
        (quotient.clone() * divisor + &remainder)
            .assert_equal(self, "the quotient and remainder rebuild the dividend")?;
        Ok((quotient, remainder))
    }

    fn inverse(&self) -> Result<Self, RelationError> {
        if let CircuitVar::Constant(value) = self {
            return value
                .inverse()
                .map(constant)
                .ok_or(RelationError::DivisionByZero);
        }
        if self.value().is_ok_and(|value| value.is_zero()) {
            return Err(RelationError::DivisionByZero);
        }
        Ok(FieldVar::inverse(self)?)
    }

    fn div(&self, divisor: &Self) -> Result<Self, RelationError> {
        Ok(self.clone() * Arithmetic::inverse(divisor)?)
    }

    fn pow(&self, exponent: u64) -> Result<Self, RelationError> {
        Ok(self.pow_by_constant([exponent])?)
    }
}

fn integer(value: Field) -> Option<u128> {
    let value = value.into_bigint();
    if value.num_bits() > 128 {
        return None;
    }
    let limbs = value.as_ref();
    let low = u128::from(*limbs.first()?);
    let high = u128::from(*limbs.get(1)?);
    Some(low | (high << 64))
}
