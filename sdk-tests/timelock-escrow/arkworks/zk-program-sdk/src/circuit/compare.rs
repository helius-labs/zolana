use ark_ff::{One, PrimeField};
use ark_r1cs_std::fields::FieldVar;

use super::{
    constant,
    var::{bits_le, fits_or},
    zero, Assert, Bits, Bool, CircuitVar, Field, Select,
};
use crate::RelationError;

pub trait Compare: Sized {
    fn is_zero(&self) -> Result<Bool, RelationError>;

    fn assert_zero(&self, rule: &'static str) -> Result<(), RelationError>;

    fn assert_nonzero(&self, rule: &'static str) -> Result<(), RelationError>;

    fn is_less_than(&self, other: &Self, bits: usize) -> Result<Bool, RelationError>;

    fn is_less_or_equal(&self, other: &Self, bits: usize) -> Result<Bool, RelationError>;

    fn is_greater_than(&self, other: &Self, bits: usize) -> Result<Bool, RelationError>;

    fn is_greater_or_equal(&self, other: &Self, bits: usize) -> Result<Bool, RelationError>;

    fn assert_less_than(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn assert_less_or_equal(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn assert_greater_than(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn assert_greater_or_equal(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn assert_in_range(
        &self,
        low: &Self,
        high: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn min(&self, other: &Self, bits: usize) -> Result<Self, RelationError>;

    fn max(&self, other: &Self, bits: usize) -> Result<Self, RelationError>;
}

impl Compare for CircuitVar {
    fn is_zero(&self) -> Result<Bool, RelationError> {
        Ok(Bool::from_checked(CircuitVar::from(FieldVar::is_zero(
            self,
        )?)))
    }

    fn assert_zero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.assert_equal(&zero(), rule)
    }

    fn assert_nonzero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.assert_not_equal(&zero(), rule)
    }

    fn is_less_than(&self, other: &Self, bits: usize) -> Result<Bool, RelationError> {
        if bits + 1 >= Field::MODULUS_BIT_SIZE as usize {
            return Err(RelationError::RangeTooWide(bits));
        }
        self.check_bits(bits)?;
        other.check_bits(bits)?;
        let shifted = self.clone() - other + constant(power_of_two(bits));
        let at_least = bits_le(&shifted, bits + 1)?
            .pop()
            .ok_or(RelationError::RangeTooWide(bits))?;
        Ok(Bool::from_checked(at_least).not())
    }

    fn is_less_or_equal(&self, other: &Self, bits: usize) -> Result<Bool, RelationError> {
        Ok(other.is_less_than(self, bits)?.not())
    }

    fn is_greater_than(&self, other: &Self, bits: usize) -> Result<Bool, RelationError> {
        other.is_less_than(self, bits)
    }

    fn is_greater_or_equal(&self, other: &Self, bits: usize) -> Result<Bool, RelationError> {
        Ok(self.is_less_than(other, bits)?.not())
    }

    fn assert_less_than(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.check_bits(bits)?;
        fits_or(
            &(other.clone() - self - constant(1u64)),
            bits,
            RelationError::Violated(rule),
        )
    }

    fn assert_less_or_equal(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.check_bits(bits)?;
        fits_or(&(other.clone() - self), bits, RelationError::Violated(rule))
    }

    fn assert_greater_than(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        other.assert_less_than(self, bits, rule)
    }

    fn assert_greater_or_equal(
        &self,
        other: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        other.assert_less_or_equal(self, bits, rule)
    }

    fn assert_in_range(
        &self,
        low: &Self,
        high: &Self,
        bits: usize,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        low.assert_less_or_equal(self, bits, rule)?;
        self.assert_less_or_equal(high, bits, rule)
    }

    fn min(&self, other: &Self, bits: usize) -> Result<Self, RelationError> {
        Ok(CircuitVar::select(
            &self.is_less_than(other, bits)?,
            self,
            other,
        ))
    }

    fn max(&self, other: &Self, bits: usize) -> Result<Self, RelationError> {
        Ok(CircuitVar::select(
            &self.is_less_than(other, bits)?,
            other,
            self,
        ))
    }
}

pub(crate) fn power_of_two(bits: usize) -> Field {
    (0..bits).fold(Field::one(), |power, _| power + power)
}
