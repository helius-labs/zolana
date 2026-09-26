use std::cell::OnceCell;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::Bool;
use crate::RelationError;

pub type Field = Fr;
pub type CircuitVar = FpVar<Field>;
pub type CircuitSystem = ConstraintSystemRef<Field>;
pub type ConstraintSystem = ark_relations::r1cs::ConstraintSystem<Field>;

pub fn constant(value: impl Into<Field>) -> CircuitVar {
    CircuitVar::Constant(value.into())
}

pub fn zero() -> CircuitVar {
    constant(0u64)
}

pub fn value(var: &CircuitVar) -> Result<Field, RelationError> {
    Ok(var.value()?)
}

pub fn from_bits_le(bits: &[Bool]) -> CircuitVar {
    let mut weight = Field::one();
    bits.iter().fold(zero(), |sum, bit| {
        let sum = sum + bit.var() * weight;
        weight.double_in_place();
        sum
    })
}

pub(crate) fn cached(
    cell: &OnceCell<CircuitVar>,
    compute: impl FnOnce() -> Result<CircuitVar, RelationError>,
) -> Result<CircuitVar, RelationError> {
    if let Some(value) = cell.get() {
        return Ok(value.clone());
    }
    let value = compute()?;
    Ok(cell.get_or_init(|| value).clone())
}

pub(crate) fn collect_array<T, const N: usize>(
    items: impl IntoIterator<Item = T>,
) -> Result<[T; N], RelationError> {
    items
        .into_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| RelationError::Violated("an array has its own length"))
}

pub trait Assert: Sized {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError>;

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError>;

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.is_equal(other)?.assert_false(rule)
    }
}

impl Assert for CircuitVar {
    // TODO: add track caller to all asserts
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Ok(Bool::from_checked(CircuitVar::from(self.is_eq(other)?)))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        if let (CircuitVar::Constant(left), CircuitVar::Constant(right)) = (self, other) {
            return if left == right {
                Ok(())
            } else {
                Err(RelationError::Violated(rule))
            };
        }
        Ok(self.enforce_equal(other)?)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        let difference = self.clone() - other;
        match (&difference, &condition.var()) {
            (_, CircuitVar::Constant(condition)) if condition.is_zero() => Ok(()),
            (_, CircuitVar::Constant(_)) => self.assert_equal(other, rule),
            (CircuitVar::Constant(difference), _) if difference.is_zero() => Ok(()),
            (_, condition) => Ok(difference.mul_equals(condition, &zero())?),
        }
    }

    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        if let (CircuitVar::Constant(left), CircuitVar::Constant(right)) = (self, other) {
            return if left != right {
                Ok(())
            } else {
                Err(RelationError::Violated(rule))
            };
        }
        Ok(self.enforce_not_equal(other)?)
    }
}

impl<T: Assert, const N: usize> Assert for [T; N] {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        all_equal(self, other)
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        assert_all_equal(self, other, rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        assert_all_equal_if(self, other, condition, rule)
    }
}

pub(crate) fn all_equal<T: Assert>(left: &[T], right: &[T]) -> Result<Bool, RelationError> {
    let flags = left
        .iter()
        .zip(right)
        .map(|(left, right)| left.is_equal(right))
        .collect::<Result<Vec<_>, _>>()?;
    Bool::all(&flags)
}

pub(crate) fn assert_all_equal<T: Assert>(
    left: &[T],
    right: &[T],
    rule: &'static str,
) -> Result<(), RelationError> {
    left.iter()
        .zip(right)
        .try_for_each(|(left, right)| left.assert_equal(right, rule))
}

pub(crate) fn assert_all_equal_if<T: Assert>(
    left: &[T],
    right: &[T],
    condition: &Bool,
    rule: &'static str,
) -> Result<(), RelationError> {
    left.iter()
        .zip(right)
        .try_for_each(|(left, right)| left.assert_equal_if(right, condition, rule))
}

pub trait Bits {
    fn check_bits(&self, bits: usize) -> Result<(), RelationError>;

    fn check_is_bool(&self) -> Result<(), RelationError>;

    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], RelationError>;
}

impl Bits for CircuitVar {
    fn check_bits(&self, bits: usize) -> Result<(), RelationError> {
        bits_le(self, bits).map(|_| ())
    }

    fn check_is_bool(&self) -> Result<(), RelationError> {
        if let CircuitVar::Constant(value) = self {
            return if value.is_zero() || value.is_one() {
                Ok(())
            } else {
                Err(RelationError::NotBool)
            };
        }
        Ok(self.mul_equals(&(self - Field::one()), &zero())?)
    }

    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], RelationError> {
        collect_array(bits_le(self, N)?.into_iter().map(Bool::from_checked))
    }
}

pub(crate) fn bits_le(var: &CircuitVar, bits: usize) -> Result<Vec<CircuitVar>, RelationError> {
    if bits >= Field::MODULUS_BIT_SIZE as usize {
        return Err(RelationError::RangeTooWide(bits));
    }
    if let CircuitVar::Constant(value) = var {
        let value = value.into_bigint();
        if value.num_bits() as usize > bits {
            return Err(RelationError::OutOfRange(bits));
        }
        return Ok((0..bits)
            .map(|index| constant(u64::from(value.get_bit(index))))
            .collect());
    }
    let cs = var.cs();
    let value = var.value().ok();
    let mut sum = zero();
    let mut weight = Field::one();
    let mut decomposed = Vec::with_capacity(bits);
    for index in 0..bits {
        let bit = CircuitVar::from(Boolean::new_witness(cs.clone(), || {
            value
                .map(|value| value.into_bigint().get_bit(index))
                .ok_or(SynthesisError::AssignmentMissing)
        })?);
        sum += bit.clone() * weight;
        weight.double_in_place();
        decomposed.push(bit);
    }
    sum.enforce_equal(var)?;
    Ok(decomposed)
}

pub(crate) fn fits_or(
    var: &CircuitVar,
    bits: usize,
    error: RelationError,
) -> Result<(), RelationError> {
    var.check_bits(bits).map_err(|found| match found {
        RelationError::OutOfRange(_) => error,
        found => found,
    })
}

pub(crate) fn assert_equal_unless(
    left: &CircuitVar,
    right: &CircuitVar,
    skip: &Boolean<Field>,
    rule: &'static str,
) -> Result<(), RelationError> {
    if let Boolean::Constant(skip) = skip {
        return if *skip {
            Ok(())
        } else {
            left.assert_equal(right, rule)
        };
    }
    Ok(left.conditional_enforce_equal(right, &!skip)?)
}
