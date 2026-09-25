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

pub trait Assert {
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError>;

    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError>;

    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError>;

    fn check_bits(&self, bits: usize) -> Result<(), RelationError>;

    fn check_is_bool(&self) -> Result<(), RelationError>;
}

impl Assert for CircuitVar {
    // TODO: add track caller to all asserts
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

    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Bool::is_equal(self, other)
    }

    fn check_bits(&self, bits: usize) -> Result<(), RelationError> {
        if bits >= Field::MODULUS_BIT_SIZE as usize {
            return Err(RelationError::RangeTooWide(bits));
        }
        if let CircuitVar::Constant(value) = self {
            return if value.into_bigint().num_bits() as usize <= bits {
                Ok(())
            } else {
                Err(RelationError::OutOfRange(bits))
            };
        }
        let cs = self.cs();
        let value = self.value().ok();
        let mut sum = zero();
        let mut weight = Field::one();
        for index in 0..bits {
            let bit = Boolean::new_witness(cs.clone(), || {
                value
                    .map(|value| value.into_bigint().get_bit(index))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            sum += CircuitVar::from(bit) * weight;
            weight.double_in_place();
        }
        Ok(sum.enforce_equal(self)?)
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
}

pub(crate) fn subtract_within(
    balance: &CircuitVar,
    amount: &CircuitVar,
    rule: &'static str,
) -> Result<CircuitVar, RelationError> {
    if let (CircuitVar::Constant(balance), CircuitVar::Constant(amount)) = (balance, amount) {
        if amount.into_bigint() > balance.into_bigint() {
            return Err(RelationError::Violated(rule));
        }
    }
    Ok(balance.clone() - amount)
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
