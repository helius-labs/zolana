use ark_r1cs_std::eq::EqGadget;

use super::{constant, CircuitVar};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct Bool(CircuitVar);

impl Bool {
    pub fn constant(value: bool) -> Self {
        Self(constant(u64::from(value)))
    }

    pub(crate) fn from_checked(var: CircuitVar) -> Self {
        Self(var)
    }

    pub(crate) fn is_equal(left: &CircuitVar, right: &CircuitVar) -> Result<Self, RelationError> {
        Ok(Self(CircuitVar::from(left.is_eq(right)?)))
    }

    pub fn var(&self) -> CircuitVar {
        self.0.clone()
    }

    pub fn not(&self) -> Self {
        Self(constant(1u64) - &self.0)
    }

    pub fn and(&self, other: &Self) -> Self {
        Self(self.0.clone() * &other.0)
    }

    pub fn or(&self, other: &Self) -> Self {
        Self(self.0.clone() + &other.0 - self.0.clone() * &other.0)
    }

    pub fn select(&self, if_true: &CircuitVar, if_false: &CircuitVar) -> CircuitVar {
        if_false.clone() + self.0.clone() * (if_true.clone() - if_false)
    }
}
