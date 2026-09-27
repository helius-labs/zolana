use ark_ff::{Field as _, Zero};

use super::{constant, CircuitVar};
use crate::RelationError;

pub trait Arithmetic: Sized {
    fn inverse(&self) -> Result<Self, RelationError>;

    fn div(&self, divisor: &Self) -> Result<Self, RelationError>;

    fn pow(&self, exponent: u64) -> Result<Self, RelationError>;
}

impl Arithmetic for CircuitVar {
    #[track_caller]
    fn inverse(&self) -> Result<Self, RelationError> {
        if let Some(value) = self.constant_value() {
            return value
                .inverse()
                .map(constant)
                .ok_or(RelationError::DivisionByZero);
        }
        if self.assigned().is_ok_and(|value| value.is_zero()) {
            return Err(RelationError::DivisionByZero);
        }
        self.inverted()
    }

    #[track_caller]
    fn div(&self, divisor: &Self) -> Result<Self, RelationError> {
        Ok(self.times(&Arithmetic::inverse(divisor)?))
    }

    fn pow(&self, exponent: u64) -> Result<Self, RelationError> {
        self.power(exponent)
    }
}
