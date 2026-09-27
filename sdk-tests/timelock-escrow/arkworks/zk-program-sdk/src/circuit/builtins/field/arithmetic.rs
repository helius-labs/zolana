use ark_ff::{Field as _, Zero};

use super::var::{constant, CircuitVar};
use crate::{CircuitError, CircuitErrorKind};

impl CircuitVar {
    #[track_caller]
    pub fn inverse(&self) -> Result<Self, CircuitError> {
        if let Some(value) = self.constant_value() {
            return value
                .inverse()
                .map(constant)
                .ok_or(CircuitErrorKind::DivisionByZero.into());
        }
        if self.assigned().is_ok_and(|value| value.is_zero()) {
            return Err(CircuitErrorKind::DivisionByZero.into());
        }
        self.inverted()
    }

    #[track_caller]
    pub fn div(&self, divisor: &Self) -> Result<Self, CircuitError> {
        Ok(self.times(&divisor.inverse()?))
    }

    #[track_caller]
    pub fn pow(&self, exponent: u64) -> Result<Self, CircuitError> {
        self.power(exponent)
    }
}
