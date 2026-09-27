use super::{zero, Assert, Bool, CircuitVar};
use crate::CircuitError;

pub trait Compare: Sized {
    #[track_caller]
    fn is_zero(&self) -> Result<Bool, CircuitError>;

    #[track_caller]
    fn assert_zero(&self, rule: &'static str) -> Result<(), CircuitError>;

    #[track_caller]
    fn assert_nonzero(&self, rule: &'static str) -> Result<(), CircuitError>;
}

impl Compare for CircuitVar {
    #[track_caller]
    fn is_zero(&self) -> Result<Bool, CircuitError> {
        Ok(Bool::from_checked(CircuitVar::from_boolean(
            self.equals_zero()?,
        )))
    }

    #[track_caller]
    fn assert_zero(&self, rule: &'static str) -> Result<(), CircuitError> {
        self.assert_equal(&zero(), rule)
    }

    #[track_caller]
    fn assert_nonzero(&self, rule: &'static str) -> Result<(), CircuitError> {
        self.assert_not_equal(&zero(), rule)
    }
}
