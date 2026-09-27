use super::{zero, Assert, Bool, CircuitVar};
use crate::RelationError;

pub trait Compare: Sized {
    fn is_zero(&self) -> Result<Bool, RelationError>;

    fn assert_zero(&self, rule: &'static str) -> Result<(), RelationError>;

    fn assert_nonzero(&self, rule: &'static str) -> Result<(), RelationError>;
}

impl Compare for CircuitVar {
    #[track_caller]
    fn is_zero(&self) -> Result<Bool, RelationError> {
        Ok(Bool::from_checked(CircuitVar::from_boolean(
            self.equals_zero()?,
        )))
    }

    #[track_caller]
    fn assert_zero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.assert_equal(&zero(), rule)
    }

    #[track_caller]
    fn assert_nonzero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.assert_not_equal(&zero(), rule)
    }
}
