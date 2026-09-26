use super::{constant, Assert, Bits, CircuitVar, Compare, Field, Select};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct Bool(CircuitVar);

impl Bool {
    pub fn constant(value: bool) -> Self {
        Self(constant(u64::from(value)))
    }

    pub fn from_var(var: &CircuitVar) -> Result<Self, RelationError> {
        var.check_is_bool()?;
        Ok(Self(var.clone()))
    }

    pub(crate) fn from_checked(var: CircuitVar) -> Self {
        Self(var)
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

    pub fn xor(&self, other: &Self) -> Self {
        Self(self.0.clone() + &other.0 - (self.0.clone() * &other.0) * Field::from(2u64))
    }

    pub fn nand(&self, other: &Self) -> Self {
        self.and(other).not()
    }

    pub fn implies(&self, other: &Self) -> Self {
        Self(constant(1u64) - &self.0 + self.0.clone() * &other.0)
    }

    pub fn all(flags: &[Self]) -> Result<Self, RelationError> {
        match flags {
            [] => Ok(Self::constant(true)),
            [flag] => Ok(flag.clone()),
            flags => sum(flags).is_equal(&constant(flags.len() as u64)),
        }
    }

    pub fn any(flags: &[Self]) -> Result<Self, RelationError> {
        match flags {
            [] => Ok(Self::constant(false)),
            [flag] => Ok(flag.clone()),
            flags => Ok(sum(flags).is_zero()?.not()),
        }
    }

    pub fn select<T: Select>(&self, if_true: &T, if_false: &T) -> T {
        T::select(self, if_true, if_false)
    }

    pub fn assert_true(&self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&constant(1u64), rule)
    }

    pub fn assert_false(&self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&constant(0u64), rule)
    }

    pub fn assert_true_if(
        &self,
        condition: &Self,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.0.assert_equal_if(&constant(1u64), condition, rule)
    }
}

fn sum(flags: &[Bool]) -> CircuitVar {
    flags.iter().fold(constant(0u64), |sum, flag| sum + &flag.0)
}

impl Assert for Bool {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Ok(self.xor(other).not())
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&other.0, rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.0.assert_equal_if(&other.0, condition, rule)
    }
}

impl Select for Bool {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self(CircuitVar::select(condition, &if_true.0, &if_false.0))
    }
}
