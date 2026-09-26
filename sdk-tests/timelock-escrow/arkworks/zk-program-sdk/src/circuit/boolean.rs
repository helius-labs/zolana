use super::{
    constant, field, labels::Scope, Assert, Bits, CircuitVar, Compare, Field, Select, Uint,
};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct Bool(CircuitVar);

impl Bool {
    pub fn constant(value: bool) -> Self {
        Self(constant(u64::from(value)))
    }

    #[track_caller]
    pub fn from_var(var: &CircuitVar) -> Result<Self, RelationError> {
        var.check_is_bool()?;
        Ok(Self(var.clone()))
    }

    pub(crate) fn from_checked(var: CircuitVar) -> Self {
        Self(var)
    }

    #[track_caller]
    pub(crate) fn of_equality(
        left: &CircuitVar,
        right: &CircuitVar,
    ) -> Result<Self, RelationError> {
        let _scope = Scope::open(&left.cs().or(right.cs()), "an equality test");
        Ok(Self(CircuitVar::from_boolean(left.equals(right)?)))
    }

    pub fn var(&self) -> CircuitVar {
        self.0.clone()
    }

    pub fn to_uint(&self) -> Uint<1> {
        Uint::trusted(self.0.clone())
    }

    pub fn not(&self) -> Self {
        Self(constant(1u64).minus(&self.0))
    }

    pub fn and(&self, other: &Self) -> Self {
        Self(self.0.times(&other.0))
    }

    pub fn or(&self, other: &Self) -> Self {
        Self(self.0.plus(&other.0).minus(&self.0.times(&other.0)))
    }

    pub fn xor(&self, other: &Self) -> Self {
        Self(
            self.0
                .plus(&other.0)
                .minus(&self.0.times(&other.0).scaled(Field::from(2u64))),
        )
    }

    pub fn nand(&self, other: &Self) -> Self {
        self.and(other).not()
    }

    pub fn implies(&self, other: &Self) -> Self {
        Self(constant(1u64).minus(&self.0).plus(&self.0.times(&other.0)))
    }

    #[track_caller]
    pub fn all(flags: &[Self]) -> Result<Self, RelationError> {
        match flags {
            [] => Ok(Self::constant(true)),
            [flag] => Ok(flag.clone()),
            flags => sum(flags).is_equal(&constant(flags.len() as u64)),
        }
    }

    #[track_caller]
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

    #[track_caller]
    pub fn assert_true(&self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&constant(1u64), rule)
    }

    #[track_caller]
    pub fn assert_false(&self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&constant(0u64), rule)
    }

    #[track_caller]
    pub fn assert_true_if(
        &self,
        condition: &Self,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.0.assert_equal_if(&constant(1u64), condition, rule)
    }
}

fn sum(flags: &[Bool]) -> CircuitVar {
    field::sum(flags.iter().map(|flag| &flag.0))
}

impl Assert for Bool {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Ok(self.xor(other).not())
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.0.assert_equal(&other.0, rule)
    }

    #[track_caller]
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
