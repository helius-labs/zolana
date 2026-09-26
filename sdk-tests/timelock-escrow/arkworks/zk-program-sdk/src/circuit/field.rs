use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    R1CSVar,
};
use ark_relations::r1cs::SynthesisError;

use super::{labels, CircuitSystem, CircuitVar, Field, VariableRole};
use crate::RelationError;

impl CircuitVar {
    pub(crate) fn cs(&self) -> CircuitSystem {
        self.0.cs()
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.0.is_constant()
    }

    pub(crate) fn constant_value(&self) -> Option<Field> {
        match &self.0 {
            FpVar::Constant(value) => Some(*value),
            FpVar::Var(_) => None,
        }
    }

    pub(crate) fn assigned(&self) -> Result<Field, SynthesisError> {
        self.0.value()
    }

    pub(crate) fn witness(
        cs: &CircuitSystem,
        value: impl FnOnce() -> Result<Field, SynthesisError>,
    ) -> Result<Self, RelationError> {
        Ok(Self(FpVar::new_witness(cs.clone(), value)?))
    }

    #[cfg(feature = "client")]
    pub(crate) fn input(
        cs: &CircuitSystem,
        value: impl FnOnce() -> Result<Field, SynthesisError>,
    ) -> Result<Self, RelationError> {
        Ok(Self(FpVar::new_input(cs.clone(), value)?))
    }

    pub(crate) fn from_boolean(bit: Boolean<Field>) -> Self {
        Self(FpVar::from(bit))
    }

    pub(crate) fn plus(&self, other: &Self) -> Self {
        Self(self.0.clone() + &other.0)
    }

    pub(crate) fn minus(&self, other: &Self) -> Self {
        Self(self.0.clone() - &other.0)
    }

    pub(crate) fn times(&self, other: &Self) -> Self {
        Self(self.0.clone() * &other.0)
    }

    pub(crate) fn scaled(&self, factor: Field) -> Self {
        Self(self.0.clone() * factor)
    }

    pub(crate) fn offset(&self, addend: Field) -> Self {
        Self(self.0.clone() + addend)
    }

    pub(crate) fn squared(&self) -> Result<Self, RelationError> {
        Ok(Self(self.0.square()?))
    }

    pub(crate) fn inverted(&self) -> Result<Self, RelationError> {
        Ok(Self(self.0.inverse()?))
    }

    pub(crate) fn power(&self, exponent: u64) -> Result<Self, RelationError> {
        Ok(Self(self.0.pow_by_constant([exponent])?))
    }

    pub(crate) fn choose(
        condition: &Boolean<Field>,
        if_true: &Self,
        if_false: &Self,
    ) -> Result<Self, RelationError> {
        Ok(Self(FpVar::conditionally_select(
            condition,
            &if_true.0,
            &if_false.0,
        )?))
    }

    #[track_caller]
    pub(crate) fn equals(&self, other: &Self) -> Result<Boolean<Field>, RelationError> {
        let cs = self.cs().or(other.cs());
        let first = cs.num_witness_variables();
        let equal = self.0.is_eq(&other.0)?;
        labels::mark(
            &cs,
            first + 1..cs.num_witness_variables(),
            "the inverse hint of an equality test",
            VariableRole::Multiplier,
        );
        Ok(equal)
    }

    #[track_caller]
    pub(crate) fn equals_zero(&self) -> Result<Boolean<Field>, RelationError> {
        self.equals(&CircuitVar(FpVar::Constant(Field::from(0u64))))
    }

    pub(crate) fn enforce_equal(&self, other: &Self) -> Result<(), RelationError> {
        Ok(self.0.enforce_equal(&other.0)?)
    }

    pub(crate) fn enforce_equal_if(
        &self,
        other: &Self,
        condition: &Boolean<Field>,
    ) -> Result<(), RelationError> {
        Ok(self.0.conditional_enforce_equal(&other.0, condition)?)
    }

    pub(crate) fn enforce_product(
        &self,
        other: &Self,
        product: &Self,
    ) -> Result<(), RelationError> {
        Ok(self.0.mul_equals(&other.0, &product.0)?)
    }
}

pub(crate) fn sum<'a>(vars: impl IntoIterator<Item = &'a CircuitVar>) -> CircuitVar {
    CircuitVar(
        vars.into_iter()
            .fold(FpVar::Constant(Field::from(0u64)), |sum, var| sum + &var.0),
    )
}
