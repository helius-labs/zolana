use ark_r1cs_std::{boolean::Boolean, fields::FieldVar, select::CondSelectGadget};

use super::poseidon;
use crate::{
    circuit::{zero, CircuitVar},
    RelationError,
};

pub fn nonzero_hash_chain(values: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    values.iter().try_fold(zero(), |chain, value| {
        let skip = value.is_zero()?;
        if let Boolean::Constant(skip) = skip {
            return if skip {
                Ok(chain)
            } else {
                poseidon(&[chain, value.clone()])
            };
        }
        let next = poseidon(&[chain.clone(), value.clone()])?;
        Ok(CircuitVar::conditionally_select(&skip, &chain, &next)?)
    })
}
