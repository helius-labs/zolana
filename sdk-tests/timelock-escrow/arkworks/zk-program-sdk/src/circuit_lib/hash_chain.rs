use ark_r1cs_std::boolean::Boolean;

use super::poseidon;
use crate::{
    circuit::{labels::Scope, var::system_of, zero, Bool, CircuitVar},
    RelationError,
};

#[track_caller]
pub fn nonzero_hash_chain(values: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    let _scope = Scope::open(&system_of(values), "a hash chain of the nonzero values");
    values.iter().try_fold(zero(), |chain, value| {
        let skip = value.equals_zero()?;
        if let Boolean::Constant(skip) = skip {
            return if skip {
                Ok(chain)
            } else {
                poseidon(&[chain, value.clone()])
            };
        }
        let next = poseidon(&[chain.clone(), value.clone()])?;
        Ok(Bool::from_checked(CircuitVar::from_boolean(skip)).select(&chain, &next))
    })
}
