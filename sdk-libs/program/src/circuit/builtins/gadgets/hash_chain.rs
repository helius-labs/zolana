use ark_r1cs_std::boolean::Boolean;

use crate::{
    circuit::{builtins::field::var::system_of, labels::Scope, poseidon, zero, Bool, CircuitVar},
    CircuitError,
};

#[track_caller]
pub fn nonzero_hash_chain(values: &[CircuitVar]) -> Result<CircuitVar, CircuitError> {
    let _scope = Scope::open(&system_of(values), "a hash chain of the nonzero values");
    values.iter().try_fold(zero(), |chain, value| {
        let skip = value.equals_zero()?;
        if let Boolean::Constant(true) = skip {
            return Ok(chain);
        }
        let next = match chain.equals_zero()? {
            Boolean::Constant(true) => value.clone(),
            Boolean::Constant(false) => poseidon(&[chain.clone(), value.clone()])?,
            empty => Bool::from_checked(CircuitVar::from_boolean(empty))
                .select(value, &poseidon(&[chain.clone(), value.clone()])?),
        };
        match skip {
            Boolean::Constant(_) => Ok(next),
            skip => Ok(Bool::from_checked(CircuitVar::from_boolean(skip)).select(&chain, &next)),
        }
    })
}
