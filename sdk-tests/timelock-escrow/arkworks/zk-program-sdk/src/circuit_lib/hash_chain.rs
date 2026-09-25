use super::poseidon;
use crate::{
    circuit::{zero, CircuitVar},
    RelationError,
};

pub fn hash_chain4(values: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    let Some((first, rest)) = values.split_first() else {
        return Ok(zero());
    };
    let mut chain = first.clone();
    for group in rest.chunks(3) {
        let mut block = vec![chain];
        block.extend(group.iter().cloned());
        block.resize(4, zero());
        chain = poseidon(&block)?;
    }
    Ok(chain)
}
