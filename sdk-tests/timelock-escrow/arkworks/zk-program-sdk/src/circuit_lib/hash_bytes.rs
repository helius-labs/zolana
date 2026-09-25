use zolana_hasher::primitives::PACK_BE_CHUNK_BYTES;

use super::poseidon;
use crate::{
    circuit::{zero, CircuitVar, Field},
    RelationError,
};

pub fn hash_bytes(bytes: &[CircuitVar]) -> Result<CircuitVar, RelationError> {
    let mut chunks = packed(bytes).into_iter();
    let Some(first) = chunks.next() else {
        return Ok(zero());
    };
    let mut accumulator = first;
    for chunk in chunks {
        accumulator = poseidon(&[accumulator, chunk])?;
    }
    Ok(accumulator)
}

pub(crate) fn packed(bytes: &[CircuitVar]) -> Vec<CircuitVar> {
    bytes
        .chunks(PACK_BE_CHUNK_BYTES)
        .map(|chunk| {
            chunk
                .iter()
                .fold(zero(), |packed, byte| packed * Field::from(256u64) + byte)
        })
        .collect()
}
