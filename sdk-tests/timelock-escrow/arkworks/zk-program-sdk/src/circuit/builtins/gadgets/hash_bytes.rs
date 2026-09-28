use ark_bn254::Fr;
use zolana_hasher::primitives::PACK_BE_CHUNK_BYTES;

use crate::{
    circuit::{builtins::field::var::system_of, labels::Scope, poseidon, zero, CircuitVar},
    CircuitError,
};

/// Internal packing for checked bytes and the fixed owner preimage. The owner
/// path retains its conditional tag check for dummy slots.
#[track_caller]
pub(crate) fn hash_bytes<const N: usize>(
    bytes: &[CircuitVar; N],
) -> Result<CircuitVar, CircuitError> {
    let _scope = Scope::open(&system_of(bytes), "a hash of bytes");
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
            chunk.iter().fold(zero(), |packed, byte| {
                packed.scaled(Fr::from(256u64)).plus(byte)
            })
        })
        .collect()
}
