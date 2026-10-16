use zolana_zk_dsl::{
    circuit::{
        builtins::{field::var::system_of, types::bytes::packed},
        labels::Scope,
        zero, Bytes, CircuitVar,
    },
    CircuitError,
};

use crate::poseidon;

pub trait HashBytes {
    /// Commits checked bytes of the protocol's fixed length `N`.
    ///
    /// Leading zeroes are valid. Length is not part of the commitment, so
    /// callers must use one fixed `N` per hash domain. Up to 31 bytes are
    /// packed directly; longer values fold packed chunks through Poseidon.
    fn hash_bytes(&self) -> Result<CircuitVar, CircuitError>;
}

impl<const N: usize> HashBytes for Bytes<N> {
    #[track_caller]
    fn hash_bytes(&self) -> Result<CircuitVar, CircuitError> {
        hash_bytes(self.bytes())
    }
}

/// Internal packing for checked bytes and the fixed owner preimage. The owner
/// path retains its conditional tag check for dummy slots.
#[doc(hidden)]
#[track_caller]
pub fn hash_bytes<const N: usize>(bytes: &[CircuitVar; N]) -> Result<CircuitVar, CircuitError> {
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
