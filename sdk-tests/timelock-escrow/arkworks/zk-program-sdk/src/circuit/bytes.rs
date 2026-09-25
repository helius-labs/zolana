use super::{constant, hash_bytes, CircuitVar};
use crate::RelationError;

#[derive(Clone, Debug)]
pub struct Bytes<const N: usize> {
    bytes: [CircuitVar; N],
}

impl<const N: usize> Bytes<N> {
    pub fn constant(bytes: &[u8; N]) -> Self {
        Self {
            bytes: (*bytes).map(|byte| constant(u64::from(byte))),
        }
    }

    pub(crate) fn from_checked(bytes: [CircuitVar; N]) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[CircuitVar; N] {
        &self.bytes
    }

    pub fn hash_bytes(&self) -> Result<CircuitVar, RelationError> {
        hash_bytes(&self.bytes)
    }
}

impl<const N: usize> Default for Bytes<N> {
    fn default() -> Self {
        Self::constant(&[0u8; N])
    }
}
