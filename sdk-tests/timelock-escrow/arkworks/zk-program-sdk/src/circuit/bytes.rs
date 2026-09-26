use zolana_hasher::primitives::PACK_BE_CHUNK_BYTES;

use super::{
    constant, hash_bytes,
    var::{all_equal, assert_all_equal, assert_all_equal_if, bits_le, collect_array},
    zero, Assert, Bool, CircuitVar, Field, Select,
};
use crate::{circuit_lib::packed, RelationError};

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

    pub fn from_var(var: &CircuitVar) -> Result<Self, RelationError> {
        let bits = bits_le(var, 8 * N)?;
        let bytes = bits.chunks(8).rev().map(|chunk| {
            chunk
                .iter()
                .rev()
                .fold(zero(), |byte, bit| byte * Field::from(2u64) + bit)
        });
        Ok(Self {
            bytes: collect_array(bytes)?,
        })
    }

    pub(crate) fn from_checked(bytes: [CircuitVar; N]) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[CircuitVar; N] {
        &self.bytes
    }

    pub fn to_var(&self) -> Result<CircuitVar, RelationError> {
        if N > PACK_BE_CHUNK_BYTES {
            return Err(RelationError::RangeTooWide(8 * N));
        }
        Ok(packed(&self.bytes).into_iter().next().unwrap_or_else(zero))
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

impl<const N: usize> Assert for Bytes<N> {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        all_equal(&packed(&self.bytes), &packed(&other.bytes))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        assert_all_equal(&packed(&self.bytes), &packed(&other.bytes), rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        assert_all_equal_if(&packed(&self.bytes), &packed(&other.bytes), condition, rule)
    }
}

impl<const N: usize> Select for Bytes<N> {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Self {
            bytes: <[CircuitVar; N]>::select(condition, &if_true.bytes, &if_false.bytes),
        }
    }
}
