use ark_bn254::Fr;
use zolana_hasher::primitives::PACK_BE_CHUNK_BYTES;

use crate::{
    circuit::{
        builtins::{
            field::{bits::bits_le, var::collect_array},
            gadgets::hash_bytes::{hash_bytes, packed},
            ops::assert::{all_equal, assert_all_equal, assert_all_equal_if},
        },
        constant, zero, Assert, Bool, CircuitVar, Select,
    },
    CircuitError, CircuitErrorKind,
};

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

    /// Commits checked bytes of the protocol's fixed length `N`.
    ///
    /// Leading zeroes are valid. Length is not part of the commitment, so
    /// callers must use one fixed `N` per hash domain. Up to 31 bytes are
    /// packed directly; longer values fold packed chunks through Poseidon.
    #[track_caller]
    pub fn hash_bytes(&self) -> Result<CircuitVar, CircuitError> {
        hash_bytes(&self.bytes)
    }
}

impl<const N: usize> TryFrom<&CircuitVar> for Bytes<N> {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(var: &CircuitVar) -> Result<Self, CircuitError> {
        let bits = bits_le(var, 8 * N)?;
        let bytes = bits.chunks(8).rev().map(|chunk| {
            chunk
                .iter()
                .rev()
                .fold(zero(), |byte, bit| byte.scaled(Fr::from(2u64)).plus(bit))
        });
        Ok(Self {
            bytes: collect_array(bytes)?,
        })
    }
}

impl<const N: usize> TryFrom<CircuitVar> for Bytes<N> {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(var: CircuitVar) -> Result<Self, CircuitError> {
        Self::try_from(&var)
    }
}

impl<const N: usize> TryFrom<&Bytes<N>> for CircuitVar {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(bytes: &Bytes<N>) -> Result<Self, CircuitError> {
        if N > PACK_BE_CHUNK_BYTES {
            return Err(CircuitErrorKind::BitWidthTooLarge { bits: 8 * N }.into());
        }
        Ok(packed(&bytes.bytes).into_iter().next().unwrap_or_else(zero))
    }
}

impl<const N: usize> TryFrom<Bytes<N>> for CircuitVar {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(bytes: Bytes<N>) -> Result<Self, CircuitError> {
        Self::try_from(&bytes)
    }
}

impl<const N: usize> Default for Bytes<N> {
    fn default() -> Self {
        Self::constant(&[0u8; N])
    }
}

impl<const N: usize> Assert for Bytes<N> {
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        all_equal(&packed(&self.bytes), &packed(&other.bytes))
    }

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        assert_all_equal(&packed(&self.bytes), &packed(&other.bytes), rule)
    }

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
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
