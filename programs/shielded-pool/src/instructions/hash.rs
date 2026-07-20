use pinocchio::error::ProgramError;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::error::ShieldedPoolError;

/// Encodes a u64 as a big-endian BN254 field element (value in the low 8 bytes).
#[inline(always)]
pub(crate) fn field_from_u64(value: u64) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

/// Field encoding of a 32-byte value (owner pubkey, asset mint, or zone program
/// address): `hash_bytes(value)` (spec: Byte Field Encoding). The encoding carries
/// no domain tag; uses are separated by their position in the enclosing hash.
#[inline(always)]
pub(crate) fn address_field(value: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    hash_bytes(value).map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
