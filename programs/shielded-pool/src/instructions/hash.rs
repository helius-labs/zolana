use light_hasher::{Hasher, Poseidon};
use pinocchio::error::ProgramError;

use crate::error::ShieldedPoolError;

pub(crate) const EMPTY_FIELD: [u8; 32] = [0u8; 32];

/// Encodes a u64 as a big-endian BN254 field element (value in the low 8 bytes).
pub(crate) fn field_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

pub(crate) fn hash_chain(
    values: &[[u8; 32]],
    error: ShieldedPoolError,
) -> Result<[u8; 32], ProgramError> {
    if values.is_empty() {
        return Ok(EMPTY_FIELD);
    }

    let mut hash = values[0];
    for value in &values[1..] {
        hash = Poseidon::hashv(&[hash.as_slice(), value.as_slice()]).map_err(|_| error)?;
    }
    Ok(hash)
}
