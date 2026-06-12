use light_hasher::{Hasher, Poseidon};
use pinocchio::error::ProgramError;

use crate::error::ShieldedPoolError;

/// Encodes a u64 as a big-endian BN254 field element (value in the low 8 bytes).
pub(crate) fn field_from_u64(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}


/// Encodes 16 big-endian bytes as a field element (value in the low 16 bytes).
fn field_from_u128_be(value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(value);
    out
}

/// `pk_field` of a Solana / Ed25519 pubkey (spec: Shielded Address):
/// Poseidon over the two 128-bit big-endian limbs.
pub(crate) fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let pk_low = field_from_u128_be(&pubkey[16..]);
    let pk_high = field_from_u128_be(&pubkey[..16]);
    Poseidon::hashv(&[pk_low.as_slice(), pk_high.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
