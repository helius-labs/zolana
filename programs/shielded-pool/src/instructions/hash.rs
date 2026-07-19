use pinocchio::error::ProgramError;
use zolana_hasher::primitives::{hash_field, right_align};
use zolana_interface::error::ShieldedPoolError;

/// Encodes a u64 as a big-endian BN254 field element (value in the low 8 bytes).
#[inline(always)]
pub(crate) fn field_from_u64(value: u64) -> [u8; 32] {
    right_align(&value.to_be_bytes())
}

/// `pk_field` of a Solana / Ed25519 pubkey (spec: Shielded Address):
/// Poseidon over the two 128-bit big-endian limbs.
#[inline(always)]
pub(crate) fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    hash_field(pubkey).map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
