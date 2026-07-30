use pinocchio::error::ProgramError;
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::{error::ShieldedPoolError, UTXO_DOMAIN};

/// Encodes a u64 as a big-endian BN254 field element (value in the low 8 bytes).
#[inline(always)]
pub(crate) const fn field_from_u64(value: u64) -> [u8; 32] {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = value.to_be_bytes();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b0, b1, b2, b3, b4,
        b5, b6, b7,
    ]
}

/// The UTXO-hash domain separator as a field element, evaluated at compile time.
pub(crate) const UTXO_DOMAIN_FIELD: [u8; 32] = field_from_u64(UTXO_DOMAIN as u64);

/// Fixed-length proof-input hash of a Solana address or owner tag.
#[inline(always)]
pub fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    hash_bytes(pubkey).map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
