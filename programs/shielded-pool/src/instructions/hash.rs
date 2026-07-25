use pinocchio::error::ProgramError;
use zolana_hasher::{Hasher, Poseidon};
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

/// Encodes 16 big-endian bytes as a field element (value in the low 16 bytes).
#[inline(always)]
fn field_from_u128_be(value: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(value);
    out
}

/// `pk_field` of a Solana / Ed25519 pubkey (spec: Shielded Address):
/// Poseidon over the two 128-bit big-endian limbs.
#[inline(always)]
pub(crate) fn solana_pk_hash(pubkey: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let pk_low = field_from_u128_be(&pubkey[16..]);
    let pk_high = field_from_u128_be(&pubkey[..16]);
    Poseidon::hashv(&[pk_low.as_slice(), pk_high.as_slice()])
        .map_err(|_| ShieldedPoolError::TransactProofVerificationFailed.into())
}
