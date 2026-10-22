//! Prover error adapters for the shared X25519 encryption and hash gadgets.

use crate::{crypto, prover::error::SquadsProverError};

pub(crate) use crypto::pack33;

/// `Pack33To2FECircuit` low/high limbs of a compressed key (re-export wrapper).
pub(crate) fn ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::ciphertext_hash(ciphertext)?)
}

pub(crate) fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::hash_field(value)?)
}

pub(crate) fn hash_chain(items: &[[u8; 32]]) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::hash_chain(items)?)
}

pub(crate) fn ecdh_encrypt(
    dh: &[u8; 32],
    eph_pk_comp: &[u8; 33],
    recipient_pk_comp: &[u8; 33],
    plaintext: &[u8],
    encryption_context: &[u8],
) -> Result<Vec<u8>, SquadsProverError> {
    Ok(crypto::ecdh_encrypt(
        dh,
        eph_pk_comp,
        recipient_pk_comp,
        plaintext,
        encryption_context,
    )?)
}
