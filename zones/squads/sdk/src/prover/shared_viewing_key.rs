//! Host side of the squads key-encryption verifiable-encryption scheme.
//!
//! The pure-crypto gadgets now live in the always-available [`crate::crypto`]
//! module (so the wallet-facing construction/decryption modules can reuse them
//! without the `prover` feature). This module re-exports them under their former
//! names and signatures, mapping [`crate::crypto::CryptoError`] to
//! [`SquadsProverError`], so the proven path is unchanged.
//!
//! See [`crate::crypto`] for the byte-for-byte circuit correspondence: P-256
//! ECDH, a Poseidon key schedule with the `CT_*` domain separators and EMPTY
//! info, and AES-256-CTR (J0 = nonce || 2).

use p256::SecretKey;

use crate::{crypto, prover::error::SquadsProverError};

/// CTR nonce length (12 bytes).
pub(crate) const NONCE_LEN: usize = crypto::NONCE_LEN;

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
) -> Result<Vec<u8>, SquadsProverError> {
    Ok(crypto::ecdh_encrypt(
        dh,
        eph_pk_comp,
        recipient_pk_comp,
        plaintext,
    )?)
}

pub(crate) fn secret_key_from_be(scalar_be: &[u8; 32]) -> Result<SecretKey, SquadsProverError> {
    Ok(crypto::secret_key_from_be(scalar_be)?)
}

/// `KeySchedule` (poseidon_kdf.go:196) with empty info: AES-256 key + 12-byte
/// nonce from a shared secret. Public wrapper for the zone-proof builder.
pub(crate) fn key_schedule_pub(
    shared_secret: &[u8; 32],
) -> Result<([u8; 32], [u8; NONCE_LEN]), SquadsProverError> {
    Ok(crypto::key_schedule(shared_secret)?)
}

/// `DeriveSharedSecret` (poseidon_kdf.go:252). Public wrapper for the zone builder.
pub(crate) fn derive_shared_secret_pub(
    dh: &[u8; 32],
    eph_comp: &[u8; 33],
    rpk_comp: &[u8; 33],
) -> Result<[u8; 32], SquadsProverError> {
    Ok(crypto::derive_shared_secret(dh, eph_comp, rpk_comp)?)
}

/// AES-256-CTR in place (J0 = nonce || 2). Public wrapper for the zone builder.
pub(crate) fn ctr_apply_pub(key: &[u8; 32], nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    crypto::ctr_apply(key, nonce, buf)
}
