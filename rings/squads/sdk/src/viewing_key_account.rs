//! Wallet-facing decrypt side of the viewing key account ciphertexts.
//!
//! The encrypt side lives in `sdk/src/prover/key_encryption.rs`: one shared
//! `key_ciphertext_ephemeral` covers every ciphertext in an account. For each
//! recovery/auditor key the 32-byte shared viewing private key is AES-CTR
//! encrypted via `ecdh_encrypt(dh, ephemeral, recipient)` where `dh =
//! ECDH(ephemeral_sk, recipient_pk)` (`key_encryption.rs:153-163`); the 31-byte
//! nullifier secret is encrypted to the shared viewing key `sk·G`
//! (`key_encryption.rs:169-180`). Integrity comes from the key-encryption proof's
//! Poseidon ciphertext hash, not a tag, so these decryptions never fail on a wrong
//! key -- they yield garbage. The caller validates the recovered secret against
//! the published `shared_viewing_key_commitment` / `nullifier_pubkey`.
//!
//! AES-CTR is symmetric, so recovery reuses the same key schedule. A recipient
//! holding `recipient_sk` recomputes the SAME `dh` x-coordinate the sender used,
//! because `ECDH(recipient_sk, ephemeral_pk)` and `ECDH(ephemeral_sk,
//! recipient_pk)` share the shared point's x-coordinate.

use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_squads_interface::types::{EncryptedNullifierSecret, SharedKeyCiphertext};

use crate::crypto::{self, CryptoError};

/// Errors for the viewing-key-account decrypt path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewingKeyAccountError {
    /// Underlying crypto-gadget failure.
    Crypto(CryptoError),
    /// A X25519 public key was not canonical or was noncontributory.
    InvalidPubkey,
    /// A recovered plaintext was not the expected length.
    BadLength,
}

impl core::fmt::Display for ViewingKeyAccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::InvalidPubkey => write!(f, "invalid X25519 public key"),
            Self::BadLength => write!(f, "bad plaintext length"),
        }
    }
}

impl std::error::Error for ViewingKeyAccountError {}

impl From<CryptoError> for ViewingKeyAccountError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Recover the 32-byte shared viewing private key from one recovery/auditor
/// `SharedKeyCiphertext`, using the recipient (recovery/auditor) secret key and
/// the account's shared `key_ciphertext_ephemeral`.
///
/// Inverts `key_encryption.rs`'s `ecdh_encrypt(ECDH(ephemeral_sk, recipient_pk),
/// ephemeral, recipient, viewing_secret_bytes)`.
pub fn recover_shared_secret(
    recipient_sk: &X25519Keypair,
    ephemeral_pk: &X25519Pubkey,
    shared_key_ciphertext: &SharedKeyCiphertext,
) -> Result<[u8; 32], ViewingKeyAccountError> {
    let ephemeral_comp = *ephemeral_pk.as_bytes();
    let recipient_comp = *recipient_sk.pubkey().as_bytes();

    let dh = recipient_sk
        .ecdh(ephemeral_pk)
        .map_err(|_| ViewingKeyAccountError::InvalidPubkey)?;

    let plaintext = crypto::ecdh_decrypt(
        &dh,
        &ephemeral_comp,
        &recipient_comp,
        shared_key_ciphertext,
        crypto::SHARED_KEY_INFO,
    )?;
    let mut out = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(ViewingKeyAccountError::BadLength);
    }
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// Recover the 31-byte nullifier secret from `encrypted_nullifier_secret`.
///
/// The encrypt side keys this with the shared viewing key itself: `dh =
/// ECDH(ephemeral_sk, shared_viewing_pk)` and the recipient pubkey is the shared
/// viewing key (`key_encryption.rs:169-180`). The holder of `shared_viewing_sk`
/// recomputes the same `dh` as `ECDH(shared_viewing_sk, ephemeral_pk)`.
pub fn recover_nullifier_secret(
    shared_viewing_sk: &X25519Keypair,
    ephemeral_pk: &X25519Pubkey,
    encrypted_nullifier_secret: &EncryptedNullifierSecret,
) -> Result<[u8; 31], ViewingKeyAccountError> {
    let ephemeral_comp = *ephemeral_pk.as_bytes();
    let shared_viewing_comp = *shared_viewing_sk.pubkey().as_bytes();

    let dh = shared_viewing_sk
        .ecdh(ephemeral_pk)
        .map_err(|_| ViewingKeyAccountError::InvalidPubkey)?;

    let plaintext = crypto::ecdh_decrypt(
        &dh,
        &ephemeral_comp,
        &shared_viewing_comp,
        encrypted_nullifier_secret,
        crypto::NULLIFIER_INFO,
    )?;
    let mut out = [0u8; 31];
    if plaintext.len() != 31 {
        return Err(ViewingKeyAccountError::BadLength);
    }
    out.copy_from_slice(&plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Re-implement the prover's encrypt side locally (it is `prover`-gated) so the
    // round-trip test runs under default features.
    fn encrypt_to(
        ephemeral_sk: &X25519Keypair,
        recipient_pk: &X25519Pubkey,
        plaintext: &[u8],
        encryption_context: &[u8],
    ) -> Vec<u8> {
        let ephemeral_comp = *ephemeral_sk.pubkey().as_bytes();
        let recipient_comp = *recipient_pk.as_bytes();
        let dh = ephemeral_sk.ecdh(recipient_pk).unwrap();
        crypto::ecdh_encrypt(
            &dh,
            &ephemeral_comp,
            &recipient_comp,
            plaintext,
            encryption_context,
        )
        .unwrap()
    }

    #[test]
    fn shared_secret_round_trips() {
        let ephemeral_sk = X25519Keypair::new();
        let ephemeral_pk = ephemeral_sk.pubkey();
        let recovery_sk = X25519Keypair::new();
        let recovery_pk = recovery_sk.pubkey();

        // The plaintext encrypted to each recovery key is the 32-byte big-endian
        // shared viewing secret.
        let viewing_sk = X25519Keypair::new();
        let mut viewing_secret_bytes = [0u8; 32];
        viewing_secret_bytes.copy_from_slice(viewing_sk.secret_bytes().as_slice());

        let ct = encrypt_to(
            &ephemeral_sk,
            &recovery_pk,
            &viewing_secret_bytes,
            crypto::SHARED_KEY_INFO,
        );
        assert_eq!(ct.len(), 32);
        let ct_arr: SharedKeyCiphertext = ct.as_slice().try_into().unwrap();

        let recovered = recover_shared_secret(&recovery_sk, &ephemeral_pk, &ct_arr).unwrap();
        assert_eq!(recovered, viewing_secret_bytes);
    }

    #[test]
    fn nullifier_secret_round_trips() {
        let ephemeral_sk = X25519Keypair::new();
        let ephemeral_pk = ephemeral_sk.pubkey();

        // The nullifier secret is encrypted to the shared viewing key sk·G.
        let viewing_sk = X25519Keypair::new();
        let viewing_pk = viewing_sk.pubkey();

        // 31-byte nullifier secret (the low 31 bytes of a 32-byte BN254 element).
        let null_secret_31 = [13u8; 31];

        let ct = encrypt_to(
            &ephemeral_sk,
            &viewing_pk,
            &null_secret_31,
            crypto::NULLIFIER_INFO,
        );
        assert_eq!(ct.len(), 31);
        let ct_arr: EncryptedNullifierSecret = ct.as_slice().try_into().unwrap();

        let recovered = recover_nullifier_secret(&viewing_sk, &ephemeral_pk, &ct_arr).unwrap();
        assert_eq!(recovered, null_secret_31);
    }
}
