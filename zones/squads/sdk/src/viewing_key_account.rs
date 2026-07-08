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

use p256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, Scalar, SecretKey};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::types::{EncryptedNullifierSecret, SharedKeyCiphertext};

use crate::crypto::{self, CryptoError};

/// Errors for the viewing-key-account decrypt path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewingKeyAccountError {
    /// Underlying crypto-gadget failure.
    Crypto(CryptoError),
    /// A P-256 public key was not valid SEC1 / not on the curve.
    InvalidPubkey,
    /// A recovered plaintext was not the expected length.
    BadLength,
}

impl core::fmt::Display for ViewingKeyAccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::InvalidPubkey => write!(f, "invalid P-256 public key"),
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

/// ECDH x-coordinate of `scalar · counterparty`.
fn ecdh_x(scalar: &Scalar, counterparty: &PublicKey) -> Result<[u8; 32], ViewingKeyAccountError> {
    let point = ProjectivePoint::from(counterparty.as_affine()) * scalar;
    let encoded = point.to_affine().to_encoded_point(false);
    let x = encoded.x().ok_or(ViewingKeyAccountError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x.as_slice());
    Ok(out)
}

/// Recover the 32-byte shared viewing private key from one recovery/auditor
/// `SharedKeyCiphertext`, using the recipient (recovery/auditor) secret key and
/// the account's shared `key_ciphertext_ephemeral`.
///
/// Inverts `key_encryption.rs`'s `ecdh_encrypt(ECDH(ephemeral_sk, recipient_pk),
/// ephemeral, recipient, viewing_sk_be)`.
pub fn recover_shared_secret(
    recipient_sk: &SecretKey,
    ephemeral_pk: &P256Pubkey,
    shared_key_ciphertext: &SharedKeyCiphertext,
) -> Result<[u8; 32], ViewingKeyAccountError> {
    let ephemeral_comp = *ephemeral_pk.as_bytes();
    let recipient_comp = *P256Pubkey::from_p256(&recipient_sk.public_key()).as_bytes();

    let ephemeral_pub = ephemeral_pk
        .to_p256()
        .map_err(|_| ViewingKeyAccountError::InvalidPubkey)?;
    let scalar = *recipient_sk.to_nonzero_scalar();
    let dh = ecdh_x(&scalar, &ephemeral_pub)?;

    let plaintext =
        crypto::ecdh_decrypt(&dh, &ephemeral_comp, &recipient_comp, shared_key_ciphertext)?;
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
    shared_viewing_sk: &SecretKey,
    ephemeral_pk: &P256Pubkey,
    encrypted_nullifier_secret: &EncryptedNullifierSecret,
) -> Result<[u8; 31], ViewingKeyAccountError> {
    let ephemeral_comp = *ephemeral_pk.as_bytes();
    let shared_viewing_comp = *P256Pubkey::from_p256(&shared_viewing_sk.public_key()).as_bytes();

    let ephemeral_pub = ephemeral_pk
        .to_p256()
        .map_err(|_| ViewingKeyAccountError::InvalidPubkey)?;
    let scalar = *shared_viewing_sk.to_nonzero_scalar();
    let dh = ecdh_x(&scalar, &ephemeral_pub)?;

    let plaintext = crypto::ecdh_decrypt(
        &dh,
        &ephemeral_comp,
        &shared_viewing_comp,
        encrypted_nullifier_secret,
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
    use p256::elliptic_curve::rand_core::OsRng;

    // Re-implement the prover's encrypt side locally (it is `prover`-gated) so the
    // round-trip test runs under default features.
    fn encrypt_to(
        ephemeral_sk: &SecretKey,
        recipient_pk: &P256Pubkey,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let ephemeral_comp = *P256Pubkey::from_p256(&ephemeral_sk.public_key()).as_bytes();
        let recipient_comp = *recipient_pk.as_bytes();
        let recipient = recipient_pk.to_p256().unwrap();
        let scalar = *ephemeral_sk.to_nonzero_scalar();
        let dh = ecdh_x(&scalar, &recipient).unwrap();
        crypto::ecdh_encrypt(&dh, &ephemeral_comp, &recipient_comp, plaintext).unwrap()
    }

    #[test]
    fn shared_secret_round_trips() {
        let ephemeral_sk = SecretKey::random(&mut OsRng);
        let ephemeral_pk = P256Pubkey::from_p256(&ephemeral_sk.public_key());
        let recovery_sk = SecretKey::random(&mut OsRng);
        let recovery_pk = P256Pubkey::from_p256(&recovery_sk.public_key());

        // The plaintext encrypted to each recovery key is the 32-byte big-endian
        // shared viewing scalar.
        let viewing_sk = SecretKey::random(&mut OsRng);
        let mut viewing_sk_be = [0u8; 32];
        viewing_sk_be.copy_from_slice(viewing_sk.to_bytes().as_slice());

        let ct = encrypt_to(&ephemeral_sk, &recovery_pk, &viewing_sk_be);
        assert_eq!(ct.len(), 32);
        let ct_arr: SharedKeyCiphertext = ct.as_slice().try_into().unwrap();

        let recovered = recover_shared_secret(&recovery_sk, &ephemeral_pk, &ct_arr).unwrap();
        assert_eq!(recovered, viewing_sk_be);
    }

    #[test]
    fn nullifier_secret_round_trips() {
        let ephemeral_sk = SecretKey::random(&mut OsRng);
        let ephemeral_pk = P256Pubkey::from_p256(&ephemeral_sk.public_key());

        // The nullifier secret is encrypted to the shared viewing key sk·G.
        let viewing_sk = SecretKey::random(&mut OsRng);
        let viewing_pk = P256Pubkey::from_p256(&viewing_sk.public_key());

        // 31-byte nullifier secret (the low 31 bytes of a 32-byte BN254 element).
        let null_secret_31 = [13u8; 31];

        let ct = encrypt_to(&ephemeral_sk, &viewing_pk, &null_secret_31);
        assert_eq!(ct.len(), 31);
        let ct_arr: EncryptedNullifierSecret = ct.as_slice().try_into().unwrap();

        let recovered = recover_nullifier_secret(&viewing_sk, &ephemeral_pk, &ct_arr).unwrap();
        assert_eq!(recovered, null_secret_31);
    }
}
