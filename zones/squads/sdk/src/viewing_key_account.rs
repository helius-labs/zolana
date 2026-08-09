//! Wallet-facing decrypt side of the viewing key account ciphertexts. The
//! encrypt side lives in `sdk/src/prover/key_encryption.rs`.
//!
//! One shared `key_ciphertext_ephemeral` covers every ciphertext in an account.
//! The 32-byte shared viewing private key is AES-CTR encrypted to each
//! recovery/auditor key with `dh = ECDH(ephemeral_sk, recipient_pk)`. The
//! 31-byte nullifier secret is encrypted to the shared viewing key `sk·G`.
//!
//! AES-CTR carries no integrity tag. Integrity comes from the key-encryption
//! proof's Poseidon ciphertext hash, so decryption with a wrong key yields
//! garbage without an error. The caller must validate the recovered secret
//! against the published `shared_viewing_key_commitment` / `nullifier_pubkey`.

use p256::SecretKey;
use thiserror::Error;
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::types::{EncryptedNullifierSecret, SharedKeyCiphertext};

use crate::crypto::{self, ecdh_x, CryptoError};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ViewingKeyAccountError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid P-256 public key")]
    InvalidPubkey,
    #[error("bad plaintext length")]
    BadLength,
}

/// Recover the 32-byte shared viewing private key from one recovery/auditor
/// `SharedKeyCiphertext`, using the recipient (recovery/auditor) secret key and
/// the account's shared `key_ciphertext_ephemeral`.
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

        let viewing_sk = SecretKey::random(&mut OsRng);
        let viewing_pk = P256Pubkey::from_p256(&viewing_sk.public_key());

        // 31 bytes always fit under the BN254 modulus.
        let null_secret_31 = [13u8; 31];

        let ct = encrypt_to(&ephemeral_sk, &viewing_pk, &null_secret_31);
        assert_eq!(ct.len(), 31);
        let ct_arr: EncryptedNullifierSecret = ct.as_slice().try_into().unwrap();

        let recovered = recover_nullifier_secret(&viewing_sk, &ephemeral_pk, &ct_arr).unwrap();
        assert_eq!(recovered, null_secret_31);
    }
}
