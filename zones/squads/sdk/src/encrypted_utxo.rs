//! Wallet-facing zone encrypted-UTXO ciphertexts (sender change + recipient
//! output), reusing the proven AES-256-CTR zone crypto.
//!
//! Formats (sources of truth):
//! - Sender change ciphertext: 40 bytes = `amount(8) || asset(32)`, AES-CTR with
//!   `tx_viewing_sk` used directly as the shared secret
//!   (`prover/server/circuits/squads/zone/sender.go:25,92,108-113`).
//! - Recipient ciphertext: 71 bytes = `amount(8) || asset(32) || blinding(31)`,
//!   AES-CTR keyed by `DeriveSharedSecret(dh, tx_viewing_pk, recipient_pk)`
//!   (`recipient.go:18,59-66,71-77`).
//!
//! Neither ciphertext carries a tag; in production integrity comes from the zone
//! proof's Poseidon ciphertext hash. These helpers cover the construction and
//! wallet-side decryption only.
//!
//! AES-CTR is its own inverse, so decryption reuses the same key schedule. The
//! recipient decrypt path therefore recomputes the SAME shared secret from the
//! recipient's view: `DeriveSharedSecret(ECDH(recipient_sk, tx_viewing_pk),
//! tx_viewing_pk, recipient_pk)` equals the sender's
//! `DeriveSharedSecret(ECDH(tx_viewing_sk, recipient_pk), tx_viewing_pk,
//! recipient_pk)` because both ECDH halves share the same x-coordinate.

use p256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, PublicKey, Scalar, SecretKey};
use zolana_keypair::P256Pubkey;

use crate::crypto::{self, CryptoError};

/// Sender change ciphertext length (`amount(8) || asset(32)`).
pub const SENDER_CIPHERTEXT_LEN: usize = 8 + 32;
/// Recipient ciphertext length (`amount(8) || asset(32) || blinding(31)`).
pub const RECIPIENT_CIPHERTEXT_LEN: usize = 8 + 32 + 31;

/// Errors for the encrypted-UTXO path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedUtxoError {
    /// Underlying crypto-gadget failure.
    Crypto(CryptoError),
    /// A P-256 public key was not valid SEC1 / not on the curve.
    InvalidPubkey,
    /// A ciphertext was not the expected fixed length.
    BadLength,
}

impl core::fmt::Display for EncryptedUtxoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::InvalidPubkey => write!(f, "invalid P-256 public key"),
            Self::BadLength => write!(f, "bad ciphertext length"),
        }
    }
}

impl std::error::Error for EncryptedUtxoError {}

impl From<CryptoError> for EncryptedUtxoError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// ECDH x-coordinate of `scalar · recipient_pub`.
fn ecdh_x(scalar: &Scalar, recipient: &PublicKey) -> Result<[u8; 32], EncryptedUtxoError> {
    let point = ProjectivePoint::from(recipient.as_affine()) * scalar;
    let encoded = point.to_affine().to_encoded_point(false);
    let x = encoded.x().ok_or(EncryptedUtxoError::InvalidPubkey)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x.as_slice());
    Ok(out)
}

// ---- sender change (40 bytes) ---------------------------------------------

/// AES-CTR the sender change plaintext (`amount(8) || asset(32)`) under a key/nonce
/// derived directly from `tx_viewing_sk` (it IS the shared secret; sender.go:92).
/// CTR is symmetric, so the same routine encrypts and decrypts.
fn sender_apply(tx_viewing_sk: &[u8; 32], buf: &mut [u8]) -> Result<(), EncryptedUtxoError> {
    let (key, nonce) = crypto::key_schedule(tx_viewing_sk)?;
    crypto::ctr_apply(&key, &nonce, buf);
    Ok(())
}

/// Encrypt the sender change UTXO fields into the 40-byte sender ciphertext.
pub fn encrypt_sender_ciphertext(
    tx_viewing_sk: &[u8; 32],
    amount: u64,
    asset: &[u8; 32],
) -> Result<[u8; SENDER_CIPHERTEXT_LEN], EncryptedUtxoError> {
    let mut buf = [0u8; SENDER_CIPHERTEXT_LEN];
    buf[0..8].copy_from_slice(&amount.to_be_bytes());
    buf[8..SENDER_CIPHERTEXT_LEN].copy_from_slice(asset);
    sender_apply(tx_viewing_sk, &mut buf)?;
    Ok(buf)
}

/// Decrypt a 40-byte sender ciphertext, returning `(amount, asset)`.
pub fn decrypt_sender_ciphertext(
    tx_viewing_sk: &[u8; 32],
    ciphertext: &[u8; SENDER_CIPHERTEXT_LEN],
) -> Result<(u64, [u8; 32]), EncryptedUtxoError> {
    let mut buf = *ciphertext;
    sender_apply(tx_viewing_sk, &mut buf)?;
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&buf[0..8]);
    let mut asset = [0u8; 32];
    asset.copy_from_slice(&buf[8..SENDER_CIPHERTEXT_LEN]);
    Ok((u64::from_be_bytes(amount_bytes), asset))
}

// ---- recipient output (71 bytes) ------------------------------------------

/// Derive the recipient AES-CTR key/nonce from the ECDH x-coordinate `dh`, the
/// compressed ephemeral `tx_viewing_pk`, and the recipient's compressed pubkey
/// (recipient.go:61-62).
fn recipient_apply(
    dh: &[u8; 32],
    tx_viewing_pk: &[u8; 33],
    recipient_pk: &[u8; 33],
    buf: &mut [u8],
) -> Result<(), EncryptedUtxoError> {
    let shared = crypto::derive_shared_secret(dh, tx_viewing_pk, recipient_pk)?;
    let (key, nonce) = crypto::key_schedule(&shared)?;
    crypto::ctr_apply(&key, &nonce, buf);
    Ok(())
}

/// Encrypt the recipient output UTXO fields into the 71-byte recipient ciphertext.
///
/// The sender holds `tx_viewing_sk` (the ephemeral scalar) and the recipient's
/// public viewing key. `tx_viewing_pk` is the compressed `tx_viewing_sk · G`.
pub fn encrypt_recipient_ciphertext(
    tx_viewing_sk: &SecretKey,
    recipient_pk: &P256Pubkey,
    amount: u64,
    asset: &[u8; 32],
    blinding: &[u8; 31],
) -> Result<[u8; RECIPIENT_CIPHERTEXT_LEN], EncryptedUtxoError> {
    let tx_viewing_pk = *P256Pubkey::from_p256(&tx_viewing_sk.public_key()).as_bytes();
    let recipient = recipient_pk
        .to_p256()
        .map_err(|_| EncryptedUtxoError::InvalidPubkey)?;
    let recipient_comp = *recipient_pk.as_bytes();

    let scalar = *tx_viewing_sk.to_nonzero_scalar();
    let dh = ecdh_x(&scalar, &recipient)?;

    let mut buf = [0u8; RECIPIENT_CIPHERTEXT_LEN];
    buf[0..8].copy_from_slice(&amount.to_be_bytes());
    buf[8..40].copy_from_slice(asset);
    buf[40..RECIPIENT_CIPHERTEXT_LEN].copy_from_slice(blinding);
    recipient_apply(&dh, &tx_viewing_pk, &recipient_comp, &mut buf)?;
    Ok(buf)
}

/// Decrypt a 71-byte recipient ciphertext with the recipient's viewing secret key
/// and the published `tx_viewing_pk`, returning `(amount, asset, blinding)`.
pub fn decrypt_recipient_ciphertext(
    recipient_sk: &SecretKey,
    tx_viewing_pk: &P256Pubkey,
    ciphertext: &[u8; RECIPIENT_CIPHERTEXT_LEN],
) -> Result<(u64, [u8; 32], [u8; 31]), EncryptedUtxoError> {
    let tx_viewing_comp = *tx_viewing_pk.as_bytes();
    let recipient_comp = *P256Pubkey::from_p256(&recipient_sk.public_key()).as_bytes();

    // dh = ECDH(recipient_sk, tx_viewing_pk): same x-coordinate the sender used.
    let tx_pub = tx_viewing_pk
        .to_p256()
        .map_err(|_| EncryptedUtxoError::InvalidPubkey)?;
    let scalar = *recipient_sk.to_nonzero_scalar();
    let dh = ecdh_x(&scalar, &tx_pub)?;

    let mut buf = *ciphertext;
    recipient_apply(&dh, &tx_viewing_comp, &recipient_comp, &mut buf)?;

    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&buf[0..8]);
    let mut asset = [0u8; 32];
    asset.copy_from_slice(&buf[8..40]);
    let mut blinding = [0u8; 31];
    blinding.copy_from_slice(&buf[40..RECIPIENT_CIPHERTEXT_LEN]);
    Ok((u64::from_be_bytes(amount_bytes), asset, blinding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn sender_ciphertext_round_trips() {
        let tx_viewing_sk = [11u8; 32];
        let amount = 987_654_321u64;
        let asset = [4u8; 32];

        let ct = encrypt_sender_ciphertext(&tx_viewing_sk, amount, &asset).unwrap();
        assert_eq!(ct.len(), SENDER_CIPHERTEXT_LEN);

        let (got_amount, got_asset) = decrypt_sender_ciphertext(&tx_viewing_sk, &ct).unwrap();
        assert_eq!(got_amount, amount);
        assert_eq!(got_asset, asset);
    }

    #[test]
    fn recipient_ciphertext_round_trips() {
        let tx_viewing_sk = SecretKey::random(&mut OsRng);
        let recipient_sk = SecretKey::random(&mut OsRng);
        let recipient_pk = P256Pubkey::from_p256(&recipient_sk.public_key());
        let tx_viewing_pk = P256Pubkey::from_p256(&tx_viewing_sk.public_key());

        let amount = 555u64;
        let asset = [6u8; 32];
        let blinding = [8u8; 31];

        let ct =
            encrypt_recipient_ciphertext(&tx_viewing_sk, &recipient_pk, amount, &asset, &blinding)
                .unwrap();
        assert_eq!(ct.len(), RECIPIENT_CIPHERTEXT_LEN);

        let (got_amount, got_asset, got_blinding) =
            decrypt_recipient_ciphertext(&recipient_sk, &tx_viewing_pk, &ct).unwrap();
        assert_eq!(got_amount, amount);
        assert_eq!(got_asset, asset);
        assert_eq!(got_blinding, blinding);
    }

    #[test]
    fn recipient_decrypt_with_wrong_key_recovers_garbage() {
        // CTR has no tag, so a wrong key yields different (garbage) plaintext
        // rather than an error. Assert it does not recover the inputs.
        let tx_viewing_sk = SecretKey::random(&mut OsRng);
        let recipient_sk = SecretKey::random(&mut OsRng);
        let recipient_pk = P256Pubkey::from_p256(&recipient_sk.public_key());
        let tx_viewing_pk = P256Pubkey::from_p256(&tx_viewing_sk.public_key());
        let wrong_sk = SecretKey::random(&mut OsRng);

        let ct =
            encrypt_recipient_ciphertext(&tx_viewing_sk, &recipient_pk, 42, &[1u8; 32], &[2u8; 31])
                .unwrap();
        let (amount, asset, blinding) =
            decrypt_recipient_ciphertext(&wrong_sk, &tx_viewing_pk, &ct).unwrap();
        assert!(amount != 42 || asset != [1u8; 32] || blinding != [2u8; 31]);
    }
}
