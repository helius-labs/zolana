//! Wallet-facing proposal ciphertext construction/decryption and the
//! `proposal_hash` commitment.
//!
//! Formats (sources of truth):
//! - `ProposalCiphertext` is 88 bytes: 33-byte ephemeral tagged X25519 key +
//!   39-byte AES-GCM body (8-byte amount || 31-byte blinding) + 16-byte tag.
//!   (`docs/squads_policy_program.md:84`, `interface::constants::PROPOSAL_CIPHERTEXT_LEN`.)
//! - `proposal_hash = Poseidon(amount, recipient, blinding, public_amount)` over
//!   field elements (`rings/squads/prover/circuits/ring/proposal.go:17-24`),
//!   matching the ring witness builder's `RingProposal` field encoding
//!   (`sdk/src/prover/ring.rs:566-569`).
//!
//! Unlike the AES-CTR ring ciphertexts (whose integrity comes from the proof's
//! Poseidon ciphertext hash), the proposal ciphertext is NOT proven by any
//! circuit, so it carries a real GCM authentication tag. The AES-256-GCM key and
//! 96-bit nonce are derived from the ECDH shared secret with the same proven
//! Poseidon key schedule the ring uses ([`crate::crypto::derive_shared_secret`] +
//! [`crate::crypto::key_schedule`]), so no extra KDF dependency is introduced.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::{X25519Keypair, X25519Pubkey};
use zolana_squads_interface::{constants::PROPOSAL_CIPHERTEXT_LEN, types::ProposalCiphertext};

use crate::crypto::{self, CryptoError};

/// 33-byte ephemeral key prefix length within the proposal ciphertext.
const EPHEMERAL_LEN: usize = 33;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;
/// Plaintext: 8-byte amount (big-endian u64) || 31-byte blinding.
const PLAINTEXT_LEN: usize = 8 + 31;

/// Errors for the proposal ciphertext path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalError {
    /// Underlying crypto-gadget failure.
    Crypto(CryptoError),
    /// A X25519 public key was not canonical or was noncontributory.
    InvalidPubkey,
    /// AES-GCM authenticated encryption/decryption failed (wrong key or tampered
    /// ciphertext).
    Aead,
    /// The ciphertext was not the expected fixed length, or the recovered
    /// plaintext was not 39 bytes.
    BadLength,
}

impl core::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::InvalidPubkey => write!(f, "invalid X25519 public key"),
            Self::Aead => write!(f, "AES-GCM authentication failed"),
            Self::BadLength => write!(f, "bad ciphertext or plaintext length"),
        }
    }
}

impl std::error::Error for ProposalError {}

impl From<CryptoError> for ProposalError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Derive the AES-256-GCM key and 96-bit nonce from the ECDH shared secret and the
/// bound ephemeral/recipient compressed keys, using the proven Poseidon schedule.
fn proposal_keys(
    dh: &[u8; 32],
    eph_comp: &[u8; 33],
    recipient_comp: &[u8; 33],
) -> Result<([u8; 32], [u8; crypto::NONCE_LEN]), ProposalError> {
    let shared = crypto::derive_shared_secret(dh, eph_comp, recipient_comp)?;
    Ok(crypto::key_schedule(&shared)?)
}

/// Build a proposal ciphertext: a fresh ephemeral X25519 key, ECDH to the shared
/// viewing key, then AES-256-GCM over `amount(8) || blinding(31)`.
///
/// `ephemeral_secret` is a fresh raw RFC 7748 secret. Its tagged public key
/// prefixes the ciphertext and supplies the proposal PDA seed.
pub fn build_proposal_ciphertext(
    amount: u64,
    blinding: &[u8; 31],
    shared_viewing_pk: &X25519Pubkey,
    ephemeral_secret: &[u8; 32],
) -> Result<ProposalCiphertext, ProposalError> {
    let ephemeral_key = X25519Keypair::from_bytes(ephemeral_secret);
    let eph_comp = *ephemeral_key.pubkey().as_bytes();
    let recipient_comp = *shared_viewing_pk.as_bytes();
    let dh = ephemeral_key
        .ecdh(shared_viewing_pk)
        .map_err(|_| ProposalError::InvalidPubkey)?;
    let (key, nonce) = proposal_keys(&dh, &eph_comp, &recipient_comp)?;

    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[0..8].copy_from_slice(&amount.to_be_bytes());
    plaintext[8..PLAINTEXT_LEN].copy_from_slice(blinding);

    let cipher = Aes256Gcm::new((&key).into());
    let body = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &eph_comp,
            },
        )
        .map_err(|_| ProposalError::Aead)?;
    // 39 plaintext + 16 tag.
    if body.len() != PLAINTEXT_LEN + TAG_LEN {
        return Err(ProposalError::BadLength);
    }

    let mut out = [0u8; PROPOSAL_CIPHERTEXT_LEN];
    out[0..EPHEMERAL_LEN].copy_from_slice(&eph_comp);
    out[EPHEMERAL_LEN..].copy_from_slice(&body);
    Ok(out)
}

/// Decrypt a proposal ciphertext with the shared viewing secret key, returning
/// `(amount, blinding)`.
pub fn decrypt_proposal_ciphertext(
    ct: &ProposalCiphertext,
    shared_viewing_sk: &X25519Keypair,
) -> Result<(u64, [u8; 31]), ProposalError> {
    let mut eph_comp = [0u8; 33];
    eph_comp.copy_from_slice(&ct[0..EPHEMERAL_LEN]);
    let body = &ct[EPHEMERAL_LEN..];

    let eph_pub = X25519Pubkey::from_bytes(eph_comp).map_err(|_| ProposalError::InvalidPubkey)?;
    let recipient_comp = *shared_viewing_sk.pubkey().as_bytes();
    let dh = shared_viewing_sk
        .ecdh(&eph_pub)
        .map_err(|_| ProposalError::InvalidPubkey)?;
    let (key, nonce) = proposal_keys(&dh, &eph_comp, &recipient_comp)?;

    let cipher = Aes256Gcm::new((&key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &eph_comp,
            },
        )
        .map_err(|_| ProposalError::Aead)?;
    if plaintext.len() != PLAINTEXT_LEN {
        return Err(ProposalError::BadLength);
    }

    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&plaintext[0..8]);
    let mut blinding = [0u8; 31];
    blinding.copy_from_slice(&plaintext[8..PLAINTEXT_LEN]);
    Ok((u64::from_be_bytes(amount_bytes), blinding))
}

/// `proposal_hash = Poseidon(amount, recipient, blinding, public_amount)` over the
/// four field elements, matching `proposal.go:17` and the ring witness's
/// `RingProposal` encoding.
///
/// - `amount` and `public_amount` are u64 values, absorbed as 32-byte big-endian
///   field elements (low 8 bytes set).
/// - `recipient` is a 32-byte field element (an `Address` used directly, as the
///   circuit treats `Recipient` as a `frontend.Variable`).
/// - `blinding` is a 31-byte big-endian value, right-aligned into a field element.
pub fn proposal_hash(
    amount: u64,
    recipient: &[u8; 32],
    blinding: &[u8; 31],
    public_amount: u64,
) -> Result<[u8; 32], ProposalError> {
    let amount_fe = u64_to_fe(amount);
    let public_amount_fe = u64_to_fe(public_amount);
    let mut blinding_fe = [0u8; 32];
    blinding_fe[1..].copy_from_slice(blinding);

    Poseidon::hashv(&[&amount_fe, recipient, &blinding_fe, &public_amount_fe])
        .map_err(|_| ProposalError::Crypto(CryptoError::Poseidon))
}

fn u64_to_fe(x: u64) -> [u8; 32] {
    let mut fe = [0u8; 32];
    fe[24..32].copy_from_slice(&x.to_be_bytes());
    fe
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_pubkey(sk: &X25519Keypair) -> X25519Pubkey {
        sk.pubkey()
    }

    #[test]
    fn proposal_ciphertext_round_trips() {
        let shared_sk = X25519Keypair::new();
        let shared_pk = random_pubkey(&shared_sk);

        let mut eph = [0u8; 32];
        eph[0] = 0;
        for (i, b) in eph.iter_mut().enumerate().skip(1) {
            *b = (i * 7) as u8;
        }
        let amount = 123_456_789u64;
        let blinding = [9u8; 31];

        let ct = build_proposal_ciphertext(amount, &blinding, &shared_pk, &eph).unwrap();
        assert_eq!(ct.len(), PROPOSAL_CIPHERTEXT_LEN);
        // First 33 bytes are the ephemeral key, used as the proposal PDA seed.
        assert_eq!(
            &ct[0..33],
            X25519Keypair::from_bytes(&eph).pubkey().as_bytes()
        );

        let (got_amount, got_blinding) = decrypt_proposal_ciphertext(&ct, &shared_sk).unwrap();
        assert_eq!(got_amount, amount);
        assert_eq!(got_blinding, blinding);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let shared_sk = X25519Keypair::new();
        let shared_pk = random_pubkey(&shared_sk);
        let eph = {
            let mut e = [0u8; 32];
            e[31] = 5;
            e
        };
        let mut ct = build_proposal_ciphertext(42, &[1u8; 31], &shared_pk, &eph).unwrap();
        // Flip a byte in the GCM body (after the 33-byte ephemeral prefix).
        ct[40] ^= 0xff;
        assert_eq!(
            decrypt_proposal_ciphertext(&ct, &shared_sk),
            Err(ProposalError::Aead)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let shared_sk = X25519Keypair::new();
        let shared_pk = random_pubkey(&shared_sk);
        let other_sk = X25519Keypair::new();
        let eph = {
            let mut e = [0u8; 32];
            e[30] = 3;
            e
        };
        let ct = build_proposal_ciphertext(7, &[2u8; 31], &shared_pk, &eph).unwrap();
        assert_eq!(
            decrypt_proposal_ciphertext(&ct, &other_sk),
            Err(ProposalError::Aead)
        );
    }

    #[test]
    fn proposal_hash_matches_manual_poseidon() {
        let amount = 1000u64;
        let recipient = [7u8; 32];
        let blinding = [3u8; 31];
        let public_amount = 250u64;

        let got = proposal_hash(amount, &recipient, &blinding, public_amount).unwrap();

        let mut amount_fe = [0u8; 32];
        amount_fe[24..].copy_from_slice(&amount.to_be_bytes());
        let mut public_amount_fe = [0u8; 32];
        public_amount_fe[24..].copy_from_slice(&public_amount.to_be_bytes());
        let mut blinding_fe = [0u8; 32];
        blinding_fe[1..].copy_from_slice(&blinding);

        let expected =
            Poseidon::hashv(&[&amount_fe, &recipient, &blinding_fe, &public_amount_fe]).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn proposal_hash_is_deterministic() {
        let a = proposal_hash(5, &[1u8; 32], &[2u8; 31], 6).unwrap();
        let b = proposal_hash(5, &[1u8; 32], &[2u8; 31], 6).unwrap();
        assert_eq!(a, b);
        let c = proposal_hash(6, &[1u8; 32], &[2u8; 31], 6).unwrap();
        assert_ne!(a, c);
    }
}
