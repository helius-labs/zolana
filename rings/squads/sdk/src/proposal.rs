//! Wallet-facing proposal ciphertext construction/decryption and the
//! `proposal_hash` commitment.
//!
//! Formats (sources of truth):
//! - `ProposalCiphertext` is 88 bytes: 33-byte ephemeral compressed P-256 key +
//!   39-byte AES-GCM body (8-byte amount || 31-byte blinding) + 16-byte tag.
//!   (`docs/squads_policy_program.md:84`, `interface::constants::PROPOSAL_CIPHERTEXT_LEN`.)
//! - the proposal account stores a private v2 core over the hidden operation
//!   fields. Execution derives the circuit's public commitment by hashing that
//!   core with the operation, asset field, and destination field. This lets the
//!   program recompute every public part of the approval without publishing the
//!   encrypted amount or blinding.
//!
//! Unlike the AES-CTR zone ciphertexts (whose integrity comes from the proof's
//! Poseidon ciphertext hash), the proposal ciphertext is NOT proven by any
//! circuit, so it carries a real GCM authentication tag. The AES-256-GCM key and
//! 96-bit nonce are derived from the ECDH shared secret with the same proven
//! Poseidon key schedule the zone uses ([`crate::crypto::derive_shared_secret`] +
//! [`crate::crypto::key_schedule`]), so no extra KDF dependency is introduced.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use p256::{PublicKey, SecretKey};
use thiserror::Error;
use zolana_hasher::{Hasher, Poseidon};
use zolana_keypair::P256Pubkey;
use zolana_squads_interface::{
    circuits::{domain_field, PROPOSAL_V2_DOMAIN},
    constants::PROPOSAL_CIPHERTEXT_LEN,
    types::{Address, ProposalCiphertext},
};

use crate::crypto::{
    self, ecdh_x, fe_from_u64, scalar_from_fe, scalar_mul_generator_compressed, CryptoError,
};

const EPHEMERAL_LEN: usize = 33;
const TAG_LEN: usize = 16;
/// Plaintext: 8-byte amount (big-endian u64) || 31-byte blinding.
const PLAINTEXT_LEN: usize = 8 + 31;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProposalError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid P-256 public key")]
    InvalidPubkey,
    #[error("AES-GCM authentication failed")]
    Aead,
    #[error("bad ciphertext or plaintext length")]
    BadLength,
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

/// `ephemeral_secret` is a 32-byte big-endian scalar the caller supplies (fresh
/// per proposal, since the ciphertext's first 33 bytes seed the proposal PDA). It
/// is reduced into the P-256 scalar field, matching how the zone builder treats
/// ephemeral scalars.
pub fn build_proposal_ciphertext(
    amount: u64,
    blinding: &[u8; 31],
    shared_viewing_pk: &P256Pubkey,
    ephemeral_secret: &[u8; 32],
) -> Result<ProposalCiphertext, ProposalError> {
    let scalar = scalar_from_fe(ephemeral_secret);
    let eph_comp = scalar_mul_generator_compressed(&scalar);
    let recipient = shared_viewing_pk
        .to_p256()
        .map_err(|_| ProposalError::InvalidPubkey)?;
    let recipient_comp = *shared_viewing_pk.as_bytes();

    let dh = ecdh_x(&scalar, &recipient)?;
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
    if body.len() != PLAINTEXT_LEN + TAG_LEN {
        return Err(ProposalError::BadLength);
    }

    let mut out = [0u8; PROPOSAL_CIPHERTEXT_LEN];
    out[0..EPHEMERAL_LEN].copy_from_slice(&eph_comp);
    out[EPHEMERAL_LEN..].copy_from_slice(&body);
    Ok(out)
}

pub fn decrypt_proposal_ciphertext(
    ct: &ProposalCiphertext,
    shared_viewing_sk: &SecretKey,
) -> Result<(u64, [u8; 31]), ProposalError> {
    let mut eph_comp = [0u8; 33];
    eph_comp.copy_from_slice(&ct[0..EPHEMERAL_LEN]);
    let body = &ct[EPHEMERAL_LEN..];

    let eph_pub =
        PublicKey::from_sec1_bytes(&eph_comp).map_err(|_| ProposalError::InvalidPubkey)?;
    let recipient_comp = *P256Pubkey::from_p256(&shared_viewing_sk.public_key()).as_bytes();

    let scalar = *shared_viewing_sk.to_nonzero_scalar();
    let dh = ecdh_x(&scalar, &eph_pub)?;
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

/// Domain separator for the encrypted/private part of a v2 proposal.
const PROPOSAL_CORE_V2_DOMAIN: &[u8] = b"ZOLANA/SQUADS/PROPOSAL_CORE/V2";
pub use zolana_squads_interface::circuits::ProposalOperation;

/// Private v2 proposal core stored in `Proposal.proposal_hash`:
///
/// `Poseidon(core_domain, operation, amount, recipient, blinding, public_amount)`.
///
/// The program cannot recompute this layer because amount and blinding remain
/// encrypted. It recomputes [`proposal_commitment_hash`] from this core and the
/// public proposal record at execution.
///
/// - `amount` and `public_amount` are u64 values, absorbed as 32-byte big-endian
///   field elements (low 8 bytes set).
/// - `recipient` is a 32-byte field element (an `Address` used directly, as the
///   circuit treats `Recipient` as a `frontend.Variable`).
/// - `blinding` is a 31-byte big-endian value, right-aligned into a field element.
pub fn proposal_hash(
    operation: ProposalOperation,
    amount: u64,
    recipient: &[u8; 32],
    blinding: &[u8; 31],
    public_amount: u64,
) -> Result<[u8; 32], ProposalError> {
    let amount_fe = fe_from_u64(amount);
    let public_amount_fe = fe_from_u64(public_amount);
    let mut blinding_fe = [0u8; 32];
    blinding_fe[1..].copy_from_slice(blinding);

    proposal_hash_fields(
        operation,
        &amount_fe,
        recipient,
        &blinding_fe,
        &public_amount_fe,
    )
}

pub(crate) fn proposal_hash_fields(
    operation: ProposalOperation,
    amount: &[u8; 32],
    recipient: &[u8; 32],
    blinding: &[u8; 32],
    public_amount: &[u8; 32],
) -> Result<[u8; 32], ProposalError> {
    let domain = domain_field(PROPOSAL_CORE_V2_DOMAIN);
    let operation = operation.field();
    Poseidon::hashv(&[
        &domain,
        &operation,
        amount,
        recipient,
        blinding,
        public_amount,
    ])
    .map_err(|_| ProposalError::Crypto(CryptoError::Poseidon))
}

/// Public asset commitment included in the zone transaction proposal context.
pub fn proposal_asset_commitment(asset: &Address) -> Result<[u8; 32], ProposalError> {
    zolana_hasher::primitives::hash_bytes(asset.as_array())
        .map_err(|_| ProposalError::Crypto(CryptoError::Poseidon))
}

/// Public destination commitment. A transfer destination is already the
/// recipient viewing-key account's canonical owner encoding. A withdrawal
/// destination is an arbitrary Solana address and is therefore hashed.
pub fn proposal_destination_commitment(
    operation: ProposalOperation,
    destination: &Address,
) -> Result<[u8; 32], ProposalError> {
    match operation {
        ProposalOperation::Transfer => Ok(destination.to_bytes()),
        ProposalOperation::Withdrawal => {
            zolana_hasher::primitives::hash_bytes(destination.as_array())
                .map_err(|_| ProposalError::Crypto(CryptoError::Poseidon))
        }
    }
}

/// V2 proposal commitment used as the zone proof's proposal public input:
///
/// `Poseidon(context_domain, operation, private_core, asset, destination)`.
///
/// `private_core` is the value stored in the proposal account. The program
/// derives `asset` and `destination` from that immutable record and checks them
/// against the execution accounts before recomputing this value.
pub fn proposal_commitment_hash(
    operation: ProposalOperation,
    private_core: &[u8; 32],
    asset: &[u8; 32],
    destination: &[u8; 32],
) -> Result<[u8; 32], ProposalError> {
    let domain = domain_field(PROPOSAL_V2_DOMAIN);
    let operation = operation.field();
    Poseidon::hashv(&[&domain, &operation, private_core, asset, destination])
        .map_err(|_| ProposalError::Crypto(CryptoError::Poseidon))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    fn random_pubkey(sk: &SecretKey) -> P256Pubkey {
        P256Pubkey::from_p256(&sk.public_key())
    }

    #[test]
    fn proposal_ciphertext_round_trips() {
        let shared_sk = SecretKey::random(&mut OsRng);
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
        let scalar = scalar_from_fe(&eph);
        assert_eq!(&ct[0..33], &scalar_mul_generator_compressed(&scalar));

        let (got_amount, got_blinding) = decrypt_proposal_ciphertext(&ct, &shared_sk).unwrap();
        assert_eq!(got_amount, amount);
        assert_eq!(got_blinding, blinding);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let shared_sk = SecretKey::random(&mut OsRng);
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
        let shared_sk = SecretKey::random(&mut OsRng);
        let shared_pk = random_pubkey(&shared_sk);
        let other_sk = SecretKey::random(&mut OsRng);
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

        let got = proposal_hash(
            ProposalOperation::Withdrawal,
            amount,
            &recipient,
            &blinding,
            public_amount,
        )
        .unwrap();

        let mut amount_fe = [0u8; 32];
        amount_fe[24..].copy_from_slice(&amount.to_be_bytes());
        let mut public_amount_fe = [0u8; 32];
        public_amount_fe[24..].copy_from_slice(&public_amount.to_be_bytes());
        let mut blinding_fe = [0u8; 32];
        blinding_fe[1..].copy_from_slice(&blinding);

        let domain = domain_field(PROPOSAL_CORE_V2_DOMAIN);
        let operation = fe_from_u64(ProposalOperation::Withdrawal as u64);
        let expected = Poseidon::hashv(&[
            &domain,
            &operation,
            &amount_fe,
            &recipient,
            &blinding_fe,
            &public_amount_fe,
        ])
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn proposal_hash_is_deterministic() {
        let a = proposal_hash(ProposalOperation::Transfer, 5, &[1u8; 32], &[2u8; 31], 6).unwrap();
        let b = proposal_hash(ProposalOperation::Transfer, 5, &[1u8; 32], &[2u8; 31], 6).unwrap();
        assert_eq!(a, b);
        let c = proposal_hash(ProposalOperation::Transfer, 6, &[1u8; 32], &[2u8; 31], 6).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn proposal_commitment_binds_asset_and_withdrawal_destination() {
        let core =
            proposal_hash(ProposalOperation::Withdrawal, 0, &[0u8; 32], &[2u8; 31], 6).unwrap();
        let asset_a = proposal_asset_commitment(&Address::new_from_array([3u8; 32])).unwrap();
        let asset_b = proposal_asset_commitment(&Address::new_from_array([4u8; 32])).unwrap();
        let destination_a = proposal_destination_commitment(
            ProposalOperation::Withdrawal,
            &Address::new_from_array([5u8; 32]),
        )
        .unwrap();
        let destination_b = proposal_destination_commitment(
            ProposalOperation::Withdrawal,
            &Address::new_from_array([6u8; 32]),
        )
        .unwrap();
        assert_eq!(
            asset_a,
            [
                0x03, 0xdf, 0x2d, 0x93, 0xdf, 0xa1, 0xb0, 0x06, 0xbb, 0xad, 0x4e, 0x16, 0x63, 0x8c,
                0xc7, 0x92, 0x1f, 0x64, 0x88, 0xce, 0x29, 0x5d, 0xe4, 0x67, 0x1e, 0x79, 0xeb, 0x7f,
                0x17, 0x7f, 0xbd, 0xb4,
            ],
            "canonical SPP asset-field vector drifted"
        );
        assert_eq!(
            destination_a,
            [
                0x05, 0xf8, 0xab, 0xf0, 0xc3, 0x1c, 0x1f, 0x86, 0xe6, 0xd1, 0x24, 0x3f, 0xe8, 0x69,
                0xab, 0xfc, 0xf6, 0x06, 0x96, 0xfd, 0xe3, 0x5e, 0xdc, 0x1c, 0x1a, 0xfd, 0x6a, 0x14,
                0x3d, 0xcd, 0x2a, 0x2a,
            ],
            "withdrawal destination-field vector drifted"
        );

        let approved = proposal_commitment_hash(
            ProposalOperation::Withdrawal,
            &core,
            &asset_a,
            &destination_a,
        )
        .unwrap();
        assert_eq!(
            core,
            [
                0x2c, 0xa1, 0x5b, 0x83, 0x0d, 0x4a, 0xc5, 0xff, 0xf8, 0x43, 0x0f, 0x00, 0xbf, 0x6b,
                0xb8, 0xc0, 0x25, 0xda, 0xa8, 0x86, 0xee, 0x97, 0x0e, 0x73, 0xcd, 0xa7, 0xa1, 0xdb,
                0xe5, 0x4d, 0x8a, 0x4e,
            ],
            "proposal private-core vector drifted"
        );
        assert_eq!(
            approved,
            [
                0x03, 0x56, 0xda, 0xc9, 0xf8, 0x28, 0xbf, 0x58, 0x77, 0xcb, 0xcb, 0xa1, 0xcd, 0x73,
                0xed, 0xdb, 0x9e, 0x8e, 0xf2, 0x4b, 0xd1, 0x3d, 0xeb, 0xdb, 0x56, 0xa4, 0x14, 0x9e,
                0x43, 0xbd, 0xae, 0xb3,
            ],
            "proposal v2 commitment vector drifted"
        );
        assert_ne!(
            approved,
            proposal_commitment_hash(
                ProposalOperation::Withdrawal,
                &core,
                &asset_b,
                &destination_a,
            )
            .unwrap(),
            "substituting the asset must change the approved commitment"
        );
        assert_ne!(
            approved,
            proposal_commitment_hash(
                ProposalOperation::Withdrawal,
                &core,
                &asset_a,
                &destination_b,
            )
            .unwrap(),
            "substituting the public withdrawal destination must change the approved commitment"
        );
    }
}
