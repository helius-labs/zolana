//! Host mirror of the custom ring's `auditor_key_encryption` circuit
//! (`custom-rings/prover/circuits/auditor_key_encryption/{circuit.go,pack.go}`).
//!
//! The circuit proves that the transaction viewing secret key was encrypted to
//! the ring's auditor key, so every value below has an in-circuit counterpart
//! that must agree bit for bit:
//!
//! ```text
//! dh            = ECDH(eph_sk, auditor_pk).x                 -- p256.ECDH
//! shared_secret = Poseidon(DOM_SEP_CR_SHARED,
//!                          dh_lo, dh_hi,
//!                          eph_pk_lo, eph_pk_hi,
//!                          auditor_pk_lo, auditor_pk_hi)     -- DeriveAuditSharedSecret
//! ciphertext    = AES-256-CTR(KeySchedule(shared_secret, AUDIT_ENC_INFO),
//!                             tx_viewing_sk)                 -- ve.KeySchedule + aes.CTREncrypt
//! ```
//!
//! `pack.go` is the source of truth for the packing of `dh` and of the 33-byte
//! compressed keys into pairs of field elements; [`pack32_to_2fe`] and
//! [`pack33_to_2fe`] mirror it. The key schedule and the CTR keystream come from
//! [`zolana_keypair::symmetric_apply`], whose Poseidon silo/key/nonce separators
//! are the ones `ve.KeySchedule` uses.

use thiserror::Error;
use zeroize::Zeroizing;
use zolana_interface::instruction::MessageData;
use zolana_keypair::{
    hash::{poseidon, right_align},
    symmetric_apply, KeypairError, P256Pubkey, ViewingKey,
};

/// Key-schedule info string; equals the Go `auditEncInfo`.
pub const AUDIT_ENC_INFO: &[u8; 10] = b"CRING/adt1";

/// Shared-secret domain separator, ASCII "CR_S" read as a big-endian u32; equals
/// the Go `DomSepCRShared`.
pub const DOM_SEP_CR_SHARED: u32 = 0x4352_5f53;

/// `eph_pk_compressed(33) || ciphertext(32)`.
pub const AUDITOR_MESSAGE_LEN: usize = 65;

const COMPRESSED_PUBKEY_LEN: usize = 33;
const CIPHERTEXT_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditEncryptionError {
    #[error("message view tag is not the auditor view tag")]
    ViewTagMismatch,
    #[error("auditor message data must be {AUDITOR_MESSAGE_LEN} bytes, got {0}")]
    MessageLength(usize),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
}

type Result<T> = core::result::Result<T, AuditEncryptionError>;

/// Mirrors `Pack32To2FECircuit`: `lo = 0x00 || bytes[0..31]` (byte 0 is the most
/// significant data byte) and `hi = bytes[31]`, both as 32-byte big-endian field
/// elements.
pub fn pack32_to_2fe(bytes: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..].copy_from_slice(&bytes[..31]);
    (lo, right_align(&[bytes[31]]))
}

/// Mirrors `Pack33To2FECircuit`: `lo = 0x00 || key[0..31]` (the SEC1 prefix is the
/// most significant data byte) and `hi = key[31] * 256 + key[32]`, both as
/// 32-byte big-endian field elements.
pub fn pack33_to_2fe(key: &[u8; COMPRESSED_PUBKEY_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut lo = [0u8; 32];
    lo[1..].copy_from_slice(&key[..31]);
    (lo, right_align(&[key[31], key[32]]))
}

/// Mirrors `DeriveAuditSharedSecret`: binds the raw ECDH x-coordinate to both
/// public keys that produced it, so the key schedule input cannot be replayed
/// under a different key pair. Input order is pinned by `pack.go`.
pub fn derive_audit_shared_secret(
    dh: &[u8; 32],
    eph_pk: &P256Pubkey,
    auditor_pk: &P256Pubkey,
) -> Result<[u8; 32]> {
    let (dh_lo, dh_hi) = pack32_to_2fe(dh);
    let (eph_lo, eph_hi) = pack33_to_2fe(eph_pk.as_bytes());
    let (auditor_lo, auditor_hi) = pack33_to_2fe(auditor_pk.as_bytes());
    Ok(poseidon(&[
        &right_align(&DOM_SEP_CR_SHARED.to_be_bytes()),
        &dh_lo,
        &dh_hi,
        &eph_lo,
        &eph_hi,
        &auditor_lo,
        &auditor_hi,
    ])?)
}

/// Encrypts the transaction viewing secret key to `auditor_pk` under `ephemeral`.
///
/// `(shared_secret, AUDIT_ENC_INFO)` fully determines the AES-CTR keystream and
/// the shared secret is fixed by `(ephemeral, auditor_pk)`, so encrypting two
/// different plaintexts under one ephemeral key would leak their XOR. The
/// ephemeral key is therefore consumed here: one key, one transaction. Callers
/// that do not need to witness a specific ephemeral scalar should use
/// [`AuditorEncryption::new`], which generates it internally.
pub fn encrypt_tx_viewing_sk(
    tx_viewing_sk: &[u8; 32],
    ephemeral: ViewingKey,
    auditor_pk: &P256Pubkey,
) -> Result<[u8; 32]> {
    let dh = Zeroizing::new(ephemeral.ecdh(auditor_pk)?);
    let shared_secret = Zeroizing::new(derive_audit_shared_secret(
        &dh,
        &ephemeral.pubkey(),
        auditor_pk,
    )?);
    let mut ciphertext = *tx_viewing_sk;
    symmetric_apply(&shared_secret, AUDIT_ENC_INFO, &mut ciphertext)?;
    Ok(ciphertext)
}

/// Recovers the transaction viewing secret key with the auditor's viewing key.
///
/// ECDH is symmetric, so `auditor.ecdh(eph_pk)` is the same x-coordinate the
/// sender derived, and the CTR keystream application is its own inverse.
pub fn decrypt_tx_viewing_sk(
    auditor: &ViewingKey,
    eph_pk: &P256Pubkey,
    ciphertext: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let dh = Zeroizing::new(auditor.ecdh(eph_pk)?);
    let shared_secret = Zeroizing::new(derive_audit_shared_secret(&dh, eph_pk, &auditor.pubkey())?);
    let mut plaintext = Zeroizing::new(*ciphertext);
    symmetric_apply(&shared_secret, AUDIT_ENC_INFO, plaintext.as_mut_slice())?;
    Ok(plaintext)
}

/// The auditor payload published in `TransactIxData::messages`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditorMessage {
    /// SEC1-compressed ephemeral public key.
    pub eph_pk: [u8; COMPRESSED_PUBKEY_LEN],
    /// AES-256-CTR ciphertext of the transaction viewing secret key.
    pub ciphertext: [u8; CIPHERTEXT_LEN],
}

impl AuditorMessage {
    pub fn to_message_data(&self, auditor_pk: &P256Pubkey) -> MessageData {
        let mut data = Vec::with_capacity(AUDITOR_MESSAGE_LEN);
        data.extend_from_slice(&self.eph_pk);
        data.extend_from_slice(&self.ciphertext);
        MessageData {
            view_tag: auditor_view_tag(auditor_pk),
            data,
        }
    }

    pub fn parse(message: &MessageData, auditor_pk: &P256Pubkey) -> Result<Self> {
        if message.view_tag != auditor_view_tag(auditor_pk) {
            return Err(AuditEncryptionError::ViewTagMismatch);
        }
        let (eph_pk, ciphertext) = message
            .data
            .split_at_checked(COMPRESSED_PUBKEY_LEN)
            .filter(|(_, ciphertext)| ciphertext.len() == CIPHERTEXT_LEN)
            .ok_or(AuditEncryptionError::MessageLength(message.data.len()))?;
        let mut parsed = Self {
            eph_pk: [0u8; COMPRESSED_PUBKEY_LEN],
            ciphertext: [0u8; CIPHERTEXT_LEN],
        };
        parsed.eph_pk.copy_from_slice(eph_pk);
        parsed.ciphertext.copy_from_slice(ciphertext);
        Ok(parsed)
    }

    /// Fails if the published ephemeral key is not a curve point.
    pub fn ephemeral_pubkey(&self) -> Result<P256Pubkey> {
        Ok(P256Pubkey::from_bytes(self.eph_pk)?)
    }
}

/// A fresh ephemeral key and the auditor message it produced.
///
/// Generating the key here is what keeps the AES-CTR keystream single-use: the
/// only way to obtain a message is to obtain a new ephemeral scalar with it. The
/// scalar is kept because the circuit witnesses it.
pub struct AuditorEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub message: AuditorMessage,
}

impl AuditorEncryption {
    pub fn new(tx_viewing_sk: &[u8; 32], auditor_pk: &P256Pubkey) -> Result<Self> {
        let ephemeral = ViewingKey::new();
        let ephemeral_sk = ephemeral.secret_bytes();
        let eph_pk = ephemeral.pubkey();
        let ciphertext = encrypt_tx_viewing_sk(tx_viewing_sk, ephemeral, auditor_pk)?;
        Ok(Self {
            ephemeral_sk,
            message: AuditorMessage {
                eph_pk: *eph_pk.as_bytes(),
                ciphertext,
            },
        })
    }
}

/// The view tag the auditor scans for: the auditor key's x-coordinate, i.e. the
/// compressed key without its SEC1 prefix.
pub fn auditor_view_tag(pk: &P256Pubkey) -> [u8; 32] {
    pk.x()
}
