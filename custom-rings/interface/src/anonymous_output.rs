//! Scheme-9 body layout and stream secret, pinned by `test-vectors/anonymous_recipient_encryption.json`.

use thiserror::Error;
use zolana_hasher::{
    primitives::{hash_bytes, is_canonical_bn254_scalar_be, right_align},
    Hasher, HasherError, Poseidon,
};

use crate::{pack_2fe, TAGGED_X25519_KEY_LEN};

/// The scheme byte every published anonymous body starts with.
pub const ANONYMOUS_OUTPUT_SCHEME: u8 = 0x09;
/// `asset_address(32) || amount(8) || blinding(32) || pair_u(32)`.
pub const ANONYMOUS_OUTPUT_PLAINTEXT_LEN: usize = 104;
/// The scheme byte followed by the ciphertext, the exact bytes a slot carries.
pub const ANONYMOUS_OUTPUT_BODY_LEN: usize = ANONYMOUS_OUTPUT_PLAINTEXT_LEN + 1;
/// ASCII "CR_R", the Go `RecipientKeyDomain`.
pub const RECIPIENT_KEY_DOMAIN: u32 = 0x4352_5f52;
/// The stream schedule tag the recipient body shares with the auditor envelope, the Go `auditEncInfo`.
pub const AUDIT_STREAM_INFO: &[u8; 10] = b"CRING/adt1";

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AnonymousOutputError {
    #[error("blinding is not a canonical field element")]
    NoncanonicalBlinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousOutputPlaintext {
    pub asset_address: [u8; 32],
    pub amount: u64,
    /// Big-endian canonical encoding, an alias above the modulus never opens a note.
    pub blinding: [u8; 32],
    pub pair_u: [u8; 32],
}

impl AnonymousOutputPlaintext {
    pub fn to_bytes(&self) -> [u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN] {
        let mut out = [0u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN];
        out[..32].copy_from_slice(&self.asset_address);
        out[32..40].copy_from_slice(&self.amount.to_be_bytes());
        out[40..72].copy_from_slice(&self.blinding);
        out[72..].copy_from_slice(&self.pair_u);
        out
    }

    pub fn from_bytes(
        bytes: &[u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN],
    ) -> Result<Self, AnonymousOutputError> {
        let blinding = chunk::<32>(bytes, 40);
        if !is_canonical_bn254_scalar_be(&blinding) {
            return Err(AnonymousOutputError::NoncanonicalBlinding);
        }
        Ok(Self {
            asset_address: chunk(bytes, 0),
            amount: u64::from_be_bytes(chunk(bytes, 32)),
            blinding,
            pair_u: chunk(bytes, 72),
        })
    }
}

fn chunk<const N: usize>(bytes: &[u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN], at: usize) -> [u8; N] {
    core::array::from_fn(|i| bytes[at + i])
}

/// The published slot bytes of a ciphertext.
pub fn anonymous_output_body(
    ciphertext: &[u8; ANONYMOUS_OUTPUT_PLAINTEXT_LEN],
) -> [u8; ANONYMOUS_OUTPUT_BODY_LEN] {
    let mut body = [0u8; ANONYMOUS_OUTPUT_BODY_LEN];
    body[0] = ANONYMOUS_OUTPUT_SCHEME;
    body[1..].copy_from_slice(ciphertext);
    body
}

/// The statement element of one slot, the program hashes the exact bytes the slot carries.
pub fn anonymous_output_body_hash(
    body: &[u8; ANONYMOUS_OUTPUT_BODY_LEN],
) -> Result<[u8; 32], HasherError> {
    hash_bytes(body)
}

/// Shares the auditor envelope's schedule, `RECIPIENT_KEY_DOMAIN` is the only separation.
pub fn recipient_stream_secret(
    dh: &[u8; 32],
    tx_pk: &[u8; TAGGED_X25519_KEY_LEN],
    recipient_pk: &[u8; TAGGED_X25519_KEY_LEN],
    salt: &[u8; 16],
    slot: u8,
) -> Result<[u8; 32], HasherError> {
    let [dh, tx_pk, recipient_pk] = [pack_2fe(dh), pack_2fe(tx_pk), pack_2fe(recipient_pk)];
    Poseidon::hashv(&[
        &right_align(&RECIPIENT_KEY_DOMAIN.to_be_bytes()),
        &dh.lo,
        &dh.hi,
        &tx_pk.lo,
        &tx_pk.hi,
        &recipient_pk.lo,
        &recipient_pk.hi,
        &right_align(salt),
        &right_align(&[slot]),
    ])
}
