//! Account layouts, instruction data, errors and statements of the custom ring
//! program, shared by the program, the SDKs and the services.

pub mod anonymous_output;
mod bytes;
pub mod cosign;
pub mod deposit;
pub mod deposit_audit;
pub mod disclosure;
pub mod domain;
pub mod error;
pub mod instruction;
pub mod key_catalog;
pub mod member_registry;
pub mod merge;
pub mod ring_keys;
pub mod state;
pub mod statement;
pub mod stream;
pub mod transact;

// At the crate root, the generated modules keep their public paths.
#[cfg(feature = "verifying-keys")]
include!("verifying_keys.rs");

#[cfg(feature = "verifying-keys")]
pub fn proving_key_hashes() -> impl Iterator<Item = (&'static str, [u8; 32])> {
    PROVING_KEY_SHA256S.iter().copied()
}

pub use anonymous_output::*;
pub use deposit::*;
pub use deposit_audit::*;
pub use disclosure::*;
pub use error::CustomRingError;
pub use instruction::*;
pub use member_registry::*;
pub use merge::*;
pub use state::*;
pub use statement::*;
pub use transact::*;

/// One-byte `0x04` scheme tag followed by a canonical X25519 u-coordinate.
pub use zolana_event::RECIPIENT_KEY_LEN as TAGGED_X25519_KEY_LEN;
pub const VIEWING_PUBKEY_TAG: u8 = 4;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
/// The auditor message before its disclosure fields.
pub const AUDITOR_MESSAGE_PREFIX_LEN: usize = TAGGED_X25519_KEY_LEN + AUDIT_CIPHERTEXT_LEN;

pub fn tagged_x25519(u: &[u8; 32]) -> [u8; TAGGED_X25519_KEY_LEN] {
    let mut key = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
    key[1..].copy_from_slice(u);
    key
}

/// `0x04 || eph_u || sealed || disclosure`, published under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorMessage<'a> {
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub sealed: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: &'a [[u8; 32]],
}

impl<'a> AuditorMessage<'a> {
    /// `None` unless the key is tagged and the disclosure has the field count of `layout`.
    pub fn parse(data: &'a [u8], layout: DisclosureLayout) -> Option<Self> {
        let (eph_pk, rest) = data.split_first_chunk::<TAGGED_X25519_KEY_LEN>()?;
        let (sealed, disclosure) = rest.split_first_chunk::<AUDIT_CIPHERTEXT_LEN>()?;
        if eph_pk[0] != VIEWING_PUBKEY_TAG || disclosure.len() != 32 * layout.field_count() {
            return None;
        }
        Some(Self {
            eph_pk,
            sealed,
            disclosure: disclosure.as_chunks::<32>().0,
        })
    }

    pub fn data(
        eph_u: &[u8; 32],
        sealed: &[u8; AUDIT_CIPHERTEXT_LEN],
        disclosure: &[[u8; 32]],
    ) -> Vec<u8> {
        [&tagged_x25519(eph_u)[..], sealed, disclosure.as_flattened()].concat()
    }
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
