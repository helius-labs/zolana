//! Account layouts, instruction data, errors and statement hashes of the
//! custom ring program, shared by the program, the SDK and the services.

pub mod base_public_input;
pub mod deposit;
pub mod deposit_audit;
pub mod disclosure;
pub mod error;
pub mod instruction;
pub mod key_registry;
pub mod policy_public_input;
pub mod state;

macro_rules! verifying_keys {
    ($($module:ident => $key:literal,)*) => {
        $(
            #[cfg(feature = "verifying-keys")]
            pub mod $module;
        )*

        /// Proving key file name in proving-keys.lock and the sha256 its verifying key pins.
        #[cfg(feature = "verifying-keys")]
        pub const PROVING_KEY_SHA256S: &[(&str, [u8; 32])] =
            &[$(($key, $module::VERIFYINGKEY_PROVING_KEY_SHA256),)*];
    };
}

verifying_keys! {
    base_verifying_key => "custom_ring_base.key",
    delegate_policy_verifying_key => "custom_ring_delegate_policy.key",
    deposit_verifying_key => "custom_ring_deposit.key",
    policy_verifying_key => "custom_ring_policy.key",
    register_key_verifying_key => "custom_ring_register_key.key",
}

pub use base_public_input::*;
pub use deposit::*;
pub use deposit_audit::*;
pub use disclosure::*;
pub use error::CustomRingError;
pub use instruction::*;
pub use key_registry::*;
pub use policy_public_input::CustomRingPolicyPublicInput;
pub use state::*;

/// One-byte `0x04` scheme tag followed by a canonical X25519 u-coordinate.
pub const TAGGED_X25519_KEY_LEN: usize = 33;
pub const VIEWING_PUBKEY_TAG: u8 = 4;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
pub const AUDIT_OUTPUT_FIELD_COUNT: usize = 9;
pub const AUDIT_DISCLOSURE_FIELD_COUNT: usize = AUDIT_OUTPUT_FIELD_COUNT * AUDIT_OUTPUT_SLOTS;
pub const AUDIT_DISCLOSURE_LEN: usize = 32 * AUDIT_DISCLOSURE_FIELD_COUNT;
/// The auditor message before its disclosure fields.
pub const AUDITOR_MESSAGE_PREFIX_LEN: usize = TAGGED_X25519_KEY_LEN + AUDIT_CIPHERTEXT_LEN;
/// The auditor message of a ring that is not anonymous.
pub const AUDITOR_MESSAGE_LEN: usize = AUDITOR_MESSAGE_PREFIX_LEN + AUDIT_DISCLOSURE_LEN;

/// The data of the one message a transact publishes under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorMessage<'a> {
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: &'a [[u8; 32]],
}

impl<'a> AuditorMessage<'a> {
    /// `None` unless `data` holds a tagged ephemeral key, the ciphertext and
    /// exactly the disclosure fields `shape` publishes.
    pub fn parse(data: &'a [u8], shape: DisclosureShape) -> Option<Self> {
        let fields = shape.field_count()?;
        let (eph_pk, rest) = data.split_first_chunk::<TAGGED_X25519_KEY_LEN>()?;
        let (ciphertext, disclosure) = rest.split_first_chunk::<AUDIT_CIPHERTEXT_LEN>()?;
        if eph_pk[0] != VIEWING_PUBKEY_TAG || disclosure.len() != 32 * fields {
            return None;
        }
        Some(Self {
            eph_pk,
            ciphertext,
            disclosure: bytemuck::try_cast_slice(disclosure).ok()?,
        })
    }
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
