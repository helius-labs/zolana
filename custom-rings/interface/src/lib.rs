//! Account layouts, instruction data, errors and statement hashes of the
//! custom ring program, shared by the program, the SDK and the services.

pub mod base_public_input;
pub mod deposit;
pub mod deposit_audit;
pub mod disclosure;
pub mod error;
pub mod instruction;
pub mod member_registry;
pub mod policy_public_input;
pub mod public_table;
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
    base_confidential_verifying_key => "custom_ring_base_confidential.key",
    delegate_policy_verifying_key => "custom_ring_delegate_policy.key",
    delegate_policy_2x3_verifying_key => "custom_ring_delegate_policy_2x3.key",
    deposit_verifying_key => "custom_ring_deposit.key",
    policy_verifying_key => "custom_ring_policy.key",
    policy_2x3_verifying_key => "custom_ring_policy_2x3.key",
    policy_2x3_anonymous_verifying_key => "custom_ring_policy_2x3_anonymous.key",
    register_key_verifying_key => "custom_ring_register_key.key",
    update_members_verifying_key => "custom_ring_update_members.key",
}

pub use base_public_input::*;
pub use deposit::*;
pub use deposit_audit::*;
pub use disclosure::*;
pub use error::CustomRingError;
pub use instruction::*;
pub use member_registry::*;
pub use policy_public_input::{CustomRingPolicyPublicInput, POLICY_INDEXED_INPUTS};
pub use public_table::*;
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

// Public points excluded from passkey reader registration.
const READER_CONST_SEC1: [u8; 33] = [
    0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
    0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
    0xdb,
];

const READER_DERIVE_SEC1: [u8; 33] = [
    0x03, 0x9e, 0xf1, 0x65, 0x92, 0x42, 0x9d, 0xa1, 0x40, 0x3e, 0xaa, 0x29, 0x05, 0x8e, 0xb7, 0xd9,
    0xd5, 0xad, 0x15, 0xa2, 0xea, 0x55, 0x71, 0x74, 0xf7, 0xb0, 0x1f, 0xf7, 0xfe, 0x48, 0x4e, 0xee,
    0xaf,
];

const READER_PDA_SEC1: [u8; 33] = [
    0x03, 0x8a, 0x31, 0xd5, 0x3c, 0x5a, 0xd2, 0x0d, 0x1c, 0xd7, 0xee, 0x1f, 0xbb, 0x99, 0x27, 0xbd,
    0x0c, 0xdf, 0xb6, 0x1b, 0x1b, 0x89, 0xf6, 0xb2, 0xc5, 0xa9, 0x4a, 0x5f, 0x08, 0x1f, 0xe1, 0x6b,
    0x5b,
];

pub const RESERVED_READER_KEYS: [[u8; 33]; 3] =
    [READER_CONST_SEC1, READER_DERIVE_SEC1, READER_PDA_SEC1];

pub fn is_reserved_reader_key(key: &[u8; 33]) -> bool {
    RESERVED_READER_KEYS.contains(key)
}
