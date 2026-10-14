//! Account layouts, instruction data, errors and statement hashes of the
//! custom ring program, shared by the program, the SDK and the services.

use bytemuck::{Pod, Zeroable};

pub mod base_public_input;
pub mod deposit;
pub mod deposit_audit;
pub mod error;
pub mod instruction;
pub mod key_registry;
#[cfg(not(target_os = "solana"))]
pub mod pda;
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
    compressed_policy_verifying_key => "custom_ring_compressed_policy.key",
    delegate_policy_verifying_key => "custom_ring_delegate_policy.key",
    deposit_verifying_key => "custom_ring_deposit.key",
    policy_verifying_key => "custom_ring_policy.key",
    register_key_verifying_key => "custom_ring_register_key.key",
}

pub use base_public_input::*;
pub use deposit::*;
pub use deposit_audit::*;
pub use error::CustomRingError;
pub use instruction::*;
pub use key_registry::*;
pub use policy_public_input::{CompressedPolicyPublicInput, CustomRingPolicyPublicInput};
pub use state::*;

/// SEC1-compressed public key length.
pub const COMPRESSED_P256_KEY_LEN: usize = 33;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
pub const AUDIT_OUTPUT_FIELD_COUNT: usize = 9;
pub const AUDIT_OUTPUT_SLOTS: usize = 4;
pub const AUDIT_DISCLOSURE_FIELD_COUNT: usize = AUDIT_OUTPUT_FIELD_COUNT * AUDIT_OUTPUT_SLOTS;
pub const AUDIT_DISCLOSURE_LEN: usize = 32 * AUDIT_DISCLOSURE_FIELD_COUNT;
pub const AUDITOR_MESSAGE_LEN: usize = core::mem::size_of::<AuditorMessage>();

/// The data of the one message a transact publishes under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AuditorMessage {
    pub eph_pk: [u8; COMPRESSED_P256_KEY_LEN],
    pub ciphertext: [u8; AUDIT_CIPHERTEXT_LEN],
    pub disclosure: [[u8; 32]; AUDIT_DISCLOSURE_FIELD_COUNT],
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
