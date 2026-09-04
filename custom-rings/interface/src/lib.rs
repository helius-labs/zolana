//! Account layouts, instruction data, and audit statement hashing of the
//! custom ring program, shared by the program, the SDK, and the services.

pub mod base_public_input;
#[cfg(feature = "verifying-keys")]
pub mod base_verifying_key;
pub mod instruction;
pub mod policy_public_input;
#[cfg(feature = "verifying-keys")]
pub mod policy_verifying_key;
pub mod state;

pub use base_public_input::{pack32_to_2fe, pack33_to_2fe, CustomRingBasePublicInput, FieldPair};
pub use instruction::{
    tag, CreateConfigIxData, CreateEntryIxData, CustomRingProof, CustomRingTransactIxData,
    PolicyTableIxData, ReaderIxData, SetPausedIxData, SetPolicySourceIxData, SourceSpec,
    UpdateEntryIxData, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, CREATE_POLICY_COMPUTE_UNIT_LIMIT,
    ENTRY_MUTATION_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
    SET_PAUSED_COMPUTE_UNIT_LIMIT, SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
    SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
};
pub use policy_public_input::CustomRingPolicyPublicInput;
pub use state::{
    PolicyConfig, ReadAccessRecord, RingProgramConfig, SourceSlot, CONFIG_PDA_SEED, N_SOURCE_SLOTS,
    POLICY_CONFIG, POLICY_CONFIG_PDA_SEED, READ_ACCESS_RECORD, READ_ACCESS_RECORD_PDA_SEED,
    RING_PROGRAM_CONFIG,
};

/// SEC1-compressed public key length.
pub const COMPRESSED_P256_KEY_LEN: usize = 33;
/// AES-256-CTR ciphertext of the 32-byte transaction viewing secret key.
pub const AUDIT_CIPHERTEXT_LEN: usize = 32;
/// `eph_pk_compressed(33) || ciphertext(32)`.
pub const AUDITOR_MESSAGE_LEN: usize = COMPRESSED_P256_KEY_LEN + AUDIT_CIPHERTEXT_LEN;

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
