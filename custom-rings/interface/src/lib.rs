//! Account layouts, instruction data, and audit statement hashing of the
//! custom ring program, shared by the program, the SDK, and the services.

pub mod instruction;
pub mod proof;
pub mod state;
#[cfg(feature = "verifying-keys")]
pub mod verifying_key;

pub use instruction::{
    tag, CreateConfigIxData, CustomRingProof, CustomRingTransactIxData, ReaderIxData,
    CREATE_CONFIG_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
};
pub use proof::{pack32_to_2fe, pack33_to_2fe, CustomRingPublicInput, FieldPair};
pub use state::{
    ReadAccessRecord, RingProgramConfig, CONFIG_PDA_SEED, READ_ACCESS_RECORD,
    READ_ACCESS_RECORD_PDA_SEED, RING_PROGRAM_CONFIG,
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
