//! Account layouts, instruction data, and audit statement hashing of the
//! custom ring program, shared by the program, the SDK, and the services.

pub mod base_public_input;
#[cfg(feature = "verifying-keys")]
pub mod base_verifying_key;
#[cfg(feature = "verifying-keys")]
pub mod compressed_policy_verifying_key;
#[cfg(feature = "verifying-keys")]
pub mod compressed_register_verifying_key;
#[cfg(feature = "verifying-keys")]
pub mod delegate_policy_verifying_key;
pub mod head_map;
pub mod instruction;
pub mod key_registry;
#[cfg(not(target_os = "solana"))]
pub mod pda;
pub mod policy_public_input;
#[cfg(feature = "verifying-keys")]
pub mod policy_verifying_key;
#[cfg(feature = "verifying-keys")]
pub mod register_key_verifying_key;
pub mod state;

pub use base_public_input::{pack32_to_2fe, pack33_to_2fe, CustomRingBasePublicInput, FieldPair};
pub use head_map::{
    CompressedRegisterPublicInput, HeadMapInsert, HeadMapLeaf, HeadMapTransfer, HeadMapVerifyError,
    MerklePath, HEAD_MAP_CAPACITY, HEAD_MAP_HEIGHT,
};
pub use instruction::{
    accounts, tag, CreateConfigIxData, CreateEntryIxData, CustomRingProof,
    CustomRingTransactIxData, HeadMapTransition, PlainGroth16Proof, PolicyTableIxData,
    ReaderIxData, RegisterKeyIxData, RegisterSpendIxData, SetCoSignerIxData, SetPausedIxData,
    SetPolicySourceIxData, SetSpendWindowIxData, SourceSpec, UpdateEntryIxData, VelocityRowIxData,
    WithdrawalThreshold, CREATE_CONFIG_COMPUTE_UNIT_LIMIT, CREATE_HEAD_MAP_ROOT_COMPUTE_UNIT_LIMIT,
    CREATE_KEY_REGISTRY_ROOT_COMPUTE_UNIT_LIMIT, CREATE_POLICY_COMPUTE_UNIT_LIMIT,
    ENTRY_MUTATION_COMPUTE_UNIT_LIMIT, INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT,
    READ_ACCESS_COMPUTE_UNIT_LIMIT, REGISTER_KEY_COMPUTE_UNIT_LIMIT,
    REGISTER_SPEND_COMPUTE_UNIT_LIMIT, SET_AUTHORITY_COMPUTE_UNIT_LIMIT,
    SET_CO_SIGNER_COMPUTE_UNIT_LIMIT, SET_DELEGATE_COMPUTE_UNIT_LIMIT,
    SET_PAUSED_COMPUTE_UNIT_LIMIT, SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
    SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT, SET_SPEND_WINDOW_COMPUTE_UNIT_LIMIT,
};
pub use key_registry::{RegisterKeyPublicInput, RegisteredKey};
pub use policy_public_input::{CompressedPolicyPublicInput, CustomRingPolicyPublicInput};
pub use state::{
    CoSignScope, CoSigner, Delegate, FixedWindow, HeadMapRoot, KeyRegistryRoot, PolicyConfig,
    ReadAccessRecord, RingProgramConfig, SourceSlot, SpendWindow, WithdrawalThresholdRow,
    CONFIG_PDA_SEED, CO_SIGNER, CO_SIGNER_PDA_SEED, DELEGATE, DELEGATE_PDA_SEED,
    HEAD_MAP_EMPTY_ROOT, HEAD_MAP_ROOT, HEAD_MAP_ROOT_PDA_SEED, KEY_REGISTRY_ROOT,
    KEY_REGISTRY_ROOT_PDA_SEED, MAX_CO_SIGNER_THRESHOLDS, N_SOURCE_SLOTS, POLICY_CONFIG,
    POLICY_CONFIG_PDA_SEED, READ_ACCESS_RECORD, READ_ACCESS_RECORD_PDA_SEED, RING_PROGRAM_CONFIG,
    SPEND_WINDOW, SPEND_WINDOW_PDA_SEED,
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
