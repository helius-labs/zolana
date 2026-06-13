pub mod instruction;
pub mod state;

pub use state::{SyncDelegateEntry, UserRecord};

pub const USER_REGISTRY_PROGRAM_ID: [u8; 32] = [
    122, 111, 108, 97, 110, 97, 95, 117, 114, 101, 103, 95, 118, 48, 95, 95, 95, 95, 95, 95, 95,
    95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 1,
];

pub const USER_RECORD_SEED: &[u8] = b"zolana/registry/v0";

#[cfg(feature = "solana")]
pub fn user_record_pda(owner: &solana_pubkey::Pubkey) -> (solana_pubkey::Pubkey, u8) {
    solana_pubkey::Pubkey::find_program_address(
        &[USER_RECORD_SEED, owner.as_ref()],
        &user_registry_program_id(),
    )
}

#[cfg(feature = "solana")]
pub fn user_registry_program_id() -> solana_pubkey::Pubkey {
    solana_pubkey::Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID)
}
