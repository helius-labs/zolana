pub mod instruction;
pub mod state;

pub use state::{SyncDelegateEntry, UserRecord};

pub const USER_REGISTRY_PROGRAM_ID: [u8; 32] =
    pubkey_array!("9EwHPNdsPHMt7kaUZaXDTaj92HVC8CL4Q16io4Vu87t4");

pub const USER_RECORD_SEED: &[u8] = b"zolana/registry/v0";

/// Decode a base58 program id into a `[u8; 32]` const at compile time.
#[macro_export]
macro_rules! pubkey_array {
    ($address:literal) => {{
        const _PK: ::solana_pubkey::Pubkey = ::solana_pubkey::Pubkey::from_str_const($address);
        _PK.to_bytes()
    }};
}

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
