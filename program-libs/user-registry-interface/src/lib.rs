pub mod instruction;
pub mod state;

pub use state::{owner_p256_identity, P256OwnerClaim, SyncDelegateEntry, UserRecord};

pub const USER_REGISTRY_PROGRAM_ID: [u8; 32] =
    pubkey_array!("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");

pub const USER_RECORD_SEED: &[u8] = b"zolana/registry/v0";

pub const P256_OWNER_CLAIM_SEED: &[u8] = b"zolana/registry/p256-owner/v0";

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

/// The claim account that binds a P256 owner identity to one record. Keyed by the
/// key's x-coordinate, because owner identity ignores the SEC1 parity prefix.
#[cfg(feature = "solana")]
pub fn p256_owner_claim_pda(
    owner_p256: &[u8; state::P256_PUBKEY_LEN],
) -> (solana_pubkey::Pubkey, u8) {
    solana_pubkey::Pubkey::find_program_address(
        &[P256_OWNER_CLAIM_SEED, &owner_p256_identity(owner_p256)],
        &user_registry_program_id(),
    )
}

#[cfg(feature = "solana")]
pub fn user_registry_program_id() -> solana_pubkey::Pubkey {
    solana_pubkey::Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID)
}
