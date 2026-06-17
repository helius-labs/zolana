#[cfg(feature = "events")]
pub mod event;
pub mod instruction;
pub mod pda;
pub mod state;
pub mod user_registry;
#[cfg(feature = "verifying-keys")]
pub mod verifying_keys;

/// Decode a base58 program id into a `[u8; 32]` const at compile time.
#[macro_export]
macro_rules! pubkey_array {
    ($address:literal) => {{
        const _PK: ::solana_pubkey::Pubkey = ::solana_pubkey::Pubkey::from_str_const($address);
        _PK.to_bytes()
    }};
}

pub const UTXO_DOMAIN: u16 = 1;

/// Development program id for the shielded-pool program.
pub const SHIELDED_POOL_PROGRAM_ID: [u8; 32] =
    pubkey_array!("8nhL4dQgcddkc8cNV5piaZ1zKGowap1XrS8EDKi4rywq");

/// Seed for the native SOL interface account used by public SOL settlement.
pub const SOL_INTERFACE_PDA_SEED: &[u8] = b"sol_interface";
pub const DEFAULT_SOL_INTERFACE_INDEX_SEED: &[u8] = &[0];

/// Seed for the shielded-pool program's own CPI authority PDA, used as the SPL
/// vault authority for public SPL settlement.
pub const SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED: &[u8] = b"cpi_authority";
pub const SPP_ZONE_CONFIG_PDA_SEED: &[u8] = b"spp_zone_config";
/// Seed for the shielded-pool protocol-config PDA. The config is the singleton
/// authority oracle for admin instructions, so it is a canonical PDA the
/// program creates and address-checks; a substituted config can't name a new
/// authority.
pub const SPP_PROTOCOL_CONFIG_PDA_SEED: &[u8] = b"protocol_config";
pub const ZONE_AUTH_PDA_SEED: &[u8] = b"zone_auth";
pub const SPL_ASSET_COUNTER_PDA_SEED: &[u8] = b"spl_asset_counter";
pub const SPL_ASSET_REGISTRY_PDA_SEED: &[u8] = b"spl_asset_registry";
pub const SPL_ASSET_VAULT_PDA_SEED: &[u8] = b"spl_asset_vault";

/// Canonical shielded-pool CPI authority PDA:
/// `find_program_address(&[b"cpi_authority"], SHIELDED_POOL_PROGRAM_ID)`.
/// Kept as a constant so the SBF program validates settlement accounts with a
/// direct equality check.
pub const SHIELDED_POOL_CPI_AUTHORITY: [u8; 32] = [
    156, 38, 12, 194, 254, 142, 150, 51, 213, 49, 20, 162, 117, 210, 37, 253, 125, 142, 232, 230,
    4, 70, 84, 211, 121, 225, 145, 223, 38, 139, 193, 58,
];

/// Bump for `SHIELDED_POOL_CPI_AUTHORITY`.
pub const SHIELDED_POOL_CPI_AUTHORITY_BUMP: u8 = 255;

/// SPL Token v3 program id: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
pub const SPL_TOKEN_MINT_ACCOUNT_LEN: usize = 82;
pub const SPL_TOKEN_ACCOUNT_LEN: usize = 165;
pub const SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET: usize = 64;
pub const SPL_TOKEN_ACCOUNT_AMOUNT_END: usize =
    SPL_TOKEN_ACCOUNT_AMOUNT_OFFSET + core::mem::size_of::<u64>();
pub const SPL_TOKEN_ACCOUNT_STATE_OFFSET: usize = 108;
pub const SPL_TOKEN_ACCOUNT_INITIALIZED: u8 = 1;
pub const SPL_TOKEN_TRANSFER_DISCRIMINATOR: u8 = 3;
pub const SPL_TOKEN_MINT_TO_DISCRIMINATOR: u8 = 7;
pub const SPL_TOKEN_INITIALIZE_ACCOUNT3_DISCRIMINATOR: u8 = 18;
pub const SPL_TOKEN_INITIALIZE_MINT2_DISCRIMINATOR: u8 = 20;

/// Canonical SPL asset counter layout: next_asset_id (8).
pub const SPL_ASSET_COUNTER_ACCOUNT_LEN: usize = 8;

/// Canonical layout for a shielded-pool SPL asset registry record:
/// magic (8), mint pubkey (32), asset_id (8).
pub const SPL_ASSET_REGISTRY_MAGIC: [u8; 8] = *b"SPASSET1";
pub const SPL_ASSET_REGISTRY_MAGIC_OFFSET: usize = 0;
pub const SPL_ASSET_REGISTRY_MAGIC_END: usize = SPL_ASSET_REGISTRY_MAGIC_OFFSET + 8;
pub const SPL_ASSET_REGISTRY_MINT_OFFSET: usize = SPL_ASSET_REGISTRY_MAGIC_END;
pub const SPL_ASSET_REGISTRY_MINT_END: usize = SPL_ASSET_REGISTRY_MINT_OFFSET + 32;
pub const SPL_ASSET_REGISTRY_ASSET_ID_OFFSET: usize = SPL_ASSET_REGISTRY_MINT_END;
pub const SPL_ASSET_REGISTRY_ASSET_ID_END: usize =
    SPL_ASSET_REGISTRY_ASSET_ID_OFFSET + core::mem::size_of::<u64>();
pub const SPL_ASSET_REGISTRY_ACCOUNT_LEN: usize = SPL_ASSET_REGISTRY_ASSET_ID_END;
