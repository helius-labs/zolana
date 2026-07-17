pub mod error;
pub use zolana_event as event;
pub mod instruction;
pub mod merge_utils;
pub mod pda;
pub mod shape;
pub mod state;
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
    pubkey_array!("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");

/// [`SHIELDED_POOL_PROGRAM_ID`] as a `Pubkey`, used by instruction builders.
pub const PROGRAM_ID_PUBKEY: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);

/// Devnet/localnet fixture SPP pool tree address. Single source of truth so the
/// CLI config default, forester CLI default, xtask protocol init, and the CLI
/// resolve test all reference one value and cannot drift.
pub const DEFAULT_TREE_ADDRESS: &str = "treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8";

/// [`DEFAULT_POOL_TREE_ADDRESS`] as a `Pubkey`.
pub const DEFAULT_TREE_ADDRESS: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::from_str_const(DEFAULT_POOL_TREE_ADDRESS);

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
    88, 254, 248, 74, 86, 156, 76, 98, 4, 160, 29, 78, 152, 238, 8, 247, 252, 20, 54, 18, 242, 184,
    160, 99, 112, 248, 135, 246, 47, 245, 181, 43,
];

/// Bump for `SHIELDED_POOL_CPI_AUTHORITY`.
pub const SHIELDED_POOL_CPI_AUTHORITY_BUMP: u8 = 254;

/// Canonical native-SOL custody PDA:
/// `find_program_address(&[b"sol_interface", &[0]], SHIELDED_POOL_PROGRAM_ID)`.
/// Hardcoded so builders and the SBF program avoid the runtime derivation; the
/// `pda::sol_interface_const_matches_derivation` test pins it.
pub const SOL_INTERFACE: [u8; 32] = [
    153, 202, 212, 28, 214, 25, 170, 103, 127, 203, 31, 129, 56, 221, 77, 131, 217, 62, 194, 23,
    222, 98, 111, 179, 160, 182, 255, 213, 208, 236, 115, 61,
];

/// [`SOL_INTERFACE`] as a `Pubkey`.
pub const SOL_INTERFACE_PUBKEY: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::new_from_array(SOL_INTERFACE);

/// SPL Token v3 program id: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// SPL Associated Token Account program id:
/// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
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
