pub mod instruction;
pub mod state;

/// Placeholder program id for the initial shielded-pool program scaffold.
pub const SHIELDED_POOL_PROGRAM_ID: [u8; 32] = [
    6, 111, 11, 97, 110, 97, 95, 115, 104, 105, 101, 108, 100, 101, 100, 95, 112, 111, 111, 108,
    95, 118, 48, 95, 95, 95, 95, 95, 95, 95, 95, 1,
];

/// `light-registry`'s declared program id — `Lighton6oQpVkeewmo2mcPTQQp7kYHr4fWpAgJyEmDX`.
/// Used by shielded-pool to derive the expected CPI authority PDA when
/// validating callers of forester-only instructions.
pub const LIGHT_REGISTRY_PROGRAM_ID: [u8; 32] = [
    5, 13, 43, 19, 121, 81, 54, 133, 207, 2, 242, 181, 253, 82, 145, 189, 149, 155, 43, 6, 10, 165,
    37, 234, 91, 52, 129, 59, 29, 185, 183, 110,
];

/// Seed for the registry's CPI authority PDA (matches
/// `light_registry::constants::CPI_AUTHORITY_PDA_SEED`). Kept for the
/// pinning test that asserts `LIGHT_REGISTRY_CPI_AUTHORITY` matches
/// `Pubkey::find_program_address(&[CPI_AUTHORITY_PDA_SEED], &LIGHT_REGISTRY_PROGRAM_ID)`.
pub const CPI_AUTHORITY_PDA_SEED: &[u8] = b"cpi_authority";

/// Seed for the shielded-pool program's own CPI authority PDA, used as the
/// SOL vault and SPL vault authority for public settlement.
pub const SHIELDED_POOL_CPI_AUTHORITY_PDA_SEED: &[u8] = b"cpi_authority";
pub const SPP_POCKET_CONFIG_PDA_SEED: &[u8] = b"spp_pocket_config";
pub const POCKET_AUTH_PDA_SEED: &[u8] = b"pocket_auth";
pub const SPL_ASSET_COUNTER_PDA_SEED: &[u8] = b"spl_asset_counter";
pub const SPL_ASSET_REGISTRY_PDA_SEED: &[u8] = b"spl_asset_registry";
pub const SPL_ASSET_VAULT_PDA_SEED: &[u8] = b"spl_asset_vault";

/// Canonical shielded-pool CPI authority PDA:
/// `find_program_address(&[b"cpi_authority"], SHIELDED_POOL_PROGRAM_ID)`.
/// Kept as a constant so the SBF program validates settlement accounts with a
/// direct equality check.
pub const SHIELDED_POOL_CPI_AUTHORITY: [u8; 32] = [
    85, 90, 130, 119, 99, 189, 124, 34, 25, 77, 186, 49, 37, 53, 39, 49, 7, 137, 62, 163, 187, 111,
    36, 84, 136, 126, 165, 236, 8, 174, 36, 5,
];

/// Bump for `SHIELDED_POOL_CPI_AUTHORITY`.
pub const SHIELDED_POOL_CPI_AUTHORITY_BUMP: u8 = 255;

/// SPL Token v3 program id: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// Canonical layout for a shielded-pool SPL asset registry record:
/// magic (8), mint pubkey (32), reserved (8). SPL asset identity is the
/// Poseidon hash of the mint pubkey, not the reserved bytes.
pub const SPL_ASSET_REGISTRY_MAGIC: [u8; 8] = *b"SPASSET1";
pub const SPL_ASSET_REGISTRY_ACCOUNT_LEN: usize = 48;

/// Canonical registry CPI authority PDA — `find_program_address(&[b"cpi_authority"], LIGHT_REGISTRY_PROGRAM_ID)`.
/// Hardcoded so shielded-pool can do a single equality check on the signer
/// without re-deriving on every call. A pin test against
/// `Pubkey::find_program_address` lives in shielded-pool's
/// `instruction_validation` so a rename of the seed or program id is loud.
pub const LIGHT_REGISTRY_CPI_AUTHORITY: [u8; 32] = [
    16, 166, 94, 125, 214, 57, 4, 248, 56, 58, 208, 60, 222, 224, 120, 185, 20, 216, 115, 24, 128,
    59, 21, 53, 128, 112, 215, 146, 224, 92, 253, 231,
];
