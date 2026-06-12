pub mod instruction;
pub mod state;
pub mod user_registry;
pub mod verifying_keys;

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

/// Canonical registry CPI authority PDA — `find_program_address(&[b"cpi_authority"], LIGHT_REGISTRY_PROGRAM_ID)`.
/// Hardcoded so shielded-pool can do a single equality check on the signer
/// without re-deriving on every call. A pin test against
/// `Pubkey::find_program_address` lives in shielded-pool's
/// `instruction_validation` so a rename of the seed or program id is loud.
pub const LIGHT_REGISTRY_CPI_AUTHORITY: [u8; 32] = [
    16, 166, 94, 125, 214, 57, 4, 248, 56, 58, 208, 60, 222, 224, 120, 185, 20, 216, 115, 24, 128,
    59, 21, 53, 128, 112, 215, 146, 224, 92, 253, 231,
];
