pub mod instruction;
pub mod state;
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
/// `light_registry::constants::CPI_AUTHORITY_PDA_SEED`).
pub const CPI_AUTHORITY_PDA_SEED: &[u8] = b"cpi_authority";
