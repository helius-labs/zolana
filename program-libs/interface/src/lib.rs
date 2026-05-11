pub mod instruction;
pub mod state;
pub mod verifying_keys;

/// Placeholder program id for the initial shielded-pool program scaffold.
pub const SHIELDED_POOL_PROGRAM_ID: [u8; 32] = [
    6, 111, 11, 97, 110, 97, 95, 115, 104, 105, 101, 108, 100, 101, 100, 95, 112, 111, 111, 108,
    95, 118, 48, 95, 95, 95, 95, 95, 95, 95, 95, 1,
];
