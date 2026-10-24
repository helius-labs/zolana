pub const STATE_TREE_HEIGHT: usize = 32;
pub const NULLIFIER_TREE_HEIGHT: usize = 40;

/// The runtime's ceiling on the account data one transaction may load, and what
/// a transaction carrying no `set_loaded_accounts_data_size_limit` instruction
/// received by default
/// (`solana_program_runtime::execution_budget::MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES`).
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;
