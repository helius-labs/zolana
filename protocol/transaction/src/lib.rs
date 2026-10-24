//! Solana v1 transaction construction for protocol operators.
mod compute_budget;
mod transaction;
mod transaction_size;
pub use compute_budget::ComputeBudgetConfig;
pub use transaction::{compile_message, sign_transaction};
pub use transaction_size::{transaction_size, TransactionSize, SIGNATURE_LEN};
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("compile transaction: {0}")]
    Compile(String),
    #[error("sign transaction: {0}")]
    Signing(String),
    #[error("only transaction version 1 is supported")]
    UnsupportedVersion,
}
