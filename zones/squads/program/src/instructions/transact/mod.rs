//! `transact` instruction: zone-proof-gated synchronous transfer/withdrawal.

pub mod account;
pub mod processor;

pub use processor::process_transact_ix;
