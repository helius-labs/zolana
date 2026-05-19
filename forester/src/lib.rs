//! Forester skeleton. All foresting code for v1/v2/ctoken trees was removed
//! in the shielded-pool reshape. Awaiting the new combined address+state
//! tree type before any foresting logic is reintroduced.

pub type Result<T> = anyhow::Result<T>;

pub mod cli;
pub mod config;
pub mod errors;
pub mod logging;
pub mod utils;
