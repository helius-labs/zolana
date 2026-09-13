//! The compute ceiling a custom-ring transaction declares, independent of
//! transport.
//!
//! A transaction **v1** message carries this in its header instead of in a
//! compute-budget instruction; `zolana_client::ComputeBudgetConfig` turns it
//! into that header.

/// A transact verifies its own Groth16 proof and CPIs into SPP, which verifies
/// another; nothing short of the whole budget covers it.
pub const TRANSACT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
