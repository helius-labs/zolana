//! A standalone Xark circuit with a Solana verifier for its public payout.

#[cfg(all(feature = "circuits", not(target_os = "solana")))]
mod circuits;
#[cfg(all(feature = "circuits", not(target_os = "solana")))]
pub use circuits::*;
#[cfg(not(feature = "r1cs-export"))]
pub mod instruction;
#[cfg(not(feature = "r1cs-export"))]
pub mod verifier;
#[cfg(all(feature = "bpf-entrypoint", not(feature = "r1cs-export")))]
mod entrypoint { pinocchio::entrypoint!(crate::instruction::process_instruction); }
