//! A crate of zk circuits on the zk DSL and gadgets alone, without
//! spr-program, laid out like a Solana program that verifies them: the
//! circuits build on the host with the `circuits` feature, and the SBF program
//! links only the DSL's on-chain verifier and the generated verifier modules.
//!
//! The derives generate paths under `::spr_program`, so the crate root
//! names the DSL that way.

extern crate spr_zk_dsl as spr_program;

#[cfg(feature = "circuits")]
mod circuits;
#[cfg(not(feature = "r1cs-export"))]
pub mod instruction;
/// The verifier modules `zolana zk compile` generates from the circuits.
#[cfg(not(feature = "r1cs-export"))]
pub mod verifier;

#[cfg(feature = "circuits")]
pub use circuits::*;

#[cfg(all(feature = "bpf-entrypoint", not(feature = "r1cs-export")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::instruction::process_instruction);
}
