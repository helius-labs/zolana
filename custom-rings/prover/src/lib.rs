//! In-process proving engine for the custom-ring auditor key-encryption circuit.
//!
//! `build.rs` compiles `circuits/` into a cgo c-archive and generates the
//! bindings; [`ffi`] exposes them as `setup` / `preload` / `prove`. When the Go
//! sources or toolchain are unavailable the crate still compiles and every
//! engine call fails with `ffi::Error::EngineUnavailable`.
//!
//! Proof input structs here are pure containers: they encode a witness map and
//! prove. Hashing, key derivation and encryption belong in the sdk.

pub mod auditor_key_encryption;
pub mod ffi;
pub mod proof;

use num_bigint::BigUint;

pub use auditor_key_encryption::AuditorKeyEncryptionProofInputs;
pub use ffi::{preload, prove, setup, CircuitId, WitnessMap};
pub use proof::{AuditProof, ProofError};

/// Whether `build.rs` compiled and linked the Go circuits into this build.
pub const GO_CIRCUITS_LINKED: bool = cfg!(custom_ring_go_circuits);

/// Big-endian bytes as the decimal string the gnark witness assigner parses.
pub fn bytes_to_decimal_string(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
