//! # gnark-prover
//!
//! The host-side gnark prover every sdk-tests example with its own circuits
//! shares. Each example keeps only what is specific to it:
//!
//! - `prover/circuits/`: a Go `main` package whose `init` registers the
//!   example's circuits with the `zolana/gnarkprover` bridge in `go/`, plus the
//!   circuits themselves.
//! - `prover/build.rs`: `zolana_gnark_prover_build::build_prover_archive()`, which
//!   builds that package into a C archive and links it.
//! - A [`Circuit`] enum and `pub static PROVER: Prover<CircuitId> = prover!();`.
//! - The witness encoding and proof types of each circuit.
//! - `src/bin/setup.rs`: `setup_cli::main(&PROVER)`.
//!
//! Keys live in `<example>/build/gnark/<circuit>/{pk,vk}.bin`. A circuit's
//! proving key is loaded on its first proof and stays loaded.

mod ffi;
mod proof;
mod prover;
pub mod setup_cli;
mod utxo;

use std::{collections::HashMap, path::PathBuf};

use num_bigint::BigUint;

pub use ffi::{ProveResult, Symbols};
pub use proof::{Commitment, CompressedProof, ProveOutput};
pub use prover::{Circuit, Prover};
pub use utxo::{expected_utxo_witness_keys, utxo_witness_entries};

/// Witness values by key: a circuit field path, `_`-joined through nested
/// structs, mapped to its decimal field values.
pub type WitnessMap = HashMap<String, Vec<String>>;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("gnark FFI error: {0}")]
    Go(String),
    #[error("proving key missing at {0} -- fetch the example's keys or run its setup")]
    MissingKeys(PathBuf),
    #[error("circuit {0:?} is not in its Circuit::ALL")]
    UnlistedCircuit(&'static str),
    #[error("path is not valid UTF-8")]
    PathEncoding,
    #[error("interior NUL in C string")]
    NulInString(#[from] std::ffi::NulError),
    #[error("witness JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("compress G1 failed: {0}")]
    CompressG1(String),
    #[error("compress G2 failed: {0}")]
    CompressG2(String),
    #[error("proof is missing its BSB22 commitment")]
    MissingCommitment,
}

/// A 32-byte big-endian field element as the decimal string the Go witness
/// assignment parses.
pub fn decimal(bytes: &[u8; 32]) -> String {
    BigUint::from_bytes_be(bytes).to_string()
}
