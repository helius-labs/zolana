//! Test harnesses for the Squads ring integration tests.
//!
//! [`SquadsRingTest`] boots a LiteSVM instance with the prebuilt Squads ring
//! program. [`localnet::SquadsLocalnet`] boots a validator + Photon with SPP and
//! the ring for the BDD lifecycle suites, whose asserts live in [`asserts`].
//!
//! The program binary must be built first (see this crate's `Cargo.toml`):
//!
//! ```bash
//! cd rings/squads/program && cargo build-sbf --features bpf-entrypoint
//! ```

pub mod asserts;
mod harness;
pub mod localnet;

pub use harness::{
    custom_code, default_program_path, default_spp_program_path, prover_url,
    spp_external_data_hash, ProgramTestError, SquadsRingTest,
};
