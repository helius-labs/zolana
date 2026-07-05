//! Test harness for Squads zone integration tests.
//!
//! Boots a LiteSVM instance, loads the prebuilt Squads zone program SBF binary
//! at [`SQUADS_ZONE_PROGRAM_ID`], funds a payer, and exposes the small set of
//! helpers the tests need: sending instructions, reading account data, and
//! seeding raw account fixtures.
//!
//! The program binary must be built first (see this crate's `Cargo.toml`):
//!
//! ```bash
//! cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//! ```

mod harness;

pub use harness::{
    custom_code, default_program_path, default_spp_program_path, prover_url, ProgramTestError,
    SquadsZoneTest,
};
