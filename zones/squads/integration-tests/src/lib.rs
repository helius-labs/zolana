//! Test harness for Squads zone integration tests.
//!
//! The program binary must be built first:
//!
//! ```bash
//! cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
//! ```

mod harness;

pub use harness::{
    custom_code, default_program_path, default_spp_program_path, prover_url, ProgramTestError,
    SquadsZoneTest,
};
