//! Test harness for Squads ring integration tests.
//!
//! The program binary must be built first:
//!
//! ```bash
//! cd rings/squads/program && cargo build-sbf --features bpf-entrypoint
//! ```

mod harness;

pub use harness::{
    custom_code, default_program_path, default_spp_program_path, prover_url, ProgramTestError,
    SquadsRingTest,
};
