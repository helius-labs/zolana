//! Smoke test: confirms the rig surfaces a useful error when the shielded-
//! pool .so isn't present. Actual integration tests that drive the program
//! end-to-end need `cargo build-sbf -p shielded-pool-program` to have produced
//! `target/deploy/shielded_pool_program.so` and live in task #36.

use std::path::PathBuf;

use light_program_test::{PoolTestRig, RigError};

#[test]
fn missing_program_binary_surfaces_clear_error() {
    let bogus = PathBuf::from("/tmp/this/path/intentionally/does/not/exist.so");
    let result = PoolTestRig::with_program_path(&bogus);
    assert!(matches!(result, Err(RigError::MissingProgram(_))));
}
