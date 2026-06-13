use std::path::PathBuf;

use zolana_program_test::{PoolTestRig, RigError};

#[test]
fn missing_program_binary_surfaces_clear_error() {
    let bogus = PathBuf::from("/tmp/this/path/intentionally/does/not/exist.so");
    let result = PoolTestRig::with_program_path(&bogus);
    assert!(matches!(result, Err(RigError::MissingProgram(_))));
}
