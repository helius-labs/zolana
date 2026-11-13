use std::path::Path;

use spr_program_test::{ProgramTestError, SprProgramTest};

#[test]
fn missing_program_names_how_to_get_the_binary() {
    let path = Path::new("/nonexistent/shielded_pool_program.so");
    let Err(error) = SprProgramTest::with_program_path(path) else {
        panic!("booted without a program binary");
    };

    assert!(matches!(&error, ProgramTestError::MissingProgram(missing) if missing == path));
    let message = error.to_string();
    assert!(message.contains("SHIELDED_POOL_PROGRAM_PATH"), "{message}");
    assert!(message.contains("solana program dump"), "{message}");
}

#[test]
fn with_program_bytes_rejects_a_non_program() {
    let Err(error) = SprProgramTest::with_program_bytes(b"not an sbf program") else {
        panic!("loaded bytes that are not a program");
    };

    assert!(matches!(error, ProgramTestError::Litesvm(_)), "{error}");
}
