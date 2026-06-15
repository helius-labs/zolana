//! Shared setup for shielded-pool program tests.
use shielded_pool_program::error::ShieldedPoolError;
use zolana_interface::state;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub fn tree_account_size() -> u64 {
    state::tree_account_size() as u64
}

pub fn program_test() -> Option<ZolanaProgramTest> {
    match ZolanaProgramTest::new() {
        Ok(r) => Some(r),
        Err(ProgramTestError::MissingProgram(_)) => {
            eprintln!(
                "skipping program test: shielded_pool_program.so missing - \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("program test boot failed: {e}"),
    }
}

#[track_caller]
pub fn assert_custom(err: ProgramTestError, code: u32) {
    let msg = format!("{err}");
    let needle = format!("Custom({code})");
    assert!(msg.contains(&needle), "expected {needle}, got: {msg}");
}

#[track_caller]
pub fn assert_pool_error(err: ProgramTestError, error: ShieldedPoolError) {
    assert_custom(err, error as u32);
}

#[track_caller]
pub fn assert_instruction_error(err: ProgramTestError, name: &str) {
    let msg = format!("{err}");
    assert!(msg.contains(name), "expected {name}, got: {msg}");
}
