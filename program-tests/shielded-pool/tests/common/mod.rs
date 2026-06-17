//! Shared setup for shielded-pool program tests.
mod setup;

pub use setup::{program_test, tree_account_size};
use shielded_pool_program::error::ShieldedPoolError;
use zolana_program_test::ProgramTestError;

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
