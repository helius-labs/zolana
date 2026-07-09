//! Shared setup for shielded-pool program tests.
mod setup;

use rings_interface::error::ShieldedPoolError;
use rings_program_test::ProgramTestError;
pub use setup::{program_test, tree_account_size};

// This helper module is `#[path]`-included into several test binaries; not every
// binary uses every helper, so suppress dead-code noise rather than per binary.
#[allow(dead_code)]
#[track_caller]
pub fn assert_custom(err: ProgramTestError, code: u32) {
    let msg = format!("{err}");
    let needle = format!("Custom({code})");
    assert!(msg.contains(&needle), "expected {needle}, got: {msg}");
}

#[allow(dead_code)]
#[track_caller]
pub fn assert_pool_error(err: ProgramTestError, error: ShieldedPoolError) {
    assert_custom(err, error as u32);
}
