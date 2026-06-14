//! Shared setup for shielded-pool program tests.
#![allow(dead_code)]

use shielded_pool_program::error::ShieldedPoolError;
use solana_keypair::Keypair;
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
                "skipping program test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("program test boot failed: {e}"),
    }
}

pub fn program_test_with_tree() -> Option<(ZolanaProgramTest, Keypair, Keypair)> {
    let mut program_test = program_test()?;
    let authority = Keypair::new();
    program_test
        .create_protocol_config(&authority)
        .expect("create_protocol_config");
    let tree = program_test
        .create_tree(tree_account_size(), &authority)
        .expect("create_tree");
    Some((program_test, authority, tree))
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
