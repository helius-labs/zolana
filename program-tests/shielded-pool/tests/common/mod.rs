//! Shared harness for shielded-pool program tests.
#![allow(dead_code)]

use shielded_pool_program::error::ShieldedPoolError;
use solana_keypair::Keypair;
use zolana_program_test::{RigError, ShieldedPoolTestRig};

/// 1.16 MB — big enough for the combined account; the program ignores any
/// caller-supplied size and uses `tree_account_size()` internally.
pub const TREE_ACCOUNT_SIZE: u64 = 1_200_000;

pub fn rig() -> Option<ShieldedPoolTestRig> {
    match ShieldedPoolTestRig::new() {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!(
                "skipping program test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

pub fn rig_with_tree() -> Option<(ShieldedPoolTestRig, Keypair, Keypair)> {
    let mut rig = rig()?;
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");
    let tree = rig
        .create_tree(TREE_ACCOUNT_SIZE, &authority)
        .expect("create_tree");
    Some((rig, authority, tree))
}

#[track_caller]
pub fn assert_custom(err: RigError, code: u32) {
    let msg = format!("{err}");
    let needle = format!("Custom({code})");
    assert!(msg.contains(&needle), "expected {needle}, got: {msg}");
}

#[track_caller]
pub fn assert_pool_error(err: RigError, error: ShieldedPoolError) {
    assert_custom(err, error as u32);
}

#[track_caller]
pub fn assert_instruction_error(err: RigError, name: &str) {
    let msg = format!("{err}");
    assert!(msg.contains(name), "expected {name}, got: {msg}");
}
